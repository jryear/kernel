"""Trusted interpretation of received sandbox diagnostics (not candidate input).

The srt store's timestamp is reception time, not occurrence time.  A canary
match therefore requires separately correlated raw collector occurrence evidence.
"""
from __future__ import annotations
import hashlib
import json
import math
import os
import re
from datetime import datetime

SEMANTICS = 'advisory-one-directional-v1'
_BENIGN = {('sysctl-read', 'kern.iossupportversion'), ('system-info', 'vfs.disk-space'),
           ('mach-lookup', 'com.apple.diagnosticd'), ('mach-lookup', 'com.apple.analyticsd')}
_LINE = re.compile(r'^(?P<process>.+?)\((?P<pid>\d+)\) deny\((?P<result>\d+)\) (?P<operation>\S+) (?P<resource>.+)$')
_RAW = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) .*?Sandbox: (.*)$')


def match_canary_event(event, binding):
    """Match every binding independently; absent fields are never positive evidence."""
    required = ('run_id', 'check', 'phase', 'repetition', 'probe_id', 'command_tag',
                'path', 'operation', 'denial_result', 'subject_pid', 'subject_start',
                'executable', 'executable_sha256')
    reasons = []
    for field in required:
        if field not in binding or binding[field] is None:
            reasons.append('binding_missing_' + field)
        elif field not in event or event[field] is None:
            reasons.append('event_missing_' + field)
        elif event[field] != binding[field]:
            reasons.append('mismatch_' + field)
    if not isinstance(binding.get('path'), str) or not os.path.isabs(binding['path']) or os.path.realpath(binding['path']) != binding['path']:
        reasons.append('noncanonical_target')
    occurrence = event.get('occurrence_epoch')
    start, end = binding.get('preflight_start'), binding.get('preflight_end')
    syscall_start, syscall_end = binding.get('syscall_start'), binding.get('syscall_end')
    tolerance = binding.get('clock_uncertainty_seconds')
    if not all(type(x) in (int, float) and math.isfinite(x) for x in (occurrence, start, end, syscall_start, syscall_end, tolerance)):
        reasons.append('occurrence_or_window_unavailable')
    elif tolerance < 0 or tolerance > .001 or not (start <= syscall_start <= syscall_end <= end):
        reasons.append('invalid_clock_window')
    elif not (start - tolerance <= occurrence <= end + tolerance and
              syscall_start - tolerance <= occurrence <= syscall_end + tolerance):
        reasons.append('outside_preflight_or_syscall_window')
    return {'matched': not reasons, 'reasons': reasons}


def raw_occurrences(raw):
    """Correlate compact stream lines to store entries without fabricating time.

    Compact dates are local wall-clock values at millisecond resolution. Ambiguous
    DST folds are refused; an unresolved event cannot become a canary exemption.
    """
    rows = {}
    for line in raw.decode('utf-8', errors='replace').splitlines():
        m = _RAW.match(line)
        if not m:
            continue
        try:
            dt = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S.%f')
            first, second = dt.replace(fold=0).timestamp(), dt.replace(fold=1).timestamp()
            stamp = first if first == second else None
        except (ValueError, OSError, OverflowError):
            stamp = None
        rows.setdefault(m.group(2), []).append(stamp)
    return rows


def parse_raw_events(raw, subscription_events, session_suffix, chunks):
    """Parse every observed raw denial, including those filtered by srt.

    The trusted log process supplies compact framing. A denial lacking its
    immediately following tag is retained with ambiguous attribution.
    Subscription callbacks provide receive time where present, but never the
    occurrence timestamp (which is only read from the raw collector line).
    """
    byte_lines = raw.splitlines(keepends=True)
    lines = [line.decode('utf-8', errors='replace').rstrip('\r\n') for line in byte_lines]
    offsets = []
    offset = 0
    for line in byte_lines:
        offset += len(line)
        offsets.append(offset)
    available = {}
    for event in subscription_events:
        available.setdefault((event.get('line'), event.get('encodedCommand')), []).append(event)
    output, faults = [], []
    tag_re = re.compile(r'^CMD64_([A-Za-z0-9+/]+={0,2})_END_' + re.escape(session_suffix or '') + r'$')
    for index, line in enumerate(lines):
        match = _RAW.match(line)
        if not match or 'deny(' not in match.group(2):
            continue
        detail = match.group(2)
        tag = tag_re.match(lines[index + 1]) if index + 1 < len(lines) else None
        encoded = tag.group(1) if tag else None
        subscription = available.get((detail, encoded), [])
        source = subscription.pop(0) if subscription else {}
        event = dict(source)
        arrival = next((chunk for chunk in chunks if chunk.get('start', -1) < offsets[index] <= chunk.get('end', -1)), None)
        if arrival is None:
            faults.append('diagnostic_evidence_invalid')
        else:
            event.update(received_epoch=arrival.get('received_epoch'), arrival_phase=arrival.get('arrival_phase'))
        event.update(line=detail, encodedCommand=encoded,
                     raw_line_sha256=hashlib.sha256(line.encode()).hexdigest(),
                     raw_line_number=index + 1)
        if not tag:
            faults.append('diagnostic_attribution_ambiguous')
        output.append(event)
    # A callback with no corresponding retained raw line cannot be validated.
    if any(events for events in available.values()):
        faults.append('diagnostic_evidence_invalid')
    return output, list(dict.fromkeys(faults))


def process_events(events, binding, raw=b'', lifecycle=None, origins=None):
    """Interpret persisted events; this function is never fed candidate output."""
    lifecycle = lifecycle or {}
    origins = origins or {}
    corrections = []
    occurrences = raw_occurrences(raw)
    result, matches, rejected, faults = [], [], [], []
    for event in events:
        raw_event = json.dumps(event, sort_keys=True, separators=(',', ':')).encode()
        line = str(event.get('line', ''))
        match = _LINE.match(line)
        event_digest = hashlib.sha256(raw_event).hexdigest()
        row = {'event_sha256': event_digest, 'raw_reference': event.get('raw_line_sha256', event_digest), 'raw_line_number': event.get('raw_line_number'),
               'received_at': event.get('timestamp'), 'received_epoch': event.get('received_epoch'), 'arrival_phase': event.get('arrival_phase'), 'line': line,
               'command_tag': event.get('encodedCommand'), 'origin': None,
               'subject_pid': None, 'subject_start': None, 'operation': None,
               'resource': None, 'occurrence_epoch': None, 'lifecycle_phase': 'unknown',
               'attribution': 'ambiguous', 'relevance': 'ambiguous', 'exemption_id': None}
        if not match:
            faults.append('diagnostic_attribution_ambiguous')
            result.append(row)
            continue
        row.update(subject_pid=int(match.group('pid')), operation=match.group('operation'),
                   resource=match.group('resource'), denial_result=int(match.group('result')))
        raw_times = occurrences.get(line, [])
        if raw_times:
            row['occurrence_epoch'] = raw_times.pop(0)
        for name in ('run_id', 'check', 'phase', 'repetition'):
            row[name] = binding.get(name)
        # The invocation tag is assigned by the trusted supervisor, never by
        # provisional child output. Wrong/absent tags are not reassigned.
        if event.get('encodedCommand') != binding.get('command_tag') or not binding.get('command_tag'):
            prior = origins.get(event.get('encodedCommand'))
            if prior:
                row['origin'] = prior['identity']
                row['attribution'] = 'prior_invocation'
                faults.append('diagnostic_cross_invocation')
                if (row['operation'], row['resource']) in _BENIGN:
                    row.update(relevance='benign', exemption_id='reviewed-system-' + row['operation'])
                else:
                    old_binding = prior['binding']
                    # Only the exact probe PID inside the retained preflight
                    # interval may inherit its trusted process-start identity.
                    occurred = row['occurrence_epoch']
                    if (row['subject_pid'] == old_binding.get('subject_pid') and occurred is not None and
                            old_binding.get('preflight_start', float('inf')) - .001 <= occurred <= old_binding.get('preflight_end', float('-inf')) + .001):
                        row.update(subject_start=old_binding.get('subject_start'), executable=old_binding.get('executable'),
                                   executable_sha256=old_binding.get('executable_sha256'), probe_id=old_binding.get('probe_id'),
                                   path=row['resource'])
                    for key in ('run_id', 'check', 'phase', 'repetition'):
                        row[key] = old_binding.get(key)
                    if match_canary_event(row, old_binding)['matched']:
                        row.update(relevance='expected_probe', exemption_id='bound-preflight-probe')
                    elif occurred is None:
                        row['relevance'] = 'ambiguous'
                        corrections.append({'code': 'diagnostic_attribution_ambiguous', 'original_receipt_sha256': prior['receipt_sha256'],
                                            'origin': prior['identity'], 'event_sha256': event_digest})
                    else:
                        row['relevance'] = 'relevant_denial'
                        corrections.append({'code': 'observed_relevant_denial', 'original_receipt_sha256': prior['receipt_sha256'],
                                            'origin': prior['identity'], 'event_sha256': event_digest})
            else:
                faults.append('diagnostic_attribution_ambiguous')
            result.append(row)
            continue
        row['origin'] = {key: binding.get(key) for key in ('run_id', 'check', 'phase', 'repetition')}
        row['attribution'] = 'original_invocation'
        if (row['subject_pid'] == binding.get('subject_pid') and
                row['occurrence_epoch'] is not None and
                binding.get('preflight_start', float('inf')) - .001 <= row['occurrence_epoch'] <= binding.get('preflight_end', float('-inf')) + .001):
            row.update(subject_start=binding.get('subject_start'), executable=binding.get('executable'),
                       executable_sha256=binding.get('executable_sha256'), probe_id=binding.get('probe_id'),
                       path=row['resource'])
        for observed in lifecycle.get('observed', []):
            if observed.get('pid') == row['subject_pid'] and not row.get('subject_start'):
                row['subject_start'] = observed.get('started')
        if row['occurrence_epoch'] is not None:
            if row['occurrence_epoch'] <= binding.get('preflight_end', -1): row['lifecycle_phase'] = 'preflight'
            elif row['occurrence_epoch'] <= lifecycle.get('exited_at', float('inf')): row['lifecycle_phase'] = 'check'
            else: row['lifecycle_phase'] = 'drain'
        if (row['operation'], row['resource']) in _BENIGN:
            row.update(relevance='benign', exemption_id='reviewed-system-' + row['operation'])
        else:
            canary = match_canary_event(row, binding)
            if canary['matched']:
                row.update(relevance='expected_probe', exemption_id='bound-preflight-probe')
                matches.append(event_digest)
            else:
                if 'canary' in row['resource'] or row['subject_pid'] == binding.get('subject_pid'):
                    rejected.append({'event_sha256': event_digest, 'reasons': canary['reasons']})
                # The matching supervisor tag establishes this invocation, not
                # which PID was running after the probe ended. Probe-PID reuse
                # or missing occurrence makes origin uncertain and fails closed.
                if row['occurrence_epoch'] is None or not row.get('subject_start'):
                    row['relevance'] = 'ambiguous'
                    faults.append('diagnostic_attribution_ambiguous')
                else:
                    row['relevance'] = 'relevant_denial'
                    faults.append('observed_relevant_denial')
        result.append(row)
    return {'events': result, 'matched': matches, 'rejected': rejected, 'faults': list(dict.fromkeys(faults)), 'corrections': corrections}
