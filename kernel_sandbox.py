"""Trusted sandbox policy validation and evidence classification.

This module classifies observed facts, not intention. Incomplete evidence always
precedes a measured contradiction. A clean observation does not establish that
no attempt, transient write, hidden process, or missing OS log event occurred.
"""
from __future__ import annotations

import json
import platform
import shutil
import subprocess
from pathlib import Path, PurePosixPath


def classify_sandbox_evidence(evidence):
    """Classify the same typed evidence in the verifier and external probes."""
    if not isinstance(evidence, dict) or evidence.get('schema') != 1:
        return {'verdict': 'unverifiable', 'facts': [], 'unavailable_reasons': ['invalid evidence schema'],
                'contradictions': [], 'collector_ready': False, 'logs_complete': False}
    integrity = evidence.get('integrity') or {}
    execution = evidence.get('execution') or {}
    cleanup = evidence.get('cleanup') or {}
    assertions = evidence.get('assertions') or {}
    diagnostics = evidence.get('diagnostics') or {}
    facts, unavailable, contradictions = [], [], []
    if integrity.get('available') is not True:
        unavailable.append('integrity inventory unavailable')
    else:
        changes = integrity.get('changes')
        if not isinstance(changes, list):
            unavailable.append('integrity changes unavailable')
        else:
            facts.extend(changes)
            if any(change.get('kind') == 'protected_change' for change in changes if isinstance(change, dict)):
                contradictions.append('measured protected change')
    if integrity.get('additional_inventory_available') is False:
        unavailable.append('additional integrity measurement unavailable')
    judge = evidence.get('judge_integrity')
    if judge:
        if judge.get('available') is not True or judge.get('unchanged') is not True:
            unavailable.append('judge integrity unavailable or changed')
        if judge.get('available') is True:
            facts.extend(judge.get('changes', []))
    if execution.get('complete') is not True or execution.get('timed_out') or execution.get('unavailable_reason'):
        unavailable.append('execution incomplete or unavailable')
    if cleanup.get('complete') is not True or cleanup.get('survivors') or cleanup.get('timed_out') or cleanup.get('errors'):
        unavailable.append('cleanup incomplete')
    if assertions.get('complete') is not True:
        unavailable.append('assertion evidence incomplete')
    elif assertions.get('failed'):
        contradictions.append('complete behavioral assertion failed')
    mode = diagnostics.get('mode')
    if mode == 'enabled':
        if (diagnostics.get('state') != 'active' or diagnostics.get('dropped', 0) or
                diagnostics.get('collector_fault') or diagnostics.get('drain_timed_out') or
                diagnostics.get('attribution') not in (None, 'original_invocation') or
                diagnostics.get('late_event') == 'relevant_denial' or diagnostics.get('spool_overflow')):
            unavailable.append('enabled diagnostics incomplete or ambiguous')
        canary = diagnostics.get('canary')
        if canary and canary.get('event_received') is False:
            unavailable.append('enabled diagnostic canary absent')
    elif mode == 'disabled':
        if diagnostics.get('state') != 'disabled':
            unavailable.append('diagnostic mode changed')
    else:
        unavailable.append('diagnostic mode unavailable')
    return {'verdict': 'unverifiable' if unavailable else 'contradicted' if contradictions else 'supported',
            'facts': facts, 'unavailable_reasons': unavailable, 'contradictions': contradictions,
            'collector_ready': False, 'logs_complete': False}


def validate_declaration(raw):
    """Validate syntax independently of the machine and snapshot grant checks."""
    if not isinstance(raw, dict) or set(raw) - {'writable_paths', 'localhost_ports'}:
        raise ValueError('unsupported sandbox policy fields')
    paths, ports = raw.get('writable_paths', []), raw.get('localhost_ports', [])
    if not isinstance(paths, list) or not isinstance(ports, list):
        raise ValueError('sandbox writable_paths and localhost_ports must be arrays')
    clean = []
    for path in paths:
        if (not isinstance(path, str) or not path or path != path.strip() or
                PurePosixPath(path).is_absolute() or '\\' in path or
                any(part in ('', '.', '..') for part in path.split('/')) or
                any(char in path for char in '*?[')):
            raise ValueError('sandbox writable path must be a literal relative directory')
        if path in clean:
            raise ValueError('duplicate sandbox writable path')
        clean.append(path)
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports) or len(ports) != len(set(ports)):
        raise ValueError('sandbox localhost ports must be unique integers 1..65535')
    return {'writable_paths': clean, 'localhost_ports': sorted(ports)}


def resolve_writable_paths(root, declaration, tracked, links):
    root = Path(root).resolve(strict=True)
    result = []
    for relative in declaration['writable_paths']:
        path = root / relative
        parts = PurePosixPath(relative).parts
        for i in range(1, len(parts) + 1):
            ancestor = root.joinpath(*parts[:i])
            if ancestor.is_symlink():
                raise ValueError('sandbox writable grant traverses a symlink')
        resolved = path.resolve(strict=False)
        if root not in resolved.parents:
            raise ValueError('sandbox writable grant escapes snapshot')
        for other in list(tracked) + list(links):
            target = root / other
            if target == path or target in path.parents or path in target.parents:
                raise ValueError('sandbox writable grant overlaps tracked source or dependency')
        if path.exists() and not path.is_dir():
            raise ValueError('sandbox writable grant is not a directory')
        # A real output must be ignored; otherwise snapshot integrity cannot tell
        # an output from an unexpected new input. git check-ignore is read-only.
        ignored = subprocess.run(['git', 'check-ignore', '-q', '--no-index', relative + '/'], cwd=root)
        if ignored.returncode != 0:
            raise ValueError('sandbox writable output root is not ignored')
        result.append(str(resolved))
    return result


def backend_supports_policy(policy):
    """Platform capability gate; authenticated patch/profile proof is also required."""
    validate_declaration(policy)
    return platform.system() == 'Darwin' and shutil.which('sandbox-exec') is not None


def validate_generated_profile(profile, context):
    """Shared read-only seam used by production and the frozen fault adapter."""
    from kernel_profile import validate_generated_profile as inspect
    return inspect(profile, context)


def refuse_unqualified_backend(args, repo, spec, base):
    """An explicit sandbox request never silently executes without a backend.

    This is the architecture-stop path, not an enforcement implementation.
    Authentication has already run in verify.main; no candidate check is launched.
    The shared classifier makes this incomplete execution unverifiable.
    """
    evidence = {
        'schema': 1,
        'integrity': {'available': False, 'changes': []},
        'execution': {'complete': False, 'unavailable_reason':
                      'sandbox execution requires the authenticated patched schema-2 backend'},
        'cleanup': {'complete': True, 'survivors': []},
        'assertions': {'complete': False, 'failed': []},
        'diagnostics': {'mode': 'disabled', 'state': 'disabled'},
    }
    decision = classify_sandbox_evidence(evidence)
    record = {'schema': 2, 'task_id': spec['id'], 'base_ref': args.base,
              'merge_base': base, 'verdict': decision['verdict'],
              'assurance': 'sandbox-backend-unqualified',
              'base_checks': [], 'candidate_checks': [],
              'sandbox_receipt': {'schema': 2, 'requested': True, 'enforced': False,
                                  'lifecycle': {'launched': False},
                                  'decision': decision, 'evidence': evidence}}
    if args.log:
        path = args.log.resolve()
        if path == repo or repo in path.parents:
            raise OSError('sandbox refusal log must be outside caller repository')
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(record, sort_keys=True) + '\n')
    print('UNVERIFIABLE  ' + spec['id'] + '  sandbox backend unqualified; no checks launched')
    return 2
