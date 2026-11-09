"""Trusted parent-side sandbox session and schema-2 evidence receipts.

No candidate check runs before bundle authentication, exact profile inspection
and an independent protected/scratch write canary. Supervisors own proxies in a
separate process group; actual wrapped checks use kernel_process.execute.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from kernel_bundle import authenticate, AuthenticationError, DependencyUnavailable, canonical_digest
from kernel_diagnostics import SEMANTICS, parse_raw_events, process_events


def snapshot(paths, excluded=()):
    rows = {}
    for root in map(Path, paths):
        names = [root]
        if root.is_dir() and not root.is_symlink():
            names += sorted(root.rglob('*'))
        for path in names:
            if any(path == value or value in path.parents for value in excluded):
                continue
            try:
                info = path.lstat()
            except FileNotFoundError:
                rows[str(path)] = {'type': 'absent'}; continue
            row = {'mode': stat.S_IMODE(info.st_mode)}
            if stat.S_ISLNK(info.st_mode): row.update(type='link', target=os.readlink(path))
            elif stat.S_ISDIR(info.st_mode): row['type'] = 'directory'
            elif stat.S_ISREG(info.st_mode): row.update(type='file', sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            else: raise OSError('unsupported protected object')
            rows[str(path)] = row
    return rows


def load_context(spec, repo, log, tracked, links):
    from kernel_sandbox import validate_declaration, resolve_writable_paths
    declaration = validate_declaration(spec.get('sandbox', {}))
    resolve_writable_paths(repo, declaration, tracked, links)
    context = {'declaration': declaration, 'repo': str(repo), 'log': str(log), 'links': links,
               'package': str(Path(__file__).resolve().parent), 'operator': {}, 'bundle': None}
    try:
        request = Path(os.environ['VERIFY_SANDBOX_OPERATOR']).resolve(strict=True)
        if request == repo or repo in request.parents:
            raise AuthenticationError('sandbox operator request is inside caller repository')
        operator = json.loads(request.read_text())
        if operator.get('schema') != 1 or operator.get('diagnostics', {}).get('mode') not in ('enabled', 'disabled'):
            raise AuthenticationError('invalid sandbox operator request')
        context['operator'] = operator
        qualification_path = Path(operator['qualification_record']).resolve(strict=True)
        if qualification_path == repo or repo in qualification_path.parents:
            raise AuthenticationError('qualification record inside candidate repository')
        qualification_bytes = qualification_path.read_bytes()
        qualification_digest = hashlib.sha256(qualification_bytes).hexdigest()
        if qualification_digest != operator.get('qualification_record_sha256'):
            raise AuthenticationError('qualification record digest mismatch')
        context['qualification'] = {'path': str(qualification_path), 'sha256': qualification_digest,
                                    'record': json.loads(qualification_bytes)}
        if not operator.get('bundle_receipt'):
            raise DependencyUnavailable('external sandbox bundle receipt absent')
        # Keep authenticated metadata available for a conservative ownership refusal.
        context['receipt'] = json.loads(Path(operator['bundle_receipt']).read_text())
        context['diagnostic_origins'] = {}
        context['diagnostic_corrections'] = []
        context['bundle'] = authenticate(operator, repo)
        local_validator = Path(context['package'])/'kernel_profile.py'
        bundled_validator = context['bundle']['root']/'kernel_profile.py'
        if hashlib.sha256(local_validator.read_bytes()).digest() != hashlib.sha256(bundled_validator.read_bytes()).digest():
            raise AuthenticationError('release validator differs from authenticated bundle')
    except (FileNotFoundError, KeyError, DependencyUnavailable) as error:
        context['unavailable'] = str(error)
    return context


def _platform():
    build = 'unavailable'
    if platform.system() == 'Darwin':
        try:
            result = subprocess.run(['/usr/bin/sw_vers', '-buildVersion'], capture_output=True, text=True)
            if result.returncode == 0: build = result.stdout.strip()
        except OSError: pass
    return {'system': platform.system(), 'release': platform.release(), 'machine': platform.machine(),
            'python': sys.version, 'python_executable': str(Path(sys.executable).resolve()),
            'python_executable_sha256': hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
            'git': shutil.which('git'), 'ps': shutil.which('ps'),
            'build': build}


def _secret_aliases(operator):
    """Resolve explicit secrets and preexisting hardlinks within bounded operator roots.

    This is not a host-wide secret inventory or a no-transient-read guarantee.
    If a linked secret has an unaccounted existing name, fail closed.
    """
    secrets = [Path(p).resolve(strict=True) for p in operator.get('secret_read_paths', [])]
    if (Path.home()/'.ssh').exists(): secrets.append((Path.home()/'.ssh').resolve(strict=True))
    aliases = set(secrets)
    protected = [Path(p).resolve() for p in operator.get('additional_protected_paths', [])]
    common = Path(os.path.commonpath([str(p) for p in protected])) if protected else None
    if common == Path('/') or common == Path.home():
        common = None  # Never enumerate the host or the user's entire home.
    files = set(secrets)
    for secret in secrets:
        if secret.is_dir(): files.update(path for path in secret.rglob('*') if path.is_file())
    for secret in files:
        info = secret.stat()
        if not secret.is_file() or info.st_nlink < 2: continue
        found = {secret}
        if common and common.is_dir():
            for path in common.rglob('*'):
                if not path.is_symlink() and path.is_file():
                    other = path.stat()
                    if (other.st_dev, other.st_ino) == (info.st_dev, info.st_ino): found.add(path)
        if len(found) != info.st_nlink:
            raise DependencyUnavailable('secret hardlink aliases are not fully inventoried in operator roots')
        aliases.update(found)
    return sorted(str(p) for p in aliases)


def git_metadata(root):
    paths = []
    for flag in ('--absolute-git-dir', '--git-common-dir'):
        result = subprocess.run(['git', 'rev-parse', flag], cwd=root,
                                capture_output=True, text=True, check=True)
        paths.append((Path(root)/result.stdout.strip()).resolve(strict=True))
    return paths


def validated_expected_denials(operator, check, phase, root, contract_sha256):
    """Bind explicit operator expectations to the frozen checked source.

    These declarations are caller-owned, not fields in candidate result text.
    They grant a diagnostic exemption only to the exact asserted operation.
    """
    rows = operator.get('expected_denials', [])
    if not isinstance(rows, list):
        raise DependencyUnavailable('invalid trusted expected-denial declarations')
    accepted = []
    for item in rows:
        if not isinstance(item, dict):
            raise DependencyUnavailable('invalid trusted expected-denial declaration')
        if item.get('check') != check['name'] or item.get('phase') != phase:
            continue
        target = item.get('target')
        source = item.get('source_path')
        if (not isinstance(item.get('id'), str) or not item['id'] or
                item.get('assertion_id') not in check['assertions'] or
                not isinstance(item.get('operation'), str) or not item['operation'] or
                not isinstance(target, str) or not os.path.isabs(target) or
                str(Path(target).resolve()) != target or
                source != check['entry'] or source not in check['chain'] or
                item.get('contract_sha256') != contract_sha256 or
                not isinstance(item.get('executable_sha256'), str) or len(item['executable_sha256']) != 64):
            raise DependencyUnavailable('invalid trusted expected-denial binding')
        source_path = (root/source).resolve(strict=True)
        if root.resolve() not in source_path.parents:
            raise DependencyUnavailable('expected-denial source escapes snapshot')
        if hashlib.sha256(source_path.read_bytes()).hexdigest() != item.get('source_sha256'):
            raise DependencyUnavailable('expected-denial source binding mismatch')
        accepted.append(dict(item))
    if len({entry['id'] for entry in accepted}) != len(accepted):
        raise DependencyUnavailable('duplicate expected-denial id')
    return accepted


def run_check(root, check, phase, context):
    from kernel_sandbox import classify_sandbox_evidence, backend_supports_policy, validate_generated_profile, resolve_writable_paths
    from kernel_report import read_result
    from kernel_process import execute, executable_identity
    token = uuid.uuid4().hex; start = time.time(); operator = context['operator']
    mode = operator.get('diagnostics', {}).get('mode', 'disabled')
    bundle = context.get('bundle'); raw_bundle = (bundle or {}).get('receipt', context.get('receipt', {}))
    declaration = context['declaration']; ports = declaration['localhost_ports']
    row = {'name': check['name'], 'kind': check['kind'], 'expected_exit': 0, 'passed': False, 'harness_error': True}
    lifecycle = {'launched': False}; prepared = {}; validation = {'validator_id': 'kernel-srt-profile-validator-v1', 'exact_match': False, 'inspected_profile': '', 'errors': ['not inspected']}
    diagnostics = {'semantics': SEMANTICS, 'absence_proves_nothing': True, 'absence_is_failure': False, 'mode': mode, 'state': 'disabled' if mode == 'disabled' else 'unavailable',
                   'received': 0, 'persisted': 0, 'dropped': 0, 'spool_capacity': 10000,
                   'drain_deadline': 2, 'upstream_completeness': 'unknown',
                   'raw_events_sha256': hashlib.sha256(b'').hexdigest(), 'collector_ready': False, 'complete': False,
                   'events': [], 'faults': [], 'canary': {'event_gates_verdict': False,
                       'event_received': None if mode == 'disabled' else False,
                       'match_status': 'not_collected' if mode == 'disabled' else 'absent',
                       'write_denied': None, 'scratch_succeeded': None, 'errno': None,
                       'probe_exit': None, 'probe_cleanup_complete': None,
                       'protected_before': None, 'protected_after': None,
                       'matched_event_ref': None, 'rejected_match_reasons': []}}
    cleanup = {'complete': True, 'survivors': [], 'errors': [], 'timed_out': False, 'observed': []}
    code = 99; output = ''; before = after = {}; failed = []; assertion = None; unavailable = None; supervisor = None
    provisional_bytes = None
    state_parent = Path(operator.get('scratch_root', tempfile.gettempdir())).resolve()
    state_parent.mkdir(parents=True, exist_ok=True)
    state = state_parent / ('kernel-' + token); state.mkdir(mode=0o700)
    scratch = state/'child'; scratch.mkdir(mode=0o700)
    result_path = scratch/'result.json'
    writes = resolve_writable_paths(root, declaration, context['tracked'], context['links'])
    excluded = tuple(Path(path) for path in writes)
    protected_paths = [root, Path(context['package']), Path(context['repo']),
                       *map(Path, operator.get('additional_protected_paths', [])), Path(context['log'])]
    protected_paths += git_metadata(root) + git_metadata(context['repo'])
    if bundle:
        protected_paths += [bundle['root'], Path(operator['bundle_receipt']).resolve()]
    profile_hash = None; inspected = ''; canary_binding = {}; preflight_started = False
    expected_denials = []
    try:
        # The declaration names usable output directory roots. Materialize only
        # the already validated, ignored, disjoint roots before observing the
        # protected inventory; this is trusted setup, not candidate authority.
        for path in writes:
            Path(path).mkdir(mode=0o700, parents=True, exist_ok=True)
        before = snapshot(protected_paths, excluded)
        expected_denials = validated_expected_denials(operator, check, phase, root, context.get('contract_sha256'))
        if context.get('unavailable'): raise DependencyUnavailable(context['unavailable'])
        if not backend_supports_policy(declaration): raise DependencyUnavailable('backend cannot enforce the requested policy')
        trusted_env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C.UTF-8'}
        version = subprocess.run([bundle['node'], '--version'], env=trusted_env,
                                 capture_output=True, text=True, timeout=5)
        if version.returncode or version.stdout.strip() != 'v24.22.0': raise DependencyUnavailable('qualified Node version unavailable')
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin', 'LANG': 'C.UTF-8',
               'HOME': str(scratch), 'TMPDIR': str(scratch), 'XDG_CACHE_HOME': str(scratch),
               'PYTHONDONTWRITEBYTECODE': '1', 'VERIFY_ROOT': str(root), 'VERIFY_TREE': phase,
               'VERIFY_RUN_ID': token, 'VERIFY_RESULT_JSON': str(result_path)}
        argv = list(check['argv'])
        argv[0] = check['_runtime_executable'] if check['_entry_position'] else str(root/check['entry'])
        if not argv[0]: raise DependencyUnavailable('declared runtime unavailable')
        config = {'cwd': str(root), 'command': shlex.join(argv), 'env': env,
                  'filesystem': {'denyRead': _secret_aliases(operator),
                                 'allowWrite': [*writes, str(scratch)],
                                 'denyWrite': [str(p) for p in protected_paths if p != root] + ['/tmp/claude', '/private/tmp/claude', str(state/'.npm'), str(state/'.claude')]},
                  'localhost_ports': ports, 'diagnostics': mode,
                  'prepared_path': str(state/'prepared.json'), 'result_path': str(state/'supervisor-result.json'),
                  'spool_path': str(state/'diagnostics.jsonl'),
                  'collector_spool_path': str(state/'collector.raw')}
        config_path = state/'config.json'; config_path.write_text(json.dumps(config))
        supervisor_env = {'PATH': env['PATH'], 'HOME': str(state), 'TMPDIR': str(state), 'LANG': env['LANG'], 'PYTHONDONTWRITEBYTECODE': '1', 'CLAUDE_CODE_TMPDIR': str(scratch)}
        supervisor = subprocess.Popen([bundle['node'], bundle['supervisor'], str(config_path)],
                                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                     env=supervisor_env, start_new_session=True)
        deadline = time.monotonic() + 12
        while not Path(config['prepared_path']).exists():
            if supervisor.poll() is not None or time.monotonic() > deadline:
                raise DependencyUnavailable('supervisor failed before profile preparation')
            time.sleep(.01)
        prepared = json.loads(Path(config['prepared_path']).read_text())
        profile = prepared['profile']; validation_context = prepared['template_context']
        generator = next(r['sha256'] for r in raw_bundle['patch_postimages'] if r['path'].endswith('/macos-sandbox-utils.js'))
        if (validation_context.get('generator_sha256') != generator or validation_context.get('localhost_ports') != ports or
                validation_context.get('proxies') != prepared['proxies'] or any(p['pid'] != supervisor.pid for p in prepared['proxies'])):
            raise DependencyUnavailable('prepared policy/template provenance mismatch')
        try: validation = validate_generated_profile(profile, validation_context)
        except (RuntimeError, OSError) as error:
            validation = {'validator_id': 'kernel-srt-profile-validator-v1', 'exact_match': False, 'inspected_profile': profile, 'errors': [str(error)]}
        inspected = validation['inspected_profile']; profile_hash = hashlib.sha256(inspected.encode()).hexdigest()
        if validation.get('exact_match') is not True: raise DependencyUnavailable('generated profile inspection failed: ' + '; '.join(validation['errors']))
        wrapped = prepared['argv']; index = prepared['command_index']
        if (not isinstance(wrapped, list) or type(index) is not int or not 5 <= index < len(wrapped) or wrapped[index] != config['command'] or
                wrapped[index-5:index] != ['/usr/bin/sandbox-exec', '-p', profile, '/bin/bash', '-c'] or
                wrapped.count(profile) != 1 or prepared['env'] != env):
            raise DependencyUnavailable('prepared launch bytes/environment differ from inspected policy')
        preflight_started = True
        probe_id = uuid.uuid4().hex
        canary = state/('canary-protected-' + probe_id); canary.write_text('protected')
        canary_before = snapshot([canary])
        # Probe is the same third-party Python executable under the inspected
        # policy. Its first record identifies the actual payload, which waits
        # while the trusted parent records a process start identity.
        script = """import os,sys,json,time
print(json.dumps({'pid':os.getpid(),'executable':os.path.realpath(sys.executable)}),flush=True)
sys.stdin.readline()
a=time.time_ns(); denied=False; error=None
try:
 fd=os.open(sys.argv[1],os.O_WRONLY|os.O_TRUNC); os.close(fd)
except OSError as e:
 error=e.errno; denied=e.errno in (1,13)
b=time.time_ns()
fd=os.open(sys.argv[2],os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); os.write(fd,b'scratch'); os.close(fd)
fd=os.open(sys.argv[2],os.O_RDONLY); data=os.read(fd,16); os.close(fd)
print(json.dumps({'denied':denied,'errno':error,'scratch':data==b'scratch','syscall_start':a/1e9,'syscall_end':b/1e9}),flush=True)
"""
        probe_argv = list(wrapped); probe_argv[index] = shlex.join([sys.executable, '-I', '-S', '-B', '-c', script, str(canary), str(scratch/'canary-allowed')])
        preflight_start = time.time()
        probe = subprocess.Popen(probe_argv, cwd=root, env=env, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            readable, _, _ = select.select([probe.stdout], [], [], 5)
            if not readable: raise DependencyUnavailable('preflight payload identity unavailable')
            subject = json.loads(probe.stdout.readline())
            pid = subject['pid']
            ps = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'lstart='], capture_output=True, text=True, timeout=2)
            subject_start = ps.stdout.strip() if ps.returncode == 0 else ''
            if not subject_start or not isinstance(pid, int) or pid <= 0:
                raise DependencyUnavailable('preflight payload start identity unavailable')
            launch_executable = str(Path(sys.executable).resolve(strict=True))
            if subject.get('executable') != launch_executable:
                raise DependencyUnavailable('preflight payload launch executable identity differs')
            process_identity = executable_identity(pid, subject_start)
            if not process_identity:
                raise DependencyUnavailable('preflight payload process executable identity unavailable')
            executable = process_identity['path']
            executable_sha = process_identity['sha256']
            stdout, stderr = probe.communicate('run\n', timeout=5)
        finally:
            if probe.poll() is None:
                probe.kill(); probe.communicate()
        preflight_end = time.time()
        pre = json.loads(stdout.strip())
        canary_binding = {'run_id': token, 'check': check['name'], 'phase': phase, 'repetition': 0,
            'probe_id': probe_id, 'command_tag': prepared['command_tag'], 'session_suffix': prepared['session_suffix'], 'path': str(canary.resolve()),
            'operation': 'file-write-data', 'denial_result': 1, 'subject_pid': pid,
            'subject_start': subject_start, 'executable': executable, 'executable_sha256': executable_sha,
            'preflight_start': preflight_start, 'preflight_end': preflight_end,
            'syscall_start': pre.get('syscall_start'), 'syscall_end': pre.get('syscall_end'),
            'clock_domain': 'unix-realtime', 'clock_resolution_seconds': .001,
            'clock_uncertainty_seconds': .001}
        canary_after = snapshot([canary])
        diagnostics['canary'] = {**canary_binding, 'write_denied': pre.get('denied') is True,
            'errno': pre.get('errno'), 'scratch_succeeded': pre.get('scratch') is True,
            'protected_before': canary_before, 'protected_after': canary_after,
            'probe_exit': probe.returncode, 'probe_cleanup_complete': probe.poll() is not None,
            'launch_executable': launch_executable, 'process_identity_observation': process_identity,
            'event_gates_verdict': False, 'event_received': None if mode == 'disabled' else False,
            'match_status': 'not_collected' if mode == 'disabled' else 'absent',
            'matched_event_ref': None, 'rejected_match_reasons': []}
        if probe.returncode or pre.get('denied') is not True or pre.get('scratch') is not True or canary_before != canary_after:
            raise DependencyUnavailable('preflight_operation_unavailable')
        lifecycle.update(launched=True, started_at=time.time())
        code, output, cleanup = execute(wrapped, root, env, check['timeout'])
        lifecycle.update(exited_at=time.time(), cleanup_finished_at=time.time())
        try:
            assertion, failed = read_result(result_path, check, phase, token, code)
            provisional_bytes = result_path.read_bytes()
        except (OSError, ValueError, TypeError, UnicodeError) as error: row['result_protocol_error'] = str(error)
    except (DependencyUnavailable, OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError) as error:
        unavailable = str(error)
        if preflight_started and not lifecycle['launched']:
            diagnostics['faults'].append('preflight_operation_unavailable')
    finally:
        if supervisor is not None:
            try:
                if supervisor.poll() is not None:
                    unavailable = unavailable or 'supervisor died before finish request'
                _, stderr = supervisor.communicate(b'finish\n', timeout=8)
                if supervisor.returncode: unavailable = unavailable or 'supervisor exited unsuccessfully'
            except (OSError, subprocess.TimeoutExpired):
                unavailable = unavailable or 'supervisor cleanup incomplete'
                try: os.killpg(supervisor.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                except OSError as error: cleanup['errors'].append('supervisor group cleanup: ' + str(error))
                try: supervisor.communicate(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    cleanup['errors'].append('supervisor exit not observed')
                cleanup['complete'] = False
            path = state/'supervisor-result.json'
            try:
                if not path.exists(): raise OSError('supervisor final evidence missing')
                collected = json.loads(path.read_text())
                if not isinstance(collected, dict) or collected.get('mode') != mode:
                    raise ValueError('diagnostic requested mode differs from supervisor evidence')
                monitor = collected.get('monitor')
                if not isinstance(monitor, dict):
                    raise ValueError('diagnostic collector lifecycle evidence missing')
                if mode == 'disabled':
                    diagnostics['monitor'] = monitor
                    if (monitor.get('started') or collected.get('received') or
                            collected.get('persisted') or collected.get('dropped') or collected.get('events')):
                        raise ValueError('unexpected collector activity in disabled mode')
                if collected.get('error'): unavailable = unavailable or collected['error']
                if mode == 'enabled':
                    spool = Path(config['spool_path'])
                    raw_events = spool.read_bytes()
                    events = [json.loads(line) for line in raw_events.splitlines()]
                    if any(not isinstance(event, dict) for event in events):
                        raise ValueError('invalid diagnostic event record')
                    if len(events) != collected.get('persisted'):
                        raise ValueError('diagnostic spool count mismatch')
                    if hashlib.sha256(raw_events).hexdigest() != collected.get('spool_sha256'):
                        raise ValueError('diagnostic spool digest mismatch')
                    collector_bytes = Path(config['collector_spool_path']).read_bytes()
                    if (len(collector_bytes) != collected.get('collector_persisted_bytes') or
                            hashlib.sha256(collector_bytes).hexdigest() != collected.get('collector_spool_sha256')):
                        raise ValueError('raw collector spool identity mismatch')
                    diagnostics.update(state='failed' if collected.get('collector_fault') else 'active',
                                       received=collected.get('received', len(events)), persisted=len(events),
                                       dropped=collected.get('dropped', 0),
                                       collector_fault=collected.get('collector_fault'),
                                       drain_timed_out=collected.get('drain_timed_out', False),
                                       late_event=collected.get('late_event'),
                                       attribution=collected.get('attribution'), monitor=collected.get('monitor'),
                                       raw_collector_path=config['collector_spool_path'],
                                       raw_collector_sha256=hashlib.sha256(collector_bytes).hexdigest(),
                                       raw_collector_bytes=len(collector_bytes),
                                       raw_collector_received_bytes=collected.get('collector_received_bytes'),
                                       raw_collector_capacity=collected.get('collector_capacity'),
                                       raw_events_path=str(spool), raw_events_sha256=hashlib.sha256(raw_events).hexdigest(),
                                       collector_raw_chunks=collected.get('collector_raw', {}).get('chunks', []))
                    raw_denials, raw_faults = parse_raw_events(collector_bytes, events, prepared.get('session_suffix'), collected.get('collector_raw', {}).get('chunks', []))
                    interpreted = process_events(raw_denials, canary_binding, collector_bytes, {**lifecycle, 'observed': cleanup.get('observed', [])}, context.get('diagnostic_origins'), expected_denials, assertion)
                    diagnostics.update(events=interpreted['events'], raw_denial_count=len(raw_denials),
                                       faults=list(dict.fromkeys(diagnostics['faults'] + raw_faults + interpreted['faults'])))
                    # The parent can resolve a retained prior origin that the
                    # per-session supervisor could only mark non-current.
                    if (interpreted['events'] and not raw_faults and
                            all(event['attribution'] in ('original_invocation', 'prior_invocation')
                                for event in interpreted['events'])):
                        diagnostics['attribution'] = ('resolved_cross_invocation'
                            if any(event['attribution'] == 'prior_invocation' for event in interpreted['events'])
                            else 'original_invocation')
                    canary_record = diagnostics.setdefault('canary', {})
                    canary_record['event_received'] = bool(interpreted['matched'])
                    canary_record['match_status'] = ('matched' if interpreted['matched'] else
                                                      'unmatched' if interpreted['rejected'] else 'absent')
                    canary_record['matched_event_ref'] = interpreted['matched'][0] if interpreted['matched'] else None
                    canary_record['rejected_match_reasons'] = interpreted['rejected']
                    for correction in interpreted['corrections']:
                        # The sealed original receipt is immutable. Append the
                        # correction under this trusted invocation's state and
                        # invalidate the dependent in-memory aggregate row.
                        correction = {'schema': 1, 'kind': 'diagnostic_receipt_correction',
                                      'receiving_run_id': token, 'at': time.time(), **correction,
                                      'origin_verdict': 'unverifiable', 'aggregate_verdict': 'unverifiable'}
                        correction_path = state/'corrections.jsonl'
                        with correction_path.open('a', encoding='utf-8') as handle:
                            handle.write(json.dumps(correction, sort_keys=True) + '\n')
                            handle.flush(); os.fsync(handle.fileno())
                        correction['path'] = str(correction_path)
                        context.setdefault('diagnostic_corrections', []).append(correction)
                        for origin in context.get('diagnostic_origins', {}).values():
                            if origin['receipt_sha256'] == correction['original_receipt_sha256']:
                                origin['row']['passed'] = False
                                origin['row']['harness_error'] = True
                                origin['row'].setdefault('receipt_corrections', []).append(correction)
                lifecycle['supervisor'] = {'pid': supervisor.pid, 'exit': supervisor.returncode,
                                           'cleanup_finished_at': time.time()}
            except (OSError, ValueError, TypeError) as error:
                unavailable = unavailable or 'supervisor evidence unavailable: ' + str(error)
                diagnostics['faults'].append('diagnostic_evidence_invalid')
                if mode == 'enabled': diagnostics['state'] = 'failed'
        if lifecycle['launched']:
            lifecycle.setdefault('exited_at', time.time())
            lifecycle['cleanup_finished_at'] = time.time()
        try: after = snapshot(protected_paths, excluded)
        except OSError as error: unavailable = unavailable or str(error)
    changes = [{'kind': 'protected_change', 'path': p, 'before': before.get(p), 'after': after.get(p)}
               for p in sorted(set(before)|set(after)) if before.get(p) != after.get(p)] if before and after else []
    # Preserve measured changes even if this independent final observation fails.
    final_inventory_available = True
    try:
        final = snapshot(protected_paths, excluded)
        if final != after:
            for p in sorted(set(after)|set(final)):
                if after.get(p) != final.get(p):
                    changes.append({'kind': 'protected_change', 'path': p, 'before': after.get(p), 'after': final.get(p), 'boundary': 'final'})
    except OSError as error:
        final_inventory_available = False; unavailable = unavailable or str(error)
    evidence = {'schema': 1, 'integrity': {'available': bool(before and after), 'before': before, 'after': after, 'changes': changes,
                                        'additional_inventory_available': final_inventory_available},
                'execution': {'complete': unavailable is None, 'unavailable_reason': unavailable, 'timed_out': cleanup['timed_out']},
                'cleanup': cleanup, 'assertions': {'complete': assertion is not None, 'failed': failed}, 'diagnostics': diagnostics}
    decision = classify_sandbox_evidence(evidence); host = _platform()
    policy = {'writable_roots': writes, 'scratch_root': str(scratch), 'secret_read_paths': operator.get('secret_read_paths', []),
              'protected_inventory_digest': canonical_digest(before), 'policy_digest': canonical_digest(declaration), 'backend': 'srt-0.0.81',
              'localhost_endpoints': [{'host': h, 'port': p, 'transport': 'tcp'} for p in ports for h in ('127.0.0.1','::1')],
              'network_semantics': 'srt-0.0.81-exact-tcp-v1', 'effective_network_rules': validation.get('effective_network_rules'),
              'profile_sha256': profile_hash, 'profile_validation': validation,
              'internal_ipc': {'proxies': prepared.get('proxies', []), 'non_ip_rules': [{'operation': 'system-socket', 'socket_domain': 'AF_SYSTEM', 'socket_protocol': 2}]},
              'exceptions': [
                  {'id': 'address_wildcard_declared_tcp_binding', 'ports': ports, 'nonloopback_inbound_exposure': bool(ports), 'accepted_connection_data_exchange': bool(ports), 'detail': 'Declared TCP binds/inbound are wildcard-address and accepted peers can exchange data.'},
                  {'id': 'localhost_address_class_aliases', 'literal_spelling_enforced': False, 'detail': 'Seatbelt localhost is an OS address class, not a spelling or server identity filter.'},
                  {'id': 'mapped_outbound_qualification', 'status': 'unavailable', 'universal_compatibility': False, 'platform': {k: host[k] for k in ('system','release','machine')}, 'os_build': host['build'], 'node_version': raw_bundle.get('node', {}).get('version'), 'node_artifact_sha256': raw_bundle.get('node', {}).get('artifact_sha256'), 'detail': 'Mapped outbound behavior has not been qualified on this exact bundle/platform.'}]}
    metadata = {k: raw_bundle.get(k) for k in ('srt_version','lock_sha256','bundle_digest','patch_id','patch_sha256','patch_preimages','patch_postimages')}
    metadata.update(node_version=raw_bundle.get('node', {}).get('version'), node_artifact_sha256=raw_bundle.get('node', {}).get('artifact_sha256'), node_executable=(bundle or {}).get('node'), node_executable_sha256=raw_bundle.get('node', {}).get('executable_sha256'))
    lifecycle['finalized_at'] = time.time()
    enforced = (validation.get('exact_match') is True and
                diagnostics.get('canary', {}).get('write_denied') is True and
                diagnostics.get('canary', {}).get('scratch_succeeded') is True)
    receipt = {'schema': 3, 'qualification': context.get('qualification'), 'requested': True, 'enforced': enforced, 'identity': {'run_id': token, 'check': check['name'], 'phase': phase, 'repetition': 0},
               'release': {'manifest_sha256': os.environ.get('VERIFY_RELEASE_SHA256')}, 'bundle': metadata, 'platform': host,
               'policy': policy, 'lifecycle': lifecycle, 'integrity': {**evidence['integrity'], 'judge_before': before, 'judge_after': after, 'receipt_prefix_sha256': before.get(context['log'], {}).get('sha256')},
               'diagnostics': diagnostics, 'decision': decision, 'assertions': {'provisional': assertion, 'cleanup': cleanup,
                   'provisional_bytes': provisional_bytes.decode('utf-8') if provisional_bytes is not None else None,
                   'provisional_sha256': hashlib.sha256(provisional_bytes).hexdigest() if provisional_bytes is not None else None},
               'assurance': {k: False for k in ('all_attempts_detected','transient_writes_detected','complete_logs','semantic_attestation','exhaustive_descendant_containment','loopback_only_binding','literal_address_only')},
               'dev_only': (bundle or {}).get('dev_only', False)}
    receipt['assurance'].update(swallowed_undelivered_denial_may_be_supported=True, independent_nonnetwork_policy_oracle=False)
    sealed_bytes = json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode('utf-8')
    receipt_path = state/'sandbox-receipt.json'
    try:
        with receipt_path.open('xb') as handle:
            handle.write(sealed_bytes); handle.flush(); os.fsync(handle.fileno())
        receipt_sha = hashlib.sha256(sealed_bytes).hexdigest()
        row['sandbox_receipt_path'] = str(receipt_path)
        row['sandbox_receipt_sha256'] = receipt_sha
        if canary_binding.get('command_tag'):
            context.setdefault('diagnostic_origins', {})[(canary_binding['command_tag'], canary_binding['session_suffix'])] = {
                'identity': receipt['identity'], 'receipt_sha256': receipt_sha,
                'binding': canary_binding, 'row': row, 'observed': cleanup.get('observed', []),
                'lifecycle': {'started_at': lifecycle.get('started_at'), 'exited_at': lifecycle.get('exited_at')}}
    except OSError as error:
        row.update(passed=False, harness_error=True, result_protocol_error='receipt persistence unavailable: ' + str(error))
        decision['verdict'] = 'unverifiable'
        decision.setdefault('unavailable_reasons', []).append('receipt_persistence_unavailable')
    row.update(exit=code, seconds=round(time.time()-start, 2), output=output, output_tail=output[-1500:], cleanup=cleanup,
               sandbox_receipt=receipt, failed_assertions=failed, assertion_result=assertion,
               passed=decision['verdict']=='supported', harness_error=decision['verdict']=='unverifiable')
    return row
