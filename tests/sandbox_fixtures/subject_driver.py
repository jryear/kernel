"""Trusted test adapter: invokes the subject, never implements sandbox policy.

Faults patch only this disposable interpreter. No installed judge is imported.
The classifier seam is an explicit freeze interface, reviewed before production.
"""
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
mode, package, request_path = sys.argv[1:4]
package = Path(package).resolve()
request = json.loads(Path(request_path).read_text())
sys.path.insert(0, str(package))
if mode == 'classify':
    subject = importlib.import_module('kernel_sandbox')
    result = subject.classify_sandbox_evidence(request)
    print('SANDBOX_CLASSIFICATION ' + json.dumps(result, sort_keys=True))
else:
    fault = request.get('fault')
    marker = Path(request['fault_marker'])
    real_run, real_popen, real_which = subprocess.run, subprocess.Popen, shutil.which
    real_killpg = os.killpg
    armed = threading.Event()
    observation_fault_active = threading.Event()
    armed_check = {}
    if fault == 'kill':
        def denied(pgid, *args, **kwargs):
            if armed.is_set() and pgid == armed_check.get('pid'):
                marker.write_text(json.dumps({'fault':'kill','pgid':pgid,'at':time.time()}))
                raise PermissionError('frozen fixture: killpg unavailable')
            return real_killpg(pgid, *args, **kwargs)
        os.killpg = denied
    if fault == 'ps_or_identity_observation':
        def arm_after_cleanup_kill(pgid, *args, **kwargs):
            if armed.is_set() and pgid == armed_check.get('pid'):
                observation_fault_active.set()
            return real_killpg(pgid, *args, **kwargs)
        os.killpg = arm_after_cleanup_kill
        def failed_ps(argv, *args, **kwargs):
            if observation_fault_active.is_set() and isinstance(argv, list) and Path(argv[0]).name == 'ps':
                marker.write_text(json.dumps({'fault':'ps_or_identity_observation','pgid':armed_check['pid'],'at':time.time()}))
                return subprocess.CompletedProcess(argv, 1, stdout='', stderr='frozen fixture: ps unavailable')
            return real_run(argv, *args, **kwargs)
        subprocess.run = failed_ps
    if fault == 'missing_facility':
        def missing(name, *args, **kwargs):
            if Path(name).name in ('sandbox-exec', 'bwrap'):
                marker.write_text('facility injected')
                return None
            return real_which(name, *args, **kwargs)
        shutil.which = missing
    if fault in ('missing_node','wrong_node_version'):
        def faulty_node(argv, *args, **kwargs):
            if isinstance(argv,list) and Path(argv[0]).name.startswith('node'):
                marker.write_text(fault+' injected')
                if fault=='missing_node': raise FileNotFoundError('frozen fixture: qualified Node unavailable')
                if '--version' in argv:
                    return subprocess.CompletedProcess(argv,0,stdout='v0.0.0\n',stderr='')
            return real_run(argv,*args,**kwargs)
        subprocess.run=faulty_node
        if fault=='missing_node':
            def no_node(argv,*args,**kwargs):
                if isinstance(argv,list) and Path(argv[0]).name.startswith('node'):
                    marker.write_text('missing_node injected')
                    raise FileNotFoundError('frozen fixture: qualified Node unavailable')
                return real_popen(argv,*args,**kwargs)
            subprocess.Popen=no_node
    if fault == 'unsupported_policy':
        backend=importlib.import_module('kernel_sandbox')
        if not callable(getattr(backend,'backend_supports_policy',None)):
            raise RuntimeError('reviewed capability qualification seam unavailable')
        def unsupported(*args,**kwargs):
            marker.write_text('unsupported exact policy injected')
            return False
        backend.backend_supports_policy=unsupported
    if fault in ('supervisor_death', 'kill', 'ps_or_identity_observation'):
        owned = {}
        owned_log = Path(request['owned_check_log'])

        def host_identity(pid):
            # Use the unpatched host observer, never a child receipt, for PID reuse checks.
            result = real_run(['/bin/ps', '-p', str(pid), '-o', 'pgid=,stat=,lstart='],
                              capture_output=True, text=True, timeout=2)
            fields = result.stdout.strip().split(None, 2)
            if result.returncode or len(fields) != 3 or fields[1].startswith('Z'):
                return None
            return {'pid': pid, 'pgid': int(fields[0]), 'state': fields[1], 'started': fields[2]}

        def watch_supervisor(proc, config_path):
            try:
                config = json.loads(Path(config_path).read_text())
                scratch = Path(config['prepared_path']).parent / 'child'
                if not scratch.resolve().is_relative_to(Path(request['scratch_root']).resolve()):
                    return
                handshake = scratch / 'supervisor-handshake.json'
                release = scratch / 'supervisor-release.json'
                while proc.poll() is None:
                    if handshake.exists():
                        try: row = json.loads(handshake.read_text())
                        except (OSError, ValueError): time.sleep(.01); continue
                        check = owned.get(row.get('pgid'))
                        current = host_identity(row.get('pid')) if type(row.get('pid')) is int else None
                        leader = host_identity(check['pid']) if check else None
                        child = host_identity(row.get('child_pid')) if type(row.get('child_pid')) is int else None
                        if (row.get('nonce') != request['barrier_nonce'] or row.get('operation') != 'group_child' or
                                not check or check['phase'] != 'candidate' or not check['started'] or not current or
                                not leader or leader['started'] != check['started'] or leader['pgid'] != check['pgid'] or
                                not child or child['pgid'] != check['pgid'] or
                                current['pgid'] != check['pgid'] or row.get('pgid') != check['pgid'] or
                                proc.poll() is not None):
                            return
                        observed_at = time.time()
                        proc.kill()
                        proc.wait(timeout=1)
                        killed_at = time.time()
                        released_at = time.time()
                        release.write_text(json.dumps({'nonce': row['nonce'], 'at': released_at}))
                        marker.write_text(json.dumps({'nonce': row['nonce'], 'handshake': row,
                            'check': check, 'payload_identity': current, 'child_identity': child, 'supervisor_pid': proc.pid,
                            'observed_at': observed_at, 'killed_at': killed_at, 'released_at': released_at}))
                        return
                    time.sleep(.01)
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                return

        def watch_fault_barrier(proc, scratch, row):
            try:
                handshake = Path(scratch) / 'fault-handshake.json'
                release = Path(scratch) / 'fault-release.json'
                if not handshake.parent.resolve().is_relative_to(Path(request['scratch_root']).resolve()): return
                while proc.poll() is None:
                    if handshake.exists():
                        try: progress = json.loads(handshake.read_text())
                        except (OSError, ValueError): time.sleep(.01); continue
                        current = host_identity(progress.get('pid')) if type(progress.get('pid')) is int else None
                        leader = host_identity(row['pid'])
                        if (progress.get('nonce') != request['barrier_nonce'] or progress.get('operation') != 'timeout' or
                                progress.get('pgid') != row['pgid'] or not current or current['pgid'] != row['pgid'] or
                                not leader or leader['pgid'] != row['pgid'] or leader['started'] != row['started'] or
                                not row['started'] or proc.poll() is not None): return
                        observed_at = time.time()
                        armed_check.update(row); armed.set()
                        released_at = time.time()
                        release.write_text(json.dumps({'nonce':progress['nonce'],'at':released_at}))
                        Path(request['progress_marker']).write_text(json.dumps({'nonce':progress['nonce'],
                            'handshake':progress,'check':row,'payload_identity':current,
                            'observed_at':observed_at,'armed_at':observed_at,'released_at':released_at}))
                        return
                    time.sleep(.01)
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                return

        def tracked_popen(argv, *args, **kwargs):
            proc = real_popen(argv, *args, **kwargs)
            if isinstance(kwargs.get('env'), dict) and 'VERIFY_PROCESS_TOKEN' in kwargs['env']:
                identity = host_identity(proc.pid)
                row = {'pid': proc.pid, 'pgid': identity['pgid'] if identity else None, 'started': identity['started'] if identity else None,
                       'phase': kwargs['env'].get('VERIFY_TREE'), 'spawned_at': time.time()}
                owned[proc.pid] = row
                with owned_log.open('a') as handle:
                    handle.write(json.dumps(row) + '\n'); handle.flush(); os.fsync(handle.fileno())
                if fault in ('kill','ps_or_identity_observation') and row['phase']=='candidate':
                    threading.Thread(target=watch_fault_barrier, args=(proc,kwargs['env'].get('TMPDIR'),row), daemon=True).start()
            if (fault == 'supervisor_death' and isinstance(argv, list) and len(argv) >= 3 and
                    any('supervisor' in str(v) and str(v).endswith(('.mjs','.js')) for v in argv)):
                threading.Thread(target=watch_supervisor, args=(proc, argv[2]), daemon=True).start()
            return proc
        subprocess.Popen = tracked_popen
    if isinstance(fault, str) and fault.startswith('profile:'):
        from profile_faults import alter_profile
        backend = importlib.import_module('kernel_sandbox')
        validator = getattr(backend, 'validate_generated_profile', None)
        if not callable(validator):
            raise RuntimeError('reviewed generated-profile validator seam unavailable')
        variant = fault.split(':', 1)[1]
        def injected_profile(profile, context):
            altered = alter_profile(profile, variant)
            witness = {'fault': variant,
                       'before_sha256': hashlib.sha256(profile.encode()).hexdigest(),
                       'inspected_sha256': hashlib.sha256(altered.encode()).hexdigest()}
            marker.write_text(json.dumps(witness, sort_keys=True))
            if variant == 'inspection_failure':
                raise RuntimeError('frozen fixture: profile inspection failed')
            if variant == 'inspection_unavailable':
                raise OSError('frozen fixture: profile inspection unavailable')
            return validator(altered, context)
        backend.validate_generated_profile = injected_profile
    if request.get('audit_bundle_roots'):
        roots = [Path(value).resolve() for value in request['audit_bundle_roots']]
        audit = Path(request['bundle_launch_audit'])
        prior_popen = subprocess.Popen
        def audited_popen(argv, *args, **kwargs):
            if isinstance(argv, list) and argv:
                executable = Path(argv[0]).resolve()
                if any(executable == root or root in executable.parents for root in roots):
                    with audit.open('a') as handle:
                        handle.write(json.dumps({'executable': executable.name}) + '\n')
            return prior_popen(argv, *args, **kwargs)
        subprocess.Popen = audited_popen
    subject = importlib.import_module('verify')
    sys.argv = [str(package/'verify.py'), *sys.argv[4:]]
    sys.exit(subject.main())
