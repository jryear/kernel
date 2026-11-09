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
from datetime import datetime

sys.dont_write_bytecode = True
mode, package, request_path = sys.argv[1:4]
package = Path(package).resolve()
request = json.loads(Path(request_path).read_text())
sys.path.insert(0, str(package))
if mode == 'classify':
    subject = importlib.import_module('kernel_sandbox')
    result = subject.classify_sandbox_evidence(request)
    print('SANDBOX_CLASSIFICATION ' + json.dumps(result, sort_keys=True))
elif mode == 'match_canary':
    diagnostics = importlib.import_module('kernel_diagnostics')
    result = diagnostics.match_canary_event(request['event'], request['binding'])
    print('CANARY_MATCH ' + json.dumps(result, sort_keys=True))
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
    if request.get('collector_fixture'):
        fixture=request['collector_fixture']; prior_popen=subprocess.Popen
        collector={'write_fd':None, 'supervisor':None, 'config':None, 'check':None}
        fixture_root=Path(fixture['root']).resolve(strict=True)
        scratch_root=Path(fixture['scratch_root']).resolve(strict=True)
        audit=fixture_root/'collector-adapter-audit.jsonl'
        def log_audit(event):
            with audit.open('a',encoding='utf-8') as f:
                f.write(json.dumps(event,sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())
        def inject_when_ready():
            deadline=time.monotonic()+15
            try:
                while time.monotonic()<deadline:
                    check=collector.get('check');cfg=collector.get('config')
                    if check and cfg and collector.get('write_fd') is not None:
                        handshakes=list(scratch_root.glob('kernel-*/child/diagnostic-handshake.json'))
                        if handshakes:
                            handshake=handshakes[-1]
                            try: witness=json.loads(handshake.read_text())
                            except (OSError,ValueError): time.sleep(.01);continue
                            # Host observes that the claimed PID exists in the
                            # actual owned check group; no candidate text supplies
                            # event bytes, tag, target, or injection descriptor.
                            ps=real_run(['/bin/ps','-p',str(witness.get('pid')),'-o','pgid=,stat=,lstart='],
                                        capture_output=True,text=True,timeout=2)
                            fields=ps.stdout.strip().split(None,2)
                            if (witness.get('nonce')!=fixture.get('nonce') or witness.get('errno') not in (1,13) or
                                witness.get('outcome')!='denied' or len(fields)!=3 or
                                int(fields[0])!=check.pid or fields[1].startswith('Z')):
                                raise RuntimeError('diagnostic payload witness identity/denial unavailable')
                            prepared=json.loads(Path(cfg['prepared_path']).read_text())
                            instant=datetime.fromtimestamp(witness['at']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                            line=f"{instant} E kernel[0:abcd] (Sandbox) Sandbox: Python({witness['pid']}) deny(1) file-write-data {fixture['target']}"
                            frame={'type':'event','line':line,'tag':prepared['command_tag']}
                            release=handshake.with_name('diagnostic-release.json')
                            is_drain=fixture['case_id'] in ('DRAIN_RELEVANT_DENIAL_PASSING','LATE_RELEVANT_DENIAL')
                            if is_drain:
                                release.write_text(json.dumps({'nonce':witness['nonce']}))
                                while check.poll() is None and time.monotonic()<deadline: time.sleep(.005)
                                if check.poll() is None: raise RuntimeError('leader did not exit before drain event')
                                time.sleep(.1)
                            os.write(collector['write_fd'],(json.dumps(frame)+'\n').encode())
                            log_audit({'type':'injected','case':fixture['case_id'],'frame':frame,
                                       'witness':witness,'host_identity':fields,'at':time.time(),
                                       'leader_exited':check.poll() is not None})
                            if not is_drain:
                                # Let Node consume the event before the live
                                # candidate is released from its progress barrier.
                                time.sleep(.1)
                                release.write_text(json.dumps({'nonce':witness['nonce']}))
                            return
                    time.sleep(.01)
                raise RuntimeError('diagnostic fixture barrier timed out')
            except Exception as error:
                log_audit({'type':'adapter_error','error':repr(error)})
        def instrumented_popen(argv,*args,**kwargs):
            if isinstance(argv,list) and len(argv)>=3 and str(argv[1]).endswith('supervisor.mjs'):
                cfg=json.loads(Path(argv[2]).read_text())
                if cfg.get('env',{}).get('VERIFY_TREE')=='candidate':
                    read_fd,write_fd=os.pipe()
                    env=dict(kwargs.get('env') or {})
                    env.update(KERNEL_TEST_COLLECTOR_FD=str(read_fd),
                               KERNEL_TEST_COLLECTOR_LIVE=str(fixture_root/'collector-live.raw'),
                               KERNEL_TEST_COLLECTOR_SUPPRESS='1')
                    kwargs['env']=env;kwargs['pass_fds']=(*kwargs.get('pass_fds',()),read_fd)
                    argv=[argv[0],'--import',fixture['adapter'],*argv[1:]]
                    try: proc=prior_popen(argv,*args,**kwargs)
                    finally: os.close(read_fd)
                    collector.update(write_fd=write_fd,supervisor=proc,config=cfg)
                    threading.Thread(target=inject_when_ready,daemon=True).start()
                    log_audit({'type':'supervisor_preload','pid':proc.pid,'fd':read_fd,
                               'adapter':fixture['adapter'],'candidate_fd_inheritance':'closed by independent check subprocess'})
                    return proc
            proc=prior_popen(argv,*args,**kwargs)
            if isinstance(kwargs.get('env'),dict) and kwargs['env'].get('VERIFY_PROCESS_TOKEN') and kwargs['env'].get('VERIFY_TREE')=='candidate':
                collector['check']=proc
            return proc
        subprocess.Popen=instrumented_popen
    subject = importlib.import_module('verify')
    sys.argv = [str(package/'verify.py'), *sys.argv[4:]]
    sys.exit(subject.main())
