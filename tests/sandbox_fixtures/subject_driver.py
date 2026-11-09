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
import uuid
from datetime import datetime

sys.dont_write_bytecode = True

def publish_host_json(path, value):
    """Make a complete host barrier record visible in one rename."""
    temporary = path.with_name(path.name + '.host-' + uuid.uuid4().hex)
    with temporary.open('x', encoding='utf-8') as handle:
        json.dump(value, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)

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
                        publish_host_json(release, {'nonce': row['nonce'], 'at': released_at})
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
                        publish_host_json(release, {'nonce':progress['nonce'],'at':released_at})
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
        if fixture['case_id']=='CANARY_BOUND_DELAYED_DIAGNOSTIC':
            def trace_binding(frame,event,arg):
                if (event=='line' and frame.f_code.co_name=='run_check' and
                    frame.f_code.co_filename.endswith('kernel_sandbox_runtime.py')):
                    local=frame.f_locals
                    if local.get('phase')=='candidate' and isinstance(local.get('canary_binding'),dict):
                        collector['canary_binding']=dict(local['canary_binding'])
                return trace_binding
            sys.settrace(trace_binding)
        def publish_release(path,nonce):
            published_at=time.time()
            publish_host_json(path, {'nonce': nonce})
            log_audit({'type':'release_published','nonce':nonce,'path':str(path),'at':published_at})
        def wait_host_record(filename,predicate,deadline):
            path=fixture_root/filename
            while time.monotonic()<deadline:
                if path.exists():
                    try: rows=[json.loads(line) for line in path.read_text().splitlines()]
                    except (OSError,ValueError): time.sleep(.005);continue
                    found=next((row for row in rows if predicate(row)),None)
                    if found:return found
                time.sleep(.005)
            raise RuntimeError('host boundary acknowledgement timed out: '+filename)
        def inject_when_ready():
            deadline=time.monotonic()+15
            try:
                while time.monotonic()<deadline:
                    check=collector.get('check');cfg=collector.get('config')
                    if check and cfg and collector.get('write_fd') is not None:
                        handshake_path=Path(cfg['prepared_path']).parent/'child'/'diagnostic-handshake.json'
                        handshakes=[handshake_path] if handshake_path.exists() else []
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
                            delayed=fixture['case_id']=='CANARY_BOUND_DELAYED_DIAGNOSTIC'
                            if (witness.get('nonce')!=fixture.get('nonce') or len(fields)!=3 or
                                int(fields[0])!=check.pid or witness.get('pgid')!=check.pid or fields[1].startswith('Z') or
                                (not delayed and (witness.get('errno') not in (1,13) or witness.get('outcome')!='denied'))):
                                raise RuntimeError('diagnostic payload witness identity/operation unavailable')
                            prepared=json.loads(Path(cfg['prepared_path']).read_text())
                            binding=collector.get('canary_binding') if delayed else None
                            if delayed and not binding: raise RuntimeError('host preflight binding unavailable')
                            occurred=(binding['syscall_start']+binding['syscall_end'])/2 if delayed else witness['at']
                            subject=binding['subject_pid'] if delayed else witness['pid']
                            target=binding['path'] if delayed else fixture['target']
                            instant=datetime.fromtimestamp(occurred).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                            line=f"{instant} E kernel[0:abcd] (Sandbox) Sandbox: Python({subject}) deny(1) file-write-data {target}"
                            frame={'type':'event','line':line,'tag':prepared['command_tag']}
                            release=handshake.with_name('diagnostic-release.json')
                            is_drain=fixture['case_id'] in ('DRAIN_RELEVANT_DENIAL_PASSING','LATE_RELEVANT_DENIAL','DELAYED_AFTER_LEADER_EXIT','DRAIN_TIMEOUT')
                            if is_drain:
                                publish_release(release,witness['nonce'])
                                while check.poll() is None and time.monotonic()<deadline: time.sleep(.005)
                                if check.poll() is None: raise RuntimeError('leader did not exit before drain event')
                                if fixture['case_id']=='DRAIN_RELEVANT_DENIAL_PASSING':
                                    wait_host_record('collector-write-ack.jsonl',lambda r:r.get('type')=='drain_started',deadline)
                                if fixture.get('force_finish_before_frame'):
                                    finish=wait_host_record('fault-adapter-audit.jsonl',lambda r:r.get('type')=='supervisor_finish_observed',deadline)
                                    log_audit({'type':'forced_finish_before_frame','finish':finish,'at':time.time()})
                            is_postfinal=fixture['case_id']=='POSTFINAL_RELEVANT_DENIAL_INVALIDATES'
                            if is_postfinal and not collector.get('postfinal_frame'):
                                collector['postfinal_frame']={**frame,'suffix':prepared['session_suffix']}
                                silent=True
                            elif is_postfinal:
                                frame=collector['postfinal_frame'];silent=False
                            else:
                                silent=fixture['case_id']=='SWALLOWED_INVISIBLE_DENIAL_ENABLED'
                            frame={**frame,'frame_id':uuid.uuid4().hex}
                            if not silent:
                                os.write(collector['write_fd'],(json.dumps(frame)+'\n').encode())
                                if fixture['case_id']=='EXPECTED_DENIAL_UNRELATED_CONTROL':
                                    extra=witness.get('extra') or {}
                                    if extra.get('errno') not in (1,13) or extra.get('outcome')!='denied':
                                        raise RuntimeError('second independent denial unavailable')
                                    at=datetime.fromtimestamp(extra['at']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                                    other={'type':'event','frame_id':uuid.uuid4().hex,'line':f"{at} E kernel[0:abcd] (Sandbox) Sandbox: Python({witness['pid']}) deny(1) file-write-data {fixture['unexpected_target']}",'tag':prepared['command_tag']}
                                    os.write(collector['write_fd'],(json.dumps(other)+'\n').encode())
                                    wait_host_record('collector-write-ack.jsonl',lambda r:r.get('frame_id')==other['frame_id'],deadline)
                            ack=None if silent else wait_host_record('collector-write-ack.jsonl',lambda r:r.get('frame_id')==frame['frame_id'],deadline)
                            os.close(collector['write_fd']);collector['write_fd']=None
                            log_audit({'type':'upstream_non_delivery' if silent else 'injected','case':fixture['case_id'],'frame':frame,
                                       'witness':witness,'host_identity':fields,'preflight_binding':binding,'at':time.time(),
                                       'leader_exited':check.poll() is not None,'boundary_ack':ack,'frame_id':frame['frame_id']})
                            if not is_drain:
                                # Let Node consume the event before the live
                                # candidate is released from its progress barrier.
                                publish_release(release,witness['nonce'])
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
                    pipe_stat=os.fstat(read_fd)
                    pipe_identity={'device':pipe_stat.st_dev,'inode':pipe_stat.st_ino}
                    env=dict(kwargs.get('env') or {})
                    env.update(KERNEL_TEST_COLLECTOR_FD=str(read_fd),
                               KERNEL_TEST_COLLECTOR_LIVE=str(fixture_root/('collector-live-'+str(time.time_ns())+'.raw')),
                               KERNEL_TEST_COLLECTOR_SUPPRESS='1')
                    kwargs['env']=env;kwargs['pass_fds']=(*kwargs.get('pass_fds',()),read_fd)
                    argv=[argv[0],'--import',fixture['adapter'],*argv[1:]]
                    try: proc=prior_popen(argv,*args,**kwargs)
                    finally: os.close(read_fd)
                    collector.update(write_fd=write_fd,supervisor=proc,config=cfg,check=None)
                    if fixture['case_id'] in ('COLLECTOR_SEAM_NEGATIVE_CONTROL','ABSENT_EVENT_PASSING_ENABLED','THIRD_PARTY_CANARY_MISS_NON_GATING'):
                        os.close(write_fd);collector['write_fd']=None
                    else:
                        threading.Thread(target=inject_when_ready,daemon=True).start()
                    log_audit({'type':'supervisor_preload','pid':proc.pid,'fd':read_fd,
                               'adapter':fixture['adapter'],'pipe_identity':pipe_identity})
                    return proc
            proc=prior_popen(argv,*args,**kwargs)
            if isinstance(kwargs.get('env'),dict) and kwargs['env'].get('VERIFY_PROCESS_TOKEN') and kwargs['env'].get('VERIFY_TREE')=='candidate':
                collector['check']=proc
            return proc
        subprocess.Popen=instrumented_popen
    subject = importlib.import_module('verify')
    if request.get('collector_fixture',{}).get('case_id')=='POSTFINAL_RELEVANT_DENIAL_INVALIDATES':
        runtime=importlib.import_module('kernel_sandbox_runtime')
        original_run_check=runtime.run_check
        def postfinal_run_check(root,check,phase,context):
            first=original_run_check(root,check,phase,context)
            if phase!='candidate': return first
            initial=json.loads(json.dumps(first['sandbox_receipt']))
            log_audit({'type':'postfinal_origin_sealed','identity':initial['identity'],
                'sha256':hashlib.sha256(json.dumps(initial,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'at':time.time()})
            if initial['decision']['verdict']!='supported':
                raise RuntimeError('postfinal origin was not initially supported')
            second=original_run_check(root,check,phase,context)
            (fixture_root/'postfinal-second-receipt.json').write_text(json.dumps(second,sort_keys=True))
            (fixture_root/'postfinal-original-receipt.json').write_text(json.dumps(initial,sort_keys=True))
            return first
        runtime.run_check=postfinal_run_check
    sys.argv = [str(package/'verify.py'), *sys.argv[4:]]
    sys.exit(subject.main())
