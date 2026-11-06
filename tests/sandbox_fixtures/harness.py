"""Frozen, effect-based sandbox qualification harness. No enforcement code.

A legacy subject receives the SAME opt-in environment and actually executes the
write probe. A successful forbidden write is a meaningful counterexample; missing
CLI/API/dependencies, invalid receipts and setup errors never become useful RED.
Only after that boundary gate holds can a future subject pass the full matrix.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DENIED = {1, 13}


class Unavailable(RuntimeError):
    pass


class Mismatch(AssertionError):
    pass


def need(condition, message):
    if not condition:
        raise Mismatch(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, cwd=None, env=None, timeout=45):
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        proc.communicate()
        raise Unavailable('fixture command timed out: ' + Path(argv[0]).name)
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


def git(repo, *args):
    result = run(['git', *args], cwd=repo)
    if result.returncode:
        raise Unavailable('fixture git failed: ' + result.stderr[-500:])
    return result.stdout.strip()


def inventory(paths):
    """Types, existence, bytes, modes, links, directory additions/deletions."""
    result = {}
    for root in map(Path, paths):
        names = [root]
        if root.is_dir() and not root.is_symlink():
            names += sorted(root.rglob('*'))
        for path in names:
            try:
                info = path.lstat()
            except FileNotFoundError:
                result[str(path)] = {'type':'absent'}
                continue
            row = {'mode':stat.S_IMODE(info.st_mode)}
            if stat.S_ISLNK(info.st_mode): row.update(type='link', target=os.readlink(path))
            elif stat.S_ISDIR(info.st_mode): row['type']='directory'
            elif stat.S_ISREG(info.st_mode): row.update(type='file', sha256=digest(path))
            else: raise Unavailable('unsupported fixture inventory object')
            result[str(path)] = row
    return result


def differences(before, after):
    return [{'kind':'protected_change','path':path,'before':before.get(path), 'after':after.get(path)}
            for path in sorted(set(before)|set(after)) if before.get(path)!=after.get(path)]


def copy_package(destination):
    destination.mkdir()
    raw = (ROOT/'MANIFEST.sha256').read_bytes()
    for line in raw.decode().splitlines():
        _, name = line.split('  ',1)
        if Path(name).is_absolute() or '..' in Path(name).parts:
            raise Unavailable('unsafe subject manifest')
        source, target = ROOT/name, destination/name
        if source.is_symlink(): raise Unavailable('symlink in subject package')
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,target)
    (destination/'MANIFEST.sha256').write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def parse_line(stdout, prefix):
    found = [line[len(prefix):] for line in stdout.splitlines() if line.startswith(prefix)]
    if not found: return None
    try: return json.loads(found[-1])
    except ValueError as error: raise Unavailable('invalid fixture operation output') from error


def alive(pid):
    result = run(['ps','-p',str(pid),'-o','stat='])
    return bool(result.stdout.strip()) and not result.stdout.strip().startswith('Z')


def cleanup_owned_checks(path):
    """Remediate only host-observed, same-start-time check groups after subject exit."""
    if not path.exists():
        raise Unavailable('host-owned check launch evidence unavailable')
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if not rows:
        raise Unavailable('host-owned check launch evidence empty')
    results = []
    for row in rows:
        pid = row.get('pid'); started = row.get('started')
        if type(pid) is not int or pid <= 1 or row.get('pgid') != pid:
            raise Unavailable('invalid host-owned check identity')
        def members():
            result = run(['/bin/ps','-axo','pid=,pgid=,stat='])
            if result.returncode: raise Unavailable('independent group observation failed')
            return [line for line in result.stdout.splitlines() if len(line.split()) >= 3 and
                    line.split()[1] == str(pid) and not line.split()[2].startswith('Z')]
        remaining = members(); remediated = False
        if remaining:
            info = run(['/bin/ps','-p',str(pid),'-o','pgid=,lstart='])
            fields = info.stdout.strip().split(None,1)
            if (info.returncode or len(fields) != 2 or not started or
                    fields[0] != str(pid) or fields[1] != started):
                raise Unavailable('live check group cannot be safely tied to host launch identity')
            try: os.killpg(pid,signal.SIGKILL)
            except ProcessLookupError: pass
            except OSError as error: raise Unavailable('independent check group remediation failed: '+str(error)) from error
            remediated = True
            deadline = time.monotonic() + 3
            while members() and time.monotonic() < deadline: time.sleep(.02)
        if members(): raise Unavailable('independent check group cleanup not verified')
        results.append({**row,'remediated':remediated,'verified_no_live_group':True})
    return results


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        data=self.request.recv(4096)
        self.server.received.append(hashlib.sha256(data).hexdigest())
        if data.startswith((b'GET ',b'CONNECT ')):
            self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
        else: self.request.sendall(data)


@contextmanager
def listener(ip='127.0.0.1'):
    class Server(socketserver.ThreadingTCPServer):
        address_family=socket.AF_INET6 if ':' in ip else socket.AF_INET
        daemon_threads=True
    try: server=Server((ip,0),Handler)
    except OSError as error: raise Unavailable('controlled listener unavailable: '+str(error)) from error
    server.received=[]
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try: yield server
    finally: server.shutdown();server.server_close();thread.join(timeout=3)


class Probe:
    def __init__(self, root, case, logging, bundle_receipt=None):
        self.root=root;root.mkdir()
        self.case=case;self.logging=logging;self.package=root/'judge_copy'
        self.release_digest=copy_package(self.package)
        self.repo=root/'repo';self.repo.mkdir()
        self.protected=root/'protected';self.protected.mkdir()
        self.bundle=root/'bundle_copy';self.bundle.mkdir()
        self.out=root/'operator-scratch';self.out.mkdir()
        self.logroot=root/'final-receipts';self.logroot.mkdir()
        self.log=self.logroot/'claim.jsonl';self.prefix=b'{"trusted_prefix":"frozen-fixture"}\n';self.log.write_bytes(self.prefix)
        self.secret=self.protected/'synthetic-ssh-key';self.secret.write_text('synthetic-'+uuid.uuid4().hex)
        self.dotenv=self.protected/'.env';self.dotenv.write_text('synthetic-'+uuid.uuid4().hex)
        self.target=self.protected/'target';self.target.write_text('before')
        for name in ['srt.js','supervisor.mjs','node']: (self.bundle/name).write_text('disposable protected sentinel, not a runtime')
        self.bundle_receipt=bundle_receipt
        self.payload_path=HERE/'payload.py'
        self.config={'fixture_root':str(root),'case_id':case['id'], 'operation':case['operation'],
                     'target':str(self.target),'report_path':'$SNAPSHOT/out/report','nonce':uuid.uuid4().hex}
        self.policy={'writable_paths':['out'],'localhost_ports':[]}
        self.fault=None
        self.links={}
        self.roles={'judge_copy/verify.py':self.package/'verify.py','claim_log':self.log,
                    'runtime_module':self.package/'kernel_runtime.py','manifest':self.package/'MANIFEST.sha256',
                    'contract':'$SNAPSHOT/contracts/task.toml','chain':'$SNAPSHOT/evidence/probe.py','fixture':'$SNAPSHOT/evidence/config.json',
                    'git_worktree_metadata':'$GIT_DIR/HEAD','git_common_directory':'$COMMON_GIT/HEAD',
                    'bundle_srt':self.bundle/'srt.js','bundle_supervisor':self.bundle/'supervisor.mjs',
                    'bundle_node':self.bundle/'node','protected_fixture_file':self.target,
                    'parent_owned_receipt':self.log,'snapshot_git_file':'$SNAPSHOT/.git'}

    def prepare(self, *, legacy_gate=False):
        for args in [('init','-b','main'),('config','user.email','kernel@example.test'),('config','user.name','Sandbox frozen fixture')]:git(self.repo,*args)
        (self.repo/'evidence').mkdir();(self.repo/'contracts').mkdir()
        (self.repo/'evidence/probe.py').write_bytes(self.payload_path.read_bytes())
        (self.repo/'evidence/config.json').write_text(json.dumps(self.config))
        (self.repo/'app.txt').write_text('old')
        (self.repo/'.gitignore').write_text('/out/\n'+''.join('/'+name+'\n' for name in self.links))
        if 'dependency' not in self.links:
            (self.repo/'dependency').mkdir();(self.repo/'dependency/library.txt').write_text('readonly dependency fixture')
        for name,target in self.links.items():
            (self.repo/name).symlink_to(target,target_is_directory=True)
        spec='''spec_version = 2
id = "sandbox-nested-probe"
project = "kernel-fixtures"
goal = "observe NEW and independently observed operation"
[scope]
include = ["app.txt"]
[[checks]]
name = "probe"
kind = "acceptance"
timeout = 3
argv = ["python3", "evidence/probe.py", "evidence/config.json"]
entry = "evidence/probe.py"
chain = ["evidence/probe.py", "evidence/config.json"]
evidence = ["evidence/probe.py", "evidence/config.json"]
assertions = ["NEW"]
baseline_failures = ["NEW"]
'''
        if self.links:spec=spec.replace('[scope]', '[worktree]\nlink = '+json.dumps(list(self.links))+'\n[scope]')
        if not legacy_gate:
            # This is the decision's proposed policy, only used AFTER the legacy
            # subject has supplied a concrete forbidden-write counterexample.
            spec+='\n[sandbox]\n'+self.policy_toml()
        (self.repo/'contracts/task.toml').write_text(spec)
        git(self.repo,'add','.');git(self.repo,'commit','-m','freeze reviewed operation fixture')
        self.base=git(self.repo,'rev-parse','HEAD')
        (self.repo/'app.txt').write_text('new');git(self.repo,'commit','-am','make NEW observable')

    def policy_toml(self):
        # JSON literals for arrays of strings/integers are valid TOML here.
        return '\n'.join(k+' = '+json.dumps(v) for k,v in self.policy.items())+'\n'

    def invoke(self):
        operator={'schema':1,'bundle_receipt':self.bundle_receipt,'diagnostics':{'mode':self.logging},
                  'additional_protected_paths':[str(self.package),str(self.bundle),str(self.protected),str(self.logroot)],
                  'secret_read_paths':[str(self.secret),str(self.dotenv)],
                  'scratch_root':str(self.out)}
        op_path=self.root/'operator.json';op_path.write_text(json.dumps(operator))
        env={**os.environ,'VERIFY_RELEASE_SHA256':self.release_digest,'PYTHONDONTWRITEBYTECODE':'1',
             'VERIFY_SANDBOX':'1','VERIFY_SANDBOX_OPERATOR':str(op_path)}
        request={'fault':self.fault,'fault_marker':str(self.root/'fault-applied')}
        if self.fault in ('supervisor_death','kill','ps_or_identity_observation'):
            request.update(owned_check_log=str(self.root/'owned-checks.jsonl'), scratch_root=str(self.out),
                           progress_marker=str(self.root/'fault-progress.json'),
                           barrier_nonce=self.config.get('supervisor_barrier_nonce') or self.config.get('fault_barrier_nonce'))
        if self.case['id']=='PATCH_AUTHENTICATION_FAILURE':
            request.update(audit_bundle_roots=[str(self.audit_bundle_root)],
                           bundle_launch_audit=str(self.root/'bundle-launch-audit.jsonl'))
        request_path=self.root/'driver.json';request_path.write_text(json.dumps(request))
        argv=[sys.executable,'-B',str(HERE/'subject_driver.py'),'verify',str(self.package),str(request_path),
              'contracts/task.toml','--repo','.', '--base',self.base,'--log',str(self.log)]
        before=inventory([self.package,self.bundle,self.protected])
        before.update(inventory([p for p in self.logroot.iterdir() if p!=self.log]))
        log_mode=stat.S_IMODE(self.log.lstat().st_mode)
        owned_cleanup=None
        try:
            result=run(argv,cwd=self.repo,env=env)
        finally:
            if self.fault in ('supervisor_death','kill','ps_or_identity_observation'):
                owned_cleanup=cleanup_owned_checks(self.root/'owned-checks.jsonl')
        if result.returncode not in (0,1,2,3):raise Unavailable('subject crashed: '+result.stderr[-700:])
        try:
            raw=self.log.read_bytes()
            record=json.loads(raw.splitlines()[-1]) if result.returncode!=3 else None
        except (OSError,ValueError):raise Unavailable('final subject receipt missing/invalid')
        check=(record.get('candidate_checks') or [{}])[0] if record else {}
        observation=parse_line(check.get('output',check.get('output_tail','')),'SANDBOX_OPERATION ')
        after=inventory([self.package,self.bundle,self.protected])
        after.update(inventory([p for p in self.logroot.iterdir() if p!=self.log]))
        if self.log.is_symlink() or stat.S_IMODE(self.log.lstat().st_mode)!=log_mode:
            after[str(self.log)]={'kind':'receipt-object-or-mode-changed'}
        return {'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr,
                'record':record,'check':check,'operation':observation,'before':before,'after':after,
                'changes':differences(before,after),'prefix_unchanged':raw[:len(self.prefix)]==self.prefix,
                'expected_base':self.base,'expected_head':git(self.repo,'rev-parse','HEAD'),
                'expected_release':self.release_digest,'expected_lock':digest(ROOT/'spike/package-lock.json'),
                'declared_ports':self.policy.get('localhost_ports',[]),
                'expected_bundle':json.loads(Path(self.bundle_receipt).read_text()) if self.bundle_receipt else None,
                'final_verdict_written':any('verdict' in json.loads(line) for line in raw.splitlines()),
                'bundle_code_launched':(self.root/'bundle-launch-audit.jsonl').exists(),
                'fault_applied':(self.root/'fault-applied').exists(),
                'fault_evidence':(self.root/'fault-applied').read_text() if (self.root/'fault-applied').exists() else None,
                'progress_evidence':(self.root/'fault-progress.json').read_text() if (self.root/'fault-progress.json').exists() else None,
                'owned_cleanup':owned_cleanup}


def denied_probe(observed, case):
    op=observed['operation']
    if not op: raise Unavailable(case['id']+': no independent operation report; unverifiable alone cannot prove denial')
    need(op.get('attempted') is True,case['id']+': operation never attempted')
    need(op.get('errno') in DENIED,case['id']+': forbidden operation succeeded or failed for another reason: '+json.dumps(op))
    need(not observed['changes'],case['id']+': protected fixture changed despite claimed refusal')
    need(observed['prefix_unchanged'],case['id']+': final receipt prefix altered')


def receipt_check(observed, case, logging, *, require_enforced=True):
    expected=case['expected']
    if expected=='refused':
        need(observed['exit']==3 and observed['record'] is None,case['id']+': must refuse before verdict')
        return
    record=observed['record']
    if not record or 'verdict' not in record: raise Unavailable('no complete nested verdict')
    if expected == 'supported' and record.get('verdict') == 'unverifiable':
        for check in record.get('base_checks', []) + record.get('candidate_checks', []):
            diagnostics = check.get('sandbox_receipt', {}).get('diagnostics', {})
            canary = diagnostics.get('canary', {})
            if (diagnostics.get('mode') == 'enabled' and
                    canary.get('write_denied') is True and
                    canary.get('scratch_succeeded') is True and
                    canary.get('event_received') is False):
                raise Unavailable(case['id']+': enabled diagnostic canary positive control unavailable')
    need(record['verdict']==expected,case['id']+': expected '+expected+', got '+record['verdict'])
    need(record.get('merge_base')==observed['expected_base'] and record.get('head')==observed['expected_head'],'receipt not bound to committed fixture inputs')
    receipt=observed['check'].get('sandbox_receipt') or record.get('sandbox_receipt')
    if not isinstance(receipt,dict): raise Unavailable(case['id']+': sandbox receipt unavailable')
    for key in ['schema','identity','release','bundle','platform','policy','lifecycle','integrity','diagnostics','decision','assurance']:
        if key not in receipt: raise Unavailable(case['id']+': missing sandbox receipt '+key)
    need(receipt['schema']==2,'unknown sandbox receipt schema')
    identity=receipt['identity']
    for key in ['run_id','check','phase','repetition']:
        if key not in identity:raise Unavailable('incomplete invocation identity '+key)
    need(identity['check']=='probe' and identity['phase'] in ('base','candidate'),'wrong sandbox receipt check/phase')
    operation=observed['operation']
    if operation and operation.get('attempted'):
        need(identity['run_id']==operation.get('run_id') and identity['phase']==operation.get('phase'),'receipt crossed invocation boundaries')
    for key in ['system','release','machine','python','git','ps']:
        if not receipt['platform'].get(key):raise Unavailable('unqualified platform/runtime identity '+key)
    for key in ['writable_roots','localhost_endpoints','secret_read_paths','protected_inventory_digest','policy_digest','backend','scratch_root','internal_ipc','exceptions','network_semantics','effective_network_rules','profile_sha256','profile_validation']:
        if key not in receipt['policy']:raise Unavailable('incomplete policy receipt '+key)
    for key in ['available','before','after','changes','judge_before','judge_after','receipt_prefix_sha256']:
        if key not in receipt['integrity']:raise Unavailable('incomplete integrity observation '+key)
    for key in ['mode','state','received','persisted','dropped','spool_capacity','drain_deadline','upstream_completeness','raw_events_sha256']:
        if key not in receipt['diagnostics']:raise Unavailable('incomplete diagnostic quality '+key)
    need(receipt['diagnostics']['upstream_completeness']=='unknown','OS log completeness invented')
    for key in ['facts','unavailable_reasons','contradictions','verdict']:
        if key not in receipt['decision']:raise Unavailable('incomplete decision evidence '+key)
    need(receipt['decision']['verdict']==record['verdict'],'inner sandbox decision disagrees with aggregate')

    need(receipt['release'].get('manifest_sha256')==observed['expected_release'],'sandbox receipt not bound to caller-held package digest')
    if require_enforced:need(receipt.get('enforced') is True,'requested sandbox was not enforced')
    need(receipt['diagnostics'].get('mode')==logging,'logging request silently changed')
    if logging=='disabled':
        need(receipt['diagnostics'].get('state')=='disabled','disabled mode not explicit')
        need(not receipt['diagnostics'].get('collector_ready') and not receipt['diagnostics'].get('complete'),'invented collector completeness/readiness')
    lifecycle=receipt['lifecycle']
    if lifecycle.get('launched'):
        for key in ['started_at','exited_at','cleanup_finished_at','finalized_at']:
            if key not in lifecycle:raise Unavailable('incomplete lifecycle timestamps')
        need(lifecycle['started_at']<=lifecycle['exited_at']<=lifecycle['cleanup_finished_at']<=lifecycle['finalized_at'],'receipt finalized before cleanup')
    for prohibited in ['all_attempts_detected','transient_writes_detected','complete_logs','semantic_attestation','exhaustive_descendant_containment','loopback_only_binding','literal_address_only']:
        need(receipt['assurance'].get(prohibited) is False,'unsupported assurance claim: '+prohibited)
    if require_enforced:
        need(receipt['bundle'].get('srt_version')=='0.0.81' and receipt['bundle'].get('node_version')=='v24.22.0','unqualified sandbox/Node version')
        need(receipt['bundle'].get('lock_sha256')==observed['expected_lock'],'transitive dependency lock not pinned')
    need(bool(receipt['bundle'].get('node_artifact_sha256')) and bool(receipt['bundle'].get('lock_sha256')),'unbound execution dependencies')
    expected_bundle=observed.get('expected_bundle')
    if not isinstance(expected_bundle,dict):raise Unavailable('authenticated patch/bundle identity unavailable')
    for key in ['patch_id','patch_sha256','patch_preimages','patch_postimages','bundle_digest']:
        if key not in expected_bundle:raise Unavailable('operator receipt missing '+key)
        need(receipt['bundle'].get(key)==expected_bundle[key],'check receipt patch/bundle binding differs: '+key)
    need(receipt['bundle']['patch_id']=='kernel-srt-0.0.81-exact-tcp-v1','unreviewed srt patch revision')
    for key in ['patch_sha256','bundle_digest']:
        need(is_sha256(receipt['bundle'][key]),'invalid patch/bundle digest: '+key)
    for key in ['patch_preimages','patch_postimages']:
        entries=receipt['bundle'][key]
        need(isinstance(entries,list) and bool(entries),'missing patch file identities: '+key)
        need(all(isinstance(row,dict) and set(row)=={'path','sha256'} and
                 isinstance(row['path'],str) and row['path'] and
                 not Path(row['path']).is_absolute() and '..' not in Path(row['path']).parts and
                 is_sha256(row['sha256']) for row in entries),'invalid patch manifest: '+key)
        need(len({row['path'] for row in entries})==len(entries),'duplicate patch manifest paths')
    need({row['path'] for row in receipt['bundle']['patch_preimages']}==
         {row['path'] for row in receipt['bundle']['patch_postimages']},'patch pre/post file sets differ')
    if require_enforced and lifecycle.get('launched'):
        network_receipt_check(receipt,observed['declared_ports'])
    return receipt


def is_sha256(value):
    return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)


def network_receipt_check(receipt, ports, *, exact_match=True):
    """Compare declared destinations AND complete versioned effective IP grants.

    This tests receipt evidence, not a product profile parser or enforcement.
    Production must independently inspect complete generated profile bytes.
    """
    policy=receipt['policy']
    need(policy['network_semantics']=='srt-0.0.81-exact-tcp-v1','wrong network semantics')
    endpoints=policy['localhost_endpoints']
    need(isinstance(endpoints,list),'declared endpoints unavailable')
    expected=[{'host':host,'port':port,'transport':'tcp'} for port in sorted(ports) for host in ('127.0.0.1','::1')]
    canonical=lambda rows:sorted(json.dumps(row,sort_keys=True) for row in rows)
    need(canonical(endpoints)==canonical(expected),'canonical declared destinations differ from contract')
    ipc=policy['internal_ipc']
    need(isinstance(ipc,dict) and set(ipc)=={'proxies','non_ip_rules'},'unaccounted internal IPC')
    proxies=ipc['proxies'];need(isinstance(proxies,list),'proxy identities unavailable')
    for proxy in proxies:
        need(isinstance(proxy,dict) and set(proxy)=={'role','host','port','transport','pid','started','ready','ownership_verified'},'incomplete trusted proxy identity')
        need(proxy['role'] in ('http','socks') and proxy['host'] in ('127.0.0.1','::1') and proxy['transport']=='tcp','unreviewed proxy endpoint')
        need(type(proxy['port']) is int and 1<=proxy['port']<=65535 and proxy['port'] not in ports,'proxy port overlaps application grant')
        need(type(proxy['pid']) is int and proxy['pid']>0 and bool(proxy['started']) and proxy['ready'] is True and proxy['ownership_verified'] is True,'proxy ownership/readiness not established')
    need(len({proxy['role'] for proxy in proxies})==len(proxies),'duplicate proxy role')
    need(ipc['non_ip_rules']==[{'operation':'system-socket','socket_domain':'AF_SYSTEM','socket_protocol':2}],'unreviewed non-IP authority')
    rules=[]
    for port in sorted(ports):
        rules.extend([{'operation':operation,'selector':'local','transport':'tcp','host':'*','port':port}
                      for operation in ('network-bind','network-inbound')])
        rules.append({'operation':'network-outbound','selector':'remote','transport':'tcp','host':'localhost','port':port})
    rules.extend({'operation':'network-outbound','selector':'remote','transport':'tcp','host':'localhost','port':port}
                 for port in sorted({proxy['port'] for proxy in proxies}))
    need(isinstance(policy['effective_network_rules'],list) and canonical(policy['effective_network_rules'])==canonical(rules),'effective IP grants differ from exact application/proxy rules')
    # Exact list comparison preserves multiplicity: omissions/duplicates cannot hide.
    if not ports:need(not any(row['operation'] in ('network-bind','network-inbound') for row in policy['effective_network_rules']),'empty declaration grants application bind/inbound')
    profile_evidence_check(policy,exact_match)
    exceptions=policy['exceptions']
    need(isinstance(exceptions,list) and all(isinstance(row,dict) for row in exceptions),'network residual limits missing')
    limits={row.get('id'):row for row in exceptions}
    for name in ('address_wildcard_declared_tcp_binding','localhost_address_class_aliases','mapped_outbound_qualification'):
        need(name in limits,'missing network exception: '+name)
    binding=limits['address_wildcard_declared_tcp_binding']
    need(binding.get('ports')==sorted(ports) and binding.get('nonloopback_inbound_exposure') is bool(ports),'wildcard bind/inbound exposure not disclosed')
    need(binding.get('accepted_connection_data_exchange') is bool(ports),'accepted-connection data exposure not disclosed')
    need(limits['localhost_address_class_aliases'].get('literal_spelling_enforced') is False,'literal alias matching overclaimed')
    mapped=limits['mapped_outbound_qualification']
    need(mapped.get('status') in ('supported','unavailable') and mapped.get('universal_compatibility') is False,'mapped qualification missing or generalized')
    need(mapped.get('platform')=={key:receipt['platform'][key] for key in ('system','release','machine')},'mapped qualification not bound to this platform')
    need(isinstance(mapped.get('os_build'),str) and bool(mapped['os_build']),'mapped qualification lacks exact OS build')
    need(mapped.get('node_version')==receipt['bundle']['node_version'] and mapped.get('node_artifact_sha256')==receipt['bundle']['node_artifact_sha256'],'mapped qualification not bound to this Node artifact')
    for name in limits:
        need(isinstance(limits[name].get('detail'),str) and bool(limits[name]['detail']),'exception limit lacks explanation')


def profile_evidence_check(policy,exact_match):
    validation=policy['profile_validation']
    need(isinstance(validation,dict) and validation.get('validator_id')=='kernel-srt-profile-validator-v1','profile validator identity unavailable')
    need(validation.get('exact_match') is exact_match,'unexpected exact-profile validation result')
    profile=validation.get('inspected_profile')
    need(isinstance(profile,str) and bool(profile),'complete inspected profile bytes not retained')
    need(is_sha256(policy['profile_sha256']) and hashlib.sha256(profile.encode()).hexdigest()==policy['profile_sha256'],'inspected profile hash mismatch')
    if not exact_match:need(isinstance(validation.get('errors'),list) and bool(validation['errors']),'precise profile inspection failure absent')


def configure_file(probe, case):
    params=case.get('params',{});op=case['operation']
    role=params.get('target','protected_fixture_file')
    target=probe.roles.get(role,probe.target)
    if params.get('cache_location')=='per-check_scratch' or op=='scratch_write':target='$SNAPSHOT/out/cache-file'
    elif params.get('cache_location')=='external_dependency':
        dep=probe.protected/'external-dependency';dep.mkdir();(dep/'library.txt').write_text('synthetic dependency')
        probe.links['dependency']=dep;target='$SNAPSHOT/dependency/cache-file'
    elif params.get('cache_location')=='judge_fixture':target=probe.package/'synthetic-cache.pyc'
    elif params.get('cache_location'):target='$SNAPSHOT/source-cache-file'
    if case['operation']=='read' and not params.get('secret_fixture'):
        params={**params,'secret_fixture':'synthetic_ssh_key','path_form':'hardlink_alias' if params.get('alias')=='hardlink_to_protected' else 'absolute_fixture_path'}
    if params.get('secret_fixture'):
        secret=probe.secret if params['secret_fixture']=='synthetic_ssh_key' else probe.dotenv
        target=secret;probe.config['expected_sha256']=digest(secret)
        form=params.get('path_form','')
        alias=probe.root/'secret-alias'
        if form=='symlink_alias':alias.symlink_to(secret);target=alias
        elif form=='ancestor_alias':alias.symlink_to(secret.parent,target_is_directory=True);target=alias/secret.name
        elif form=='hardlink_alias':os.link(secret,alias);target=alias
    probe.config['target']=str(target)
    if params.get('defaults'):probe.config['report_path']='$TMP/report'
    if params.get('swallow_denial'):probe.config['swallow_denial']=True
    if params.get('expected_denial'):probe.config['expected_denial']=True
    if op=='chmod':probe.config['mode']=0o700
    if op=='create':
        # A fresh file below the protected parent, not EEXIST on an old file.
        if isinstance(target,Path):target=target.parent/'new-forbidden-file'
        else:target=target.rsplit('/',1)[0]+'/new-forbidden-file'
        probe.config['target']=str(target)
    if op in ('rename','replace_parent'):
        source=str(target)
        if op=='replace_parent':source=source.rsplit('/',1)[0]
        probe.config.update(source=source,destination=str(probe.root/'renamed-protected-object'))
    if op in ('symlink_write','hardlink_write','ancestor_alias_write'):
        probe.config['alias']='$SNAPSHOT/out/alias'
        if op=='ancestor_alias_write':
            probe.config.update(target=str(probe.target.parent),child=probe.target.name)
    if params.get('alias')=='tmp_vs_private_tmp':
        path=str(probe.target)
        alias=path.removeprefix('/private') if path.startswith('/private/') else '/private'+path
        if not Path(alias).exists() or not os.path.samefile(alias,probe.target):
            raise Unavailable('this platform lacks the /private path alias fixture')
        probe.config.update(operation='write',target=alias)
    elif params.get('alias')=='case_insensitive_path':
        alias=probe.target.with_name(probe.target.name.upper())
        if not alias.exists() or not os.path.samefile(alias,probe.target):
            raise Unavailable('case-alias fixture requires a case-insensitive qualified filesystem')
        probe.config.update(operation='write',target=str(alias))
    if case['layer']=='protocol' and params.get('variant'):
        probe.config['result_variant']=params.get('variant')
        # Preserve the chosen variant; the payload's generic malformed operation
        # would otherwise override it with malformed JSON.
        if params.get('variant') not in ('malformed_result','stale_result','missing_result','result_absent'):
            probe.config['operation']='clean'
        if params.get('variant')=='result_absent':probe.config['operation']='missing_result'
    if params.get('failure'):
        probe.fault=params['failure']
        probe.config.update(fault_barrier_nonce=uuid.uuid4().hex,
                            fault_barrier_handshake='$TMP/fault-handshake.json',
                            fault_barrier_release='$TMP/fault-release.json')
    if case['id']=='SUPERVISOR_DEATH':
        probe.fault='supervisor_death'
        probe.config.update(supervisor_barrier_nonce=uuid.uuid4().hex,
                            supervisor_barrier_handshake='$TMP/supervisor-handshake.json',
                            supervisor_barrier_release='$TMP/supervisor-release.json')


def direct_control(probe):
    """Unsandboxed reachable/effect control, entirely disposable, same payload."""
    probe.prepare(legacy_gate=True)
    env={**os.environ,'VERIFY_ROOT':str(probe.repo),'VERIFY_TREE':'candidate',
         'VERIFY_RUN_ID':uuid.uuid4().hex,'VERIFY_RESULT_JSON':str(probe.out/'result.json'),
         'PYTHONDONTWRITEBYTECODE':'1'}
    cwd=probe.repo
    if probe.config.get('target')=='$SNAPSHOT/.git':
        cwd=probe.root/'control-worktree'
        git(probe.repo,'worktree','add','--detach',str(cwd),'HEAD')
        env['VERIFY_ROOT']=str(cwd)
    (cwd/'out').mkdir()
    result=run([sys.executable,'-B',str(cwd/'evidence/probe.py'),'evidence/config.json'],cwd=cwd,env=env)
    observation=parse_line(result.stdout,'SANDBOX_OPERATION ')
    if result.returncode!=0 or not observation or observation.get('outcome')!='succeeded':
        raise Unavailable('unsandboxed operation control unavailable: '+result.stderr[-400:]+' '+str(observation))
    return observation


def effect_case(top, case, mode, bundle):
    if case.get('params',{}).get('alias') == 'tmp_vs_private_tmp':
        if not Path('/tmp').is_symlink() or not Path('/private/tmp').is_dir() or not os.path.samefile('/tmp','/private/tmp'):
            raise Unavailable('literal /tmp to /private/tmp alias unavailable')
        with tempfile.TemporaryDirectory(prefix='kernel-alias-',dir='/tmp') as temporary:
            real = Path(temporary).resolve(strict=True)
            if not real.is_relative_to(Path('/private/tmp').resolve()):
                raise Unavailable('literal /tmp fixture does not resolve under /private/tmp')
            row = _effect_case(real, case, mode, bundle)
            row['alias_evidence']={'requested_root':temporary,'resolved_root':str(real),
                                   'tmp_is_symlink':True,'samefile':True}
            return row
    return _effect_case(top, case, mode, bundle)


def _effect_case(top, case, mode, bundle):
    # Controls use a separate tree because a successful control may delete or
    # rename a disposable verifier or its parent. It never damages the subject.
    if case['layer']=='effect' and case['operation'] not in ('clean','environment_probe'):
        control=Probe(top/'control',case,mode,bundle);configure_file(control,case);direct_control(control)
    probe=Probe(top/'subject',case,mode,bundle);configure_file(probe,case)
    probe.prepare(legacy_gate=case.get('params',{}).get('defaults',False));observed=probe.invoke()
    if case['expected']=='unverifiable' and (case['layer']=='effect' or case['id']=='FINAL_RECEIPT_FORGERY'):
        denied_probe(observed,case)
    elif case['expected']=='supported' and case['layer']=='effect':
        op=observed['operation']
        if case.get('params',{}).get('expected_denial'):
            denied_probe(observed,case)
        elif case['operation']!='clean' and not case.get('params',{}).get('swallow_denial'):
            need(op is not None and op.get('outcome')=='succeeded','allowed output did not succeed')
        need(not observed['changes'] and observed['prefix_unchanged'],'clean control changed protected state')
    receipt=receipt_check(observed,case,mode)
    if case['operation']=='environment_probe':
        environment=observed['operation'].get('environment',{});scratch=Path(receipt['policy']['scratch_root']).resolve()
        for name in ('HOME','TMPDIR','XDG_CACHE_HOME'):
            value=Path(environment[name]).resolve();need(value==scratch or scratch in value.parents,'environment points outside fresh per-check scratch: '+name)
        need(environment.get('PYTHONDONTWRITEBYTECODE')=='1','Python caches not disabled')
    return {'id':case['id'],'mode':mode,'verdict':observed['record']['verdict'],
            'operation':observed['operation'],'protected_changes':observed['changes'],
            'receipt_identity':receipt['identity']}


def classifier_case(top,case,mode,package):
    top.mkdir();target=top/'measured-target';target.write_text('before');target.chmod(0o644)
    params=case.get('params',{});source=params.get('facts',{})
    before=inventory([target]);change=source.get('protected_change')=='reliable'
    if change:
        shape=source.get('change_kind','bytes')
        if shape=='addition':(top/'added').write_text('after')
        elif shape=='removal':target.unlink()
        elif shape=='replacement':target.unlink();target.symlink_to('synthetic-replacement')
        elif shape=='mode_change':target.chmod(0o600)
        else:target.write_text('lasting change')
    after=inventory([target]+([top/'added'] if (top/'added').exists() else []))
    changes=differences(before,after)
    unavailable=source.get('evidence_incomplete')
    facts={'schema':1,'integrity':{'available':source.get('inventory')!='unavailable',
                                  'before':before,'after':after,'changes':changes},
           'execution':{'complete':not((source.get('evidence_complete') is False and not source.get('collector_fault')) or source.get('incomplete_evidence')),
                        'unavailable_reason':unavailable},
           'cleanup':{'complete':unavailable not in ('survivor','timeout'),'survivors':[]},
           'assertions':{'complete':unavailable!='missing_result','failed':[]},
           'diagnostics':{'mode':mode,'state':'disabled' if mode=='disabled' else 'active',
                          'upstream_completeness':'unknown','emitted':0,'persisted':0,'dropped':0,
                          'collector_ready':False,'complete':False}}
    if source.get('judge_cache_created'):
        judge_cache=top/'judge-cache.pyc';judge_cache.write_text('synthetic host cache')
        facts['judge_integrity']={'available':True,'unchanged':False,'origin':'judge','changes':[{'kind':'judge_environment_change','path':str(judge_cache),'after':digest(judge_cache)}]}
    if unavailable=='hash_unavailable':facts['integrity']['additional_inventory_available']=False
    if unavailable=='survivor':facts['cleanup']['survivors']=[{'pid':12345,'pgid':12345,'started':'synthetic-identity','reason':'injected escaped survivor'}]
    if unavailable=='timeout':facts['execution']['timed_out']=True
    if unavailable=='collector_loss':facts['diagnostics'].update(mode='enabled',dropped=1)
    if 'emitted' in source:
        # Actually generate and persist >100 distinct fixture events. This is a
        # deterministic classifier/spool-input fixture, NOT OS log completeness.
        events=[{'run_id':'fixture-run','seq':i} for i in range(source['emitted'])]
        path=top/'events.jsonl';path.write_text(''.join(json.dumps(e)+'\n' for e in events))
        facts['diagnostics'].update(emitted=len(events),persisted=len(path.read_text().splitlines()),dropped=source['dropped'],store_tail_capacity=100)
    if source.get('collector_fault'):
        fault=source['collector_fault'];facts['diagnostics']['state']='failed'
        if fault=='suppress_canary_event':facts['diagnostics']['canary']={'write_denied':True,'scratch_succeeded':True,'event_received':False}
        if fault in ('drop_subscription_event','overflow_spool'):
            events=[{'run_id':'fixture-run','seq':i} for i in range(150)]
            retained=events[:4] if fault=='overflow_spool' else events[:-1]
            spool=top/'fault-spool.jsonl';spool.write_text(''.join(json.dumps(e)+'\n' for e in retained))
            facts['diagnostics'].update(emitted=len(events),persisted=len(spool.read_text().splitlines()),dropped=len(events)-len(retained),spool_overflow=fault=='overflow_spool')
    for key in ['collector_fault','drain_timed_out','pending_event','delayed_event','drained_before_deadline','attribution','late_event']:
        if key in source:facts['diagnostics'][key]=source[key]
    # Invisible attempts are deliberately not supplied as facts: the classifier
    # sees exactly the same complete, clean observation as the clean control.
    req=top/'facts.json';req.write_text(json.dumps(facts))
    result=run([sys.executable,'-B',str(HERE/'subject_driver.py'),'classify',str(package),str(req)],
               env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    if result.returncode:raise Unavailable('subject classifier API unavailable: '+result.stderr[-600:])
    classified=parse_line(result.stdout,'SANDBOX_CLASSIFICATION ')
    if not isinstance(classified,dict):raise Unavailable('classifier did not return a structured result')
    need(classified.get('verdict')==case['expected'],case['id']+': wrong evidence classification')
    if changes and facts['integrity']['available']:
        need(all(change in classified.get('facts',[]) for change in changes),'deterministic change facts discarded under precedence')
    if source.get('judge_cache_created'):
        need(all(change in classified.get('facts',[]) for change in facts['judge_integrity']['changes']),'judge-side cache attribution lost')
    if not changes:need(not any(f.get('kind')=='protected_change' for f in classified.get('facts',[])),'hash/read failure invented tampering')
    if facts['diagnostics']['mode']=='disabled':
        need(not classified.get('collector_ready') and not classified.get('logs_complete'),'disabled logs claimed ready/complete')
    return {'id':case['id'],'mode':mode,'facts':facts,'classification':classified}


@contextmanager
def proxy_for(destination):
    """Fixed-destination loopback proxy control; never a general open proxy."""
    host,port=destination
    class Proxy(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            data=b''
            while b'\r\n\r\n' not in data and len(data)<8192:
                block=self.request.recv(1024)
                if not block:return
                data+=block
            if data.startswith(b'CONNECT '):
                with socket.create_connection((host,port),timeout=3) as upstream:
                    self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                    body=self.request.recv(4096);upstream.sendall(body);self.request.sendall(upstream.recv(4096))
            else:
                with socket.create_connection((host,port),timeout=3) as upstream:
                    upstream.sendall(data);self.request.sendall(upstream.recv(4096))
    with socketserver.ThreadingTCPServer(('127.0.0.1',0),Proxy) as server:
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:yield server.server_address[:2]
        finally:server.shutdown();server.server_close();thread.join(timeout=3)


def network_case(top,case,mode,bundle):
    params=case.get('params',{});v6='V6' in case['id'];ip='::1' if v6 else '127.0.0.1'
    with listener(ip) as server:
        port=server.server_address[1]
        probe=Probe(top/'subject',case,mode,bundle)
        address=ip
        if 'ALTERNATE_LOOPBACK' in case['id']:address='127.0.0.2'
        if 'NONLOOPBACK_BIND' in case['id']:address='::' if v6 else '0.0.0.0'
        # Bind controls need a free (not listening) port; exact-port permission
        # still names that port, never localhost:*.
        if case['operation']=='bind':
            with socket.socket(socket.AF_INET6 if v6 else socket.AF_INET) as s:
                s.bind((ip,0));port=s.getsockname()[1]
        declared=case['expected']=='supported' or 'DECLARED_TCP' in case['id']
        probe.policy['localhost_ports']=[port] if declared else []
        if case['id']=='NETWORK_WRONG_PORT':
            probe.policy['localhost_ports']=[port+1 if port<65535 else port-1]
        probe.config.update(address=address,port=port,expect_ack=case['operation'] in ('connect','proxy_connect'),expected_ack=probe.config['nonce'])
        # Verify reachable positive control before asserting a blocked route.
        # 127.0.0.2 requires its own controlled listener, never infer denial from
        # ECONNREFUSED against a listener bound only to 127.0.0.1.
        if 'ALTERNATE_LOOPBACK' in case['id']:
            with listener('127.0.0.2') as alternate:
                probe.config['port']=alternate.server_address[1]
                return connected_probe(top,case,probe,alternate,mode)
        if case['operation'] in ('proxy_http','proxy_connect'):
            with proxy_for((ip,port)) as proxy:
                return connected_probe(top,case,probe,server,mode,proxy)
        return connected_probe(top,case,probe,server,mode)


def connected_probe(top,case,probe,server,mode,proxy=None):
    control=Probe(top/'control',case,mode,probe.bundle_receipt)
    control.config.update({k:v for k,v in probe.config.items() if k not in ('fixture_root','target','report_path')})
    # ACK nonce is a synthetic fixture value, not a secret.
    if proxy:control.config.update(proxy_address=proxy[0],proxy_port=proxy[1])
    if case['operation']=='udp':
        # A separate UDP receiver independently observes the reachable positive
        # control; declared TCP ports must never grant UDP.
        family=socket.AF_INET6 if ':' in probe.config['address'] else socket.AF_INET
        with socket.socket(family,socket.SOCK_DGRAM) as udp:
            udp.bind((probe.config['address'],0));udp.settimeout(2)
            control.config['port']=probe.config['port']=udp.getsockname()[1]
            if 'DECLARED_TCP' in case['id']:probe.policy['localhost_ports']=[probe.config['port']]
            direct_control(control)
            packet,_=udp.recvfrom(4096)
            need(bool(packet),'UDP positive control not reached')
            probe.prepare();observed=probe.invoke()
            try:packet,_=udp.recvfrom(4096);arrived=True
            except socket.timeout:arrived=False
            need(not arrived,'denied UDP reached controlled receiver')
    else:
        control_report=direct_control(control)
        if case['operation']=='connect':need(control_report.get('ack_matches') is True,'direct reachable control missing ACK')
        if case['operation'].startswith('proxy_'):need(control_report.get('proxy_status')==200,'proxy positive control unavailable')
        server.received.clear()
        probe.prepare();observed=probe.invoke()
        if case['expected']!='supported':need(not server.received,'forbidden route reached listener')
        elif case['operation']!='bind':need(bool(server.received),'allowed route never reached listener')
        if case['expected']=='supported':
            op=observed['operation']
            if not op:raise Unavailable('allowed operation report missing')
            if case['operation']=='connect':need(op.get('ack_matches') is True,'allowed socket did not exchange nonce with controlled endpoint')
            elif case['operation']=='proxy_connect':need(op.get('tunnel_ack_matches') is True,'CONNECT tunnel did not reach its controlled endpoint')
            elif case['operation']=='proxy_http':need(op.get('proxy_status')==200,'declared proxy route failed')
            elif case['operation']=='bind':need(op.get('bound_address')==probe.config['address'] and op.get('bound_port')==probe.config['port'],'binding control identity missing')
    if case['expected']=='unverifiable':
        op=observed['operation']
        if not op:raise Unavailable('network operation evidence missing')
        need(op.get('errno') in DENIED or op.get('proxy_status')==403,'network failed for unrelated reason, not policy denial')
    receipt=receipt_check(observed,case,mode)
    # Canonical destinations are declarations, not the full effective authority.
    # Compare all application AND outbound-only proxy grants with multiplicity.
    network_receipt_check(receipt,probe.policy['localhost_ports'])
    return {'id':case['id'],'mode':mode,'operation':observed['operation'],'listener_received':list(server.received),'verdict':observed['record']['verdict']}


def invalid_policy_case(top,case,mode,bundle):
    probe=Probe(top/'subject',case,mode,bundle);variant=case.get('params',{}).get('invalid_declaration',case['id'])
    grants={'absolute_path':['/tmp'],'parent_component':['../outside'],'wildcard_path':['out/*'],
            'tracked_file_overlap':['app.txt'],'dependency_overlap':['dependency'],
            'protected_ancestor':['evidence'],'symlink_alias_to_protected':['alias-output'],
            'unsafe_grant':['.']}
    ports={'duplicate_port':[12345,12345],'port_zero':[0],'port_65536':[65536],
           'port_string':['12345'],'port_wildcard':['*']}
    if variant in grants:probe.policy['writable_paths']=grants[variant]
    elif variant in ports:probe.policy['localhost_ports']=ports[variant]
    elif variant=='raw_srt_or_network_flags':probe.policy['allowAllUnixSockets']=True
    else:raise Unavailable('unmapped invalid-policy fixture '+variant)
    if variant=='symlink_alias_to_protected':probe.links['alias-output']=probe.protected
    if variant=='dependency_overlap':
        dep=probe.protected/'external-dependency';dep.mkdir();(dep/'library.txt').write_text('synthetic dependency')
        probe.links['dependency']=dep
    probe.prepare()
    observed=probe.invoke();receipt_check(observed,case,mode,require_enforced=False)
    need(observed['operation'] is None,'invalid declaration executed candidate payload')
    return {'id':case['id'],'mode':mode,'exit':observed['exit'],'launched':False}


def dependency_case(top,case,mode,bundle):
    probe=Probe(top/'subject',case,mode,bundle);params=case.get('params',{})
    if not bundle:raise Unavailable('qualified external bundle receipt required for dependency qualification')
    original=json.loads(Path(bundle).read_text())
    bundle_root=Path(original['bundle_root']).resolve(strict=True)
    # Copy only authenticated, inventoried regular files into a disposable
    # dependency fixture. No write ever targets the real qualified bundle.
    shadow=top/'qualified-bundle-copy';shadow.mkdir()
    for row in original['files']:
        relative=Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts:raise Unavailable('unsafe bundle qualification manifest')
        source=bundle_root/relative;dest=shadow/relative
        if source.is_symlink() or digest(source)!=row['sha256']:raise Unavailable('operator bundle copy authentication failed')
        dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest);dest.chmod(row.get('mode',0o644))
    copy_receipt={**original,'bundle_root':str(shadow)}
    variant=case['id']
    if variant in ('BUNDLE_DIGEST_MISMATCH','NODE_DIGEST_MISMATCH'):
        relative=original['node']['executable'] if variant.startswith('NODE_') else original['files'][0]['path']
        with (shadow/relative).open('ab') as file:file.write(b'\naltered disposable bundle\n')
    elif variant=='PATCH_AUTHENTICATION_FAILURE':
        relative=Path(original.get('patch_file',''))
        if not relative.parts or relative.is_absolute() or '..' in relative.parts:
            raise Unavailable('authenticated patch-file identity unavailable')
        if str(relative) not in {row['path'] for row in original['files']}:
            raise Unavailable('patch file is not covered by authenticated bundle inventory')
        with (shadow/relative).open('ab') as file:file.write(b'\naltered disposable patch bytes\n')
        probe.audit_bundle_root=shadow
    elif variant=='MISSING_NODE':probe.fault='missing_node'
    elif variant=='WRONG_NODE_VERSION':probe.fault='wrong_node_version'
    elif variant=='MISSING_SANDBOX_FACILITY':probe.fault='missing_facility'
    elif variant=='WRITABLE_BUNDLE':shadow.chmod(0o777)
    elif variant=='UNSUPPORTED_EXACT_PORT_POLICY':probe.fault='unsupported_policy';probe.policy['localhost_ports']=[12345]
    else:raise Unavailable('unmapped dependency fixture')
    path=top/'bundle-receipt.json';path.write_text(json.dumps(copy_receipt));probe.bundle_receipt=str(path) if variant in ('WRITABLE_BUNDLE','NODE_DIGEST_MISMATCH','BUNDLE_DIGEST_MISMATCH','PATCH_AUTHENTICATION_FAILURE') else bundle
    probe.prepare();observed=probe.invoke();receipt=receipt_check(observed,case,mode,require_enforced=False)
    need(observed['operation'] is None,'unavailable dependency ran an unconstrained check')
    if receipt:need(receipt['lifecycle'].get('launched') is False,'dependency failure did not fail before check launch')
    if probe.fault:need(observed['fault_applied'],'dependency fault was not actually injected')
    if variant=='PATCH_AUTHENTICATION_FAILURE':
        need(not observed['final_verdict_written'],'patch authentication failure emitted a verdict')
        need(not observed['bundle_code_launched'],'bundle code launched before patch authentication')
    return {'id':case['id'],'mode':mode,'exit':observed['exit'],'verdict':observed['record']['verdict'] if observed['record'] else 'refused'}



def profile_rejection_case(top,case,mode,bundle):
    if not bundle:raise Unavailable('qualified patched bundle required for profile rejection qualification')
    probe=Probe(top/'subject',case,mode,bundle)
    probe.policy['localhost_ports']=[case['params']['declared_port']]
    probe.fault='profile:'+case['params']['profile_fault']
    probe.prepare();observed=probe.invoke()
    receipt=receipt_check(observed,case,mode,require_enforced=False)
    need(observed['exit']==2 and receipt['lifecycle'].get('launched') is False,'profile rejection did not stop before candidate launch')
    need(receipt.get('enforced') is False and observed['operation'] is None,'profile rejection ran a candidate or claimed enforcement')
    need(observed['fault_applied'],'profile fault never reached production validator')
    witness=json.loads((probe.root/'fault-applied').read_text())
    need(witness['fault']==case['params']['profile_fault'],'wrong profile input fault applied')
    policy=receipt['policy'];profile_evidence_check(policy,False)
    need(policy['profile_sha256']==witness['inspected_sha256'],'receipt discarded mismatching profile identity')
    need(policy['network_semantics']=='srt-0.0.81-exact-tcp-v1','profile rejection lost versioned semantics')
    expected=[{'host':host,'port':12345,'transport':'tcp'} for host in ('127.0.0.1','::1')]
    need(sorted(json.dumps(row,sort_keys=True) for row in policy['localhost_endpoints'])==sorted(json.dumps(row,sort_keys=True) for row in expected),'profile rejection changed canonical declaration')
    need(not observed['changes'] and observed['prefix_unchanged'],'profile rejection changed protected state')
    return {'id':case['id'],'mode':mode,'verdict':observed['record']['verdict'],
            'fault':witness,'profile_validation':policy['profile_validation'],'launched':False}


def isolation_case(top,case,mode,bundle):
    runs=case.get('params',{}).get('runs',1);rows=[];identities=[];pids=[]
    for index in range(runs):
        probe=Probe(top/('subject-'+str(index)),case,mode,bundle);configure_file(probe,case)
        try:
            probe.prepare();observed=probe.invoke();op=observed['operation']
            if op and op.get('child'):pids.append(op['child']['pid'])
            receipt=receipt_check(observed,case,mode,require_enforced=case['id']!='SUPERVISOR_DEATH')
            cleanup=observed['check'].get('cleanup')
            if not isinstance(cleanup,dict):raise Unavailable('cleanup evidence missing')
            if case['operation']=='group_child' and case['expected']=='supported':
                need(bool(pids) and not alive(pids[-1]) and cleanup.get('complete') is True,'group child survived or disappeared without proof')
            if case['operation']=='escape_child':
                need(bool(pids) and any(s['pid']==pids[-1] for s in cleanup.get('survivors',[])),'escaped descendant not named')
            if case['id']=='CHECK_TIMEOUT':need(cleanup.get('timed_out') is True,'timeout not evidenced')
            if probe.fault:need(observed['fault_applied'],'lifecycle fault did not apply')
            evidence=None
            if case['id'] in ('SUPERVISOR_DEATH','KILL_FAILURE','PROCESS_OBSERVATION_FAILURE'):
                owned=observed.get('owned_cleanup')
                if not owned or not any(row.get('phase')=='candidate' and row.get('started') and row.get('verified_no_live_group') for row in owned):
                    raise Unavailable('candidate check launch/cleanup identity unavailable')
                base=(observed['record'].get('base_checks') or [{}])[0]
                need(base.get('cleanup',{}).get('complete') is True and base.get('failed_assertions')==['NEW'],
                     'base phase did not complete the normal expected RED')
                try:
                    fault=json.loads(observed['fault_evidence'])
                    evidence=fault if case['id']=='SUPERVISOR_DEATH' else json.loads(observed['progress_evidence'])
                except (TypeError,ValueError): raise Unavailable('host barrier/fault evidence unavailable')
                nonce=probe.config.get('supervisor_barrier_nonce') or probe.config.get('fault_barrier_nonce')
                handshake=evidence.get('handshake',{});check=evidence.get('check',{});payload=evidence.get('payload_identity',{})
                need(evidence.get('nonce')==nonce and handshake.get('nonce')==nonce and
                     handshake.get('operation')==case['operation'] and check.get('phase')=='candidate' and
                     check.get('started') and payload.get('pid')==handshake.get('pid') and
                     payload.get('pgid')==handshake.get('pgid')==check.get('pid') and
                     handshake.get('at',0)<=evidence.get('observed_at',0)<=evidence.get('released_at',0),
                     'host nonce barrier did not identify the live candidate operation')
                if case['id']=='SUPERVISOR_DEATH':
                    need(evidence.get('observed_at',0)<=evidence.get('killed_at',0)<=evidence.get('released_at',0),
                         'supervisor death did not precede barrier release')
                    need((op or {}).get('supervisor_barrier')==handshake,'check did not resume from the same barrier')
                else:
                    need(fault.get('fault')==probe.fault and fault.get('pgid')==check.get('pid') and
                         fault.get('at',0)>=evidence.get('observed_at',0) and cleanup.get('complete') is False,
                         'candidate fault or incomplete cleanup not evidenced')
                    if case['id']=='KILL_FAILURE':need(cleanup.get('timed_out') is True,'kill fault did not follow actual timeout')
            identities.append(receipt['identity']['run_id'])
            need(bool(receipt['policy'].get('scratch_root')),'fresh scratch identity missing')
            rows.append({'identity':receipt['identity'],'scratch':receipt['policy']['scratch_root'],'cleanup':cleanup,
                         'operation':case['operation'],'host_barrier':evidence,'host_owned_cleanup':observed.get('owned_cleanup'),
                         'fault_evidence':observed.get('fault_evidence')})
        finally:
            # Teardown only PIDs reported by the reviewed disposable payload.
            # Remediation does not erase the nested survivor verdict.
            for pid in ([] if case['id'] in ('SUPERVISOR_DEATH','KILL_FAILURE','PROCESS_OBSERVATION_FAILURE') else pids):
                if alive(pid):
                    try:os.kill(pid,signal.SIGKILL)
                    except ProcessLookupError:pass
    need(len(set(identities))==len(identities),'run identity reused')
    need(len({r['scratch'] for r in rows})==len(rows),'scratch authority reused across checks')
    return {'id':case['id'],'mode':mode,'runs':rows}


def run_case(top,case,mode,bundle,classifier_package):
    top.mkdir()
    if case['layer']=='classifier':return classifier_case(top/'facts',case,mode,classifier_package)
    if case['layer']=='dependency':return dependency_case(top,case,mode,bundle)
    if case['layer']=='isolation':return isolation_case(top,case,mode,bundle)
    if case['layer']=='policy':
        if case.get('params',{}).get('profile_fault'):return profile_rejection_case(top,case,mode,bundle)
        if case['operation']=='clean' and case['expected']=='refused':return invalid_policy_case(top,case,mode,bundle)
        if case['id']=='UNSUPPORTED_EXACT_PORT_POLICY':
            return dependency_case(top,case,mode,bundle)
        return network_case(top,case,mode,bundle)
    if case['layer'] in ('effect','protocol'):return effect_case(top,case,mode,bundle)
    raise Unavailable('unimplemented frozen matrix case '+case['id'])


GROUPS = {
    'effect-classifier': ('effect', 'classifier'),
    'protocol': ('protocol',),
    'policy-dependency': ('policy', 'dependency'),
    'isolation': ('isolation',),
}


def exercise(group):
    matrix=json.loads((HERE/'matrix.json').read_text())
    cases=[case for case in matrix['cases'] if case['layer'] in GROUPS[group]];need(len({c['id'] for c in cases})==len(cases),'duplicate matrix cases')
    bundle=os.environ.get('KERNEL_SANDBOX_BUNDLE_RECEIPT')
    detail={'protocol':'sandbox-freeze-4','group':group,'matrix_cases':len(cases),'observations':[],
            'scope':'observed effects and bounded receipts; no attempt/intent/semantic attestation'}
    with tempfile.TemporaryDirectory(prefix='kernel-sandbox-matrix-') as tmp:
        top=Path(tmp).resolve()
        gate_case={'id':'BOUNDARY_PREFLIGHT_WRITE_'+group.upper().replace('-','_'),'operation':'write','expected':'unverifiable','layer':'effect'}
        gate=Probe(top/'boundary-gate',gate_case,'disabled',bundle)
        gate.config['target']=str(gate.target);gate.prepare(legacy_gate=True)
        observed=gate.invoke()
        op=observed['operation']
        # A valid legacy receipt PLUS a successful forbidden operation is the
        # reason for RED. No source-version sniff, unknown CLI, missing API or
        # bundle/setup failure is converted into an assertion failure.
        if (op and op.get('attempted') is True and op.get('outcome')=='succeeded'
                and observed['changes'] and observed['record'] and observed['record'].get('verdict')=='supported'
                and observed['check'].get('passed') is True and observed['check'].get('harness_error') is False
                and observed['check'].get('cleanup',{}).get('complete') is True):
            detail.update(decisive_counterexample={'id':'BOUNDARY_PREFLIGHT_WRITE_'+group.upper().replace('-','_'),'operation':op,
                          'changes':observed['changes'],'nested_verdict':observed['record']['verdict'],
                          'nested_exit':observed['exit']},
                          remaining_cases='not evaluated after decisive real effect counterexample; not credited as RED or GREEN')
            return False,detail
        denied_probe(observed,gate_case);receipt_check(observed,gate_case,'disabled')
        if not bundle:raise Unavailable('operator-qualified external srt/Node bundle absent; cannot qualify full matrix')
        classifier_package=top/'classifier-package';copy_package(classifier_package)
        failures=[]
        for case in cases:
            for mode in case['logging']:
                try:
                    row=run_case(top/(case['id']+'-'+mode),case,mode,bundle,classifier_package)
                    detail['observations'].append(row)
                except Mismatch as error:
                    failures.append({'id':case['id'],'logging':mode,'error':str(error)})
                # Unavailable intentionally propagates WITHOUT an assertion
                # receipt; missing evidence never becomes finite RED or GREEN.
        detail['failures']=failures
        need(len(detail['observations'])+len(failures)==sum(len(c['logging']) for c in cases),'matrix coverage accounting incomplete')
        return not failures,detail
