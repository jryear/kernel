#!/usr/bin/env python3
"""Run and record research observations; exit 0 means completed, never 'pass'."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
PACKAGE = HERE / 'node_modules/@anthropic-ai/sandbox-runtime'
CASES = ['canary','burst','confinement','reads','network','late']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def managed(argv, cwd, timeout):
    proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


class Loopback(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(64)
        self.request.sendall(b'loopback-ok')


def main():
    metadata = json.loads((PACKAGE/'package.json').read_text())
    if metadata['version'] != '0.0.81': raise RuntimeError('requires exactly srt 0.0.81; run npm ci --prefix spike')
    output = HERE / 'results'
    output.mkdir(exist_ok=True)
    result = {'schema':1,'purpose':'research observations, no certification verdict',
              'package':metadata['version'], 'platform':platform.platform(),
              'python':sys.version, 'started':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    result['sourceBindings'] = {name:digest(PACKAGE/name) for name in ['package.json','dist/cli.js',
        'dist/sandbox/sandbox-manager.js','dist/sandbox/sandbox-violation-store.js','dist/sandbox/macos-sandbox-utils.js']}
    with tempfile.TemporaryDirectory(prefix='kernel-srt-probe-') as temporary:
        root=Path(temporary).resolve()
        allowed=root/'allowed'; allowed.mkdir()
        protected=root/'protected'; protected.mkdir()
        (protected/'.env').write_text('synthetic-fixture-no-secret')
        (protected/'ssh').mkdir()
        ssh=protected/'ssh/key'; ssh.write_text('synthetic-fixture-no-secret')
        outside=protected/'outside.txt'; outside.write_text('original')
        actual_ssh=Path.home()/'.ssh'
        with socketserver.ThreadingTCPServer(('127.0.0.1',0),Loopback) as server:
            thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
            cfg={'allowed':str(allowed),'outside':str(outside),'canary':str(protected/'denied'),
                 'unlisted':str(root/'unlisted.txt'),'synthetic_ssh':str(ssh),'actual_ssh':str(actual_ssh),'dotenv':str(protected/'.env'),
                 'port':server.server_address[1]}
            payload=root/'payload.json'; payload.write_text(json.dumps(cfg))
            policy={'filesystem':{'allowWrite':[str(allowed)],'denyWrite':[str(protected)],
                                 'denyRead':[str(protected/'.env'),str(protected/'ssh'),str(actual_ssh)]},
                    'network':{'allowedDomains':['localhost','127.0.0.1'],'deniedDomains':[],
                               'allowLocalBinding':True,'strictAllowlist':True}}
            settings=root/'settings.json'; settings.write_text(json.dumps(policy))
            commands=[{'case':case,'cwd':str(allowed),'protected':[str(outside),str(ssh),str(protected/'.env')],
                       'canaryPrefix':cfg['canary'],'command':shlex.join([sys.executable,str(HERE/'payload.py'),str(payload),case])} for case in CASES]
            command_file=root/'commands.json'; command_file.write_text(json.dumps(commands))
            result['policy']=policy
            result['networkBoundary']='only loopback exercised; no external dial or DNS attempted'
            result['cli']={'cases':[],'collector':{'requestedBeforeCheck':True}}
            collector=None
            logpath=output/'cli-collector.log'
            with logpath.open('w') as logs, (output/'cli-collector.stderr').open('w') as logerr:
                try:
                    if sys.platform=='darwin':
                        collector=subprocess.Popen(['/usr/bin/log','stream','--style','compact','--predicate',
                            'eventMessage CONTAINS "'+str(root)+'"'],stdout=logs,stderr=logerr)
                        result['cli']['collector']['startedAt']=time.time()
                        time.sleep(.7)
                        result['cli']['collector']['aliveBeforeCheck']=collector.poll() is None
                        result['cli']['collector']['readyAcknowledgement']=False
                    else:
                        result['cli']['collector']['unavailable']='macOS log collector unavailable on this platform'
                    for command in commands:
                        before={str(p):digest(p) for p in [outside,ssh,protected/'.env']}
                        row={'case':command['case'],'startedAt':time.time()}
                        start_offset=logpath.stat().st_size
                        try:
                            run=managed(['node',str(PACKAGE/'dist/cli.js'),'--settings',str(settings),'-c',command['command']], allowed, 20)
                            row.update(code=run.returncode,stdout=run.stdout,stderr=run.stderr,exitedAt=time.time())
                        except subprocess.TimeoutExpired:
                            row['setupError']='CLI timed out; no confinement conclusion'
                        logs.flush()
                        row['collectorBytesAtExit']=logpath.stat().st_size
                        time.sleep(2)
                        row['collectorBytesAfterDrain']=logpath.stat().st_size
                        with logpath.open('rb') as observed:
                            observed.seek(start_offset)
                            lines=observed.read().decode('utf-8','replace').splitlines()
                        row['canaryDenialLogLines']=sum(cfg['canary'] in line and 'deny' in line for line in lines)
                        row['protectedUnchanged']={str(p):digest(p)==before[str(p)] for p in [outside,ssh,protected/'.env']}
                        row['canaryFilesCreated']=len(list(protected.glob('denied*')))
                        result['cli']['cases'].append(row)
                finally:
                    if collector:
                        collector.terminate()
                        try: collector.wait(timeout=3)
                        except subprocess.TimeoutExpired: collector.kill(); collector.wait()
                        result['cli']['collector']['exit']=collector.returncode
            library_output=output/'library.json'
            before={str(p):digest(p) for p in [outside,ssh,protected/'.env']}
            try:
                run=managed(['node',str(HERE/'library_probe.mjs'),str(settings),str(command_file),str(library_output)], allowed, 120)
                result['libraryDriver']={'exit':run.returncode,'stdout':run.stdout,'stderr':run.stderr}
                if not library_output.exists(): raise RuntimeError('library driver did not record results')
                result['embedded']=json.loads(library_output.read_text())
                result['embedded']['protectedUnchanged']={str(p):digest(p)==before[str(p)] for p in [outside,ssh,protected/'.env']}
            finally:
                server.shutdown()
    # Completion concerns the probe protocol, never whether confinement passed.
    cli_rows=result['cli']['cases']
    embedded_rows=result['embedded'].get('cases',[])
    def payload_recorded(row):
        try:
            payload=json.loads(row.get('stdout',''))
            return payload.get('mode') == row['case']
        except (ValueError, AttributeError):
            return False
    result['completed']=(len(cli_rows)==len(CASES) and len(embedded_rows)==len(CASES)
                         and all(payload_recorded(row) for row in cli_rows+embedded_rows))
    result['probeSourceBindings']={str(p.relative_to(HERE.parent)):digest(p) for p in
        [HERE/'sandbox_probe.py', HERE/'payload.py', HERE/'library_probe.mjs', HERE/'package-lock.json']}
    result['completedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    (output/'results.json').write_text(json.dumps(result,indent=2))
    print(('COMPLETED' if result['completed'] else 'INCOMPLETE')+' research probes; observations recorded at '+str(output/'results.json'))
    return 0 if result['completed'] else 1


if __name__=='__main__': sys.exit(main())
