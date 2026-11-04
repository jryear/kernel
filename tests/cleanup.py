"""Frozen black-box receipts, process liveness and end-to-end verdict probes."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def run(argv, cwd, **kwargs):
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=45, **kwargs)


def live(pid):
    r = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='], capture_output=True, text=True)
    return bool(r.stdout.strip()) and not r.stdout.strip().startswith('Z')


SCRIPT = '''import json, os, subprocess, sys, time
from pathlib import Path
new = Path('app.txt').read_text() == 'new'
if new:
    mode = Path('mode.txt').read_text()
    if mode in ('group', 'escape', 'kill-failure'):
        child = subprocess.Popen([sys.executable, '-c', "import os,time; from pathlib import Path; " +
            ("os.setsid(); " if mode == 'escape' else "") +
            "Path(" + repr(os.environ['CHILD_PID_FILE']) + ").write_text(str(os.getpid())); time.sleep(40)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        while not Path(os.environ['CHILD_PID_FILE']).exists():
            if time.monotonic() > deadline: raise RuntimeError('child startup failed')
            time.sleep(.01)
        time.sleep(.35)
    elif mode == 'timeout':
        time.sleep(20)
    elif mode == 'missing':
        sys.exit(1)
result = {'protocol':1, 'check':'behavior', 'phase':os.environ['VERIFY_TREE'],
          'run_id':os.environ['VERIFY_RUN_ID'],
          'assertions':[{'id':'NEW', 'status':'pass' if new else 'fail', 'detail':'observed app'}]}
Path(os.environ['VERIFY_RESULT_JSON']).write_text(json.dumps(result))
sys.exit(0 if new else 1)
'''

# Fault injection at the OS boundary, confined to the nested candidate check.
DRIVER = '''import os, sys
sys.path.insert(0, sys.argv.pop(1))
import kernel_report
original = kernel_report.run_check
real_killpg = os.killpg
def denied(*args): raise PermissionError('injected kill failure')
def wrapped(root, check, phase):
    if phase == 'candidate': os.killpg = denied
    try: return original(root, check, phase)
    finally: os.killpg = real_killpg
kernel_report.run_check = wrapped
import verify
sys.exit(verify.main())
'''


def main():
    rows = []
    with tempfile.TemporaryDirectory(prefix='cleanup-evidence-') as temporary:
        top = Path(temporary)
        for mode, ident in [('group', 'GROUP_KILLED'), ('escape', 'ESCAPE_UNVERIFIABLE'),
                            ('timeout', 'TIMEOUT_UNVERIFIABLE'), ('kill-failure', 'KILL_FAILURE_UNVERIFIABLE'),
                            ('missing', 'MISSING_UNVERIFIABLE')]:
            repo = top / mode
            repo.mkdir()
            for cmd in [['git','init','-b','main'], ['git','config','user.email','kernel@example.test'],
                        ['git','config','user.name','Kernel evidence']]:
                if run(cmd, repo).returncode: raise RuntimeError('git fixture setup failed')
            (repo / 'app.txt').write_text('old')
            (repo / 'mode.txt').write_text(mode)
            (repo / 'check.py').write_text(SCRIPT)
            (repo / 'task.toml').write_text('''spec_version = 2
id = "nested-cleanup"
project = "kernel"
goal = "observe cleanup"
[scope]
include = ["app.txt"]
[[checks]]
name = "behavior"
kind = "acceptance"
timeout = 1
argv = ["python3", "check.py"]
entry = "check.py"
chain = ["check.py"]
evidence = ["check.py"]
assertions = ["NEW"]
baseline_failures = ["NEW"]
''')
            for cmd in [['git','add','.'], ['git','commit','-m','freeze']]:
                if run(cmd, repo).returncode: raise RuntimeError('git fixture freeze failed')
            base = run(['git','rev-parse','HEAD'],repo).stdout.strip()
            (repo / 'app.txt').write_text('new')
            if run(['git','commit','-am','implement'], repo).returncode: raise RuntimeError('git fixture commit failed')
            pidfile = top / (mode + '.pid')
            log = top / (mode + '.jsonl')
            argv = [sys.executable, str(ROOT/'verify.py')]
            if mode == 'kill-failure':
                driver = top / 'driver.py'
                driver.write_text(DRIVER)
                argv = [sys.executable, str(driver), str(ROOT)]
            env = {**os.environ, 'CHILD_PID_FILE':str(pidfile), 'PYTHONDONTWRITEBYTECODE':'1'}
            # This branch is independent of self-check, but permits later integration.
            import hashlib
            env['VERIFY_RELEASE_SHA256'] = hashlib.sha256((ROOT/'MANIFEST.sha256').read_bytes()).hexdigest()
            child = None
            try:
                result = run(argv + ['task.toml','--repo','.', '--base',base,'--log',str(log)], repo, env=env)
                if not log.exists(): raise RuntimeError('nested verifier produced no receipt: '+result.stderr)
                record = json.loads(log.read_text().splitlines()[-1])
                check = record['candidate_checks'][0]
                if pidfile.exists(): child = int(pidfile.read_text())
                cleanup = check.get('cleanup', {})
                if mode == 'group':
                    passed = (child is not None and not live(child) and result.returncode == 0
                              and record['verdict'] == 'supported' and cleanup.get('complete') is True)
                elif mode == 'escape':
                    survivors = cleanup.get('survivors', [])
                    passed = (child is not None and any(p.get('pid') == child for p in survivors)
                              and result.returncode == 2 and record['verdict'] == 'unverifiable')
                elif mode == 'timeout':
                    passed = (result.returncode == 2 and record['verdict'] == 'unverifiable'
                              and cleanup.get('timed_out') is True and check['harness_error'])
                elif mode == 'kill-failure':
                    passed = (result.returncode == 2 and record['verdict'] == 'unverifiable'
                              and bool(cleanup.get('errors')) and check['harness_error'])
                else:
                    passed = (result.returncode == 2 and record['verdict'] == 'unverifiable' and check['harness_error'])
                rows.append({'id':ident,'status':'pass' if passed else 'fail',
                             'detail':json.dumps({'exit':result.returncode,'verdict':record['verdict'],
                                                  'child':child,'cleanup':cleanup,'harness_error':check['harness_error']})})
            finally:
                if child is not None and live(child):
                    try: os.kill(child, signal.SIGKILL)
                    except ProcessLookupError: pass
    for row in rows: print(row['id'], row['status'], row['detail'])
    if 'VERIFY_RESULT_JSON' in os.environ:
        Path(os.environ['VERIFY_RESULT_JSON']).write_text(json.dumps({
            'protocol':1,'check':'process cleanup evidence','phase':os.environ['VERIFY_TREE'],
            'run_id':os.environ['VERIFY_RUN_ID'],'assertions':rows}))
    return int(any(r['status']=='fail' for r in rows))


if __name__ == '__main__': sys.exit(main())
