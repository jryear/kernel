"""Frozen behavioral evidence: invoke a disposable package, never the installed judge."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
# Fixture creation is frozen in the existing regression helper.
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from selftest import make_repo


def main():
    rows = []
    with tempfile.TemporaryDirectory(prefix='self-check-evidence-') as temp:
        temp = Path(temp)
        repo = make_repo(temp / 'fixture')
        package = temp / 'package'
        package.mkdir()
        manifest = (ROOT / 'MANIFEST.sha256').read_text()
        for line in manifest.splitlines():
            _, name = line.split('  ', 1)
            target = package / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        (package / 'MANIFEST.sha256').write_text(manifest)
        expected = hashlib.sha256(manifest.encode()).hexdigest()
        env = {**os.environ, 'VERIFY_RELEASE_SHA256': expected, 'PYTHONDONTWRITEBYTECODE': '1'}
        cmd = [sys.executable, str(package / 'verify.py'), 'tasks/demo.toml', '--repo', str(repo), '--base', 'main', '--baseline']
        positive = subprocess.run(cmd, cwd=repo, env=env, capture_output=True, text=True, timeout=30)
        if positive.returncode != 0 or 'BASELINE_READY' not in positive.stdout:
            raise RuntimeError('intact fixture failed: ' + positive.stdout + positive.stderr)
        cases = [('ALTERED_VERIFIER', 'verify.py'), ('ALTERED_MANIFEST', 'MANIFEST.sha256'),
                 ('ALTERED_RUNTIME', 'kernel_runtime.py'), ('ALTERED_REPORT', 'kernel_report.py'),
                 ('MISSING_DIGEST', None)]
        for ident, name in cases:
            case_env = dict(env)
            if name:
                target = package / name
                original = target.read_bytes()
                target.write_bytes(original + b'\n# altered bytes\n')
            else:
                case_env.pop('VERIFY_RELEASE_SHA256', None)
            result = subprocess.run(cmd, cwd=repo, env=case_env, capture_output=True, text=True, timeout=30)
            if name:
                target.write_bytes(original)
            no_verdict = not any(word in result.stdout for word in ('SUPPORTED', 'CONTRADICTED', 'UNVERIFIABLE', 'BASELINE_READY'))
            passed = result.returncode == 3 and no_verdict and 'release integrity' in result.stderr.lower()
            rows.append({'id': ident, 'status': 'pass' if passed else 'fail',
                         'detail': f'exit={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}'})
    for row in rows:
        print(row['id'], row['status'], row['detail'])
    if 'VERIFY_RESULT_JSON' in os.environ:
        Path(os.environ['VERIFY_RESULT_JSON']).write_text(json.dumps({
            'protocol': 1, 'check': 'release integrity refusal', 'phase': os.environ['VERIFY_TREE'],
            'run_id': os.environ['VERIFY_RUN_ID'], 'assertions': rows}))
    return int(any(row['status'] == 'fail' for row in rows))


if __name__ == '__main__':
    sys.exit(main())
