"""Strict schema 2 terminal assertion handshake; no execution attestation."""
from __future__ import annotations
import json
import os
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def read_result(path, check, phase, token, exit_code):
    if exit_code not in (0, 1):
        raise ValueError(f'exit {exit_code} is not an assertion result')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('result must be a regular non-symlink file')
    with path.open('r', encoding='utf-8') as handle:
        result = json.load(handle, object_pairs_hook=unique_object)
    keys = {'protocol', 'check', 'phase', 'run_id', 'assertions'}
    if not isinstance(result, dict) or set(result) != keys:
        raise ValueError('terminal result keys differ from protocol')
    if type(result['protocol']) is not int or result['protocol'] != 1:
        raise ValueError('unsupported terminal result protocol')
    if (result['check'], result['phase'], result['run_id']) != (check['name'], phase, token):
        raise ValueError('terminal result invocation identity mismatch')
    rows = result['assertions']
    if not isinstance(rows, list):
        raise ValueError('assertions must be an array')
    ids = []
    failed = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'id', 'status', 'detail'}:
            raise ValueError('assertion row keys differ from protocol')
        if not isinstance(row['id'], str) or row['status'] not in ('pass', 'fail') or not isinstance(row['detail'], str):
            raise ValueError('invalid assertion row types/status')
        ids.append(row['id'])
        if row['status'] == 'fail':
            failed.append(row['id'])
    if len(ids) != len(set(ids)) or set(ids) != set(check['assertions']):
        raise ValueError('assertion IDs must equal the complete unique declared set')
    if exit_code != (1 if failed else 0):
        raise ValueError('exit/assertion status disagreement')
    return result, sorted(failed)


def run_check(root, check, phase):
    start = time.monotonic()
    token = uuid.uuid4().hex
    row = {'name': check['name'], 'kind': check['kind'], 'expected_exit': 0,
           'passed': False, 'harness_error': True}
    with tempfile.TemporaryDirectory(prefix='verify-result-') as temporary:
        path = Path(temporary) / 'result.json'  # absent until trusted harness writes
        env = {**os.environ, 'VERIFY_TREE': phase, 'VERIFY_ROOT': str(root),
               'VERIFY_RUN_ID': token, 'VERIFY_RESULT_JSON': str(path)}
        argv = list(check['argv'])
        if check['_entry_position'] == 0:
            argv[0] = str(root / check['entry'])
        try:
            if check['_entry_position']:
                if not check.get('_runtime_executable'):
                    raise FileNotFoundError('declared runtime unavailable')
                argv[0] = check['_runtime_executable']
            result = subprocess.run(argv, shell=False, cwd=root, env=env,
                                    capture_output=True, timeout=check['timeout'])
            code = result.returncode
            output = (result.stdout + result.stderr).decode('utf-8', 'replace')
        except subprocess.TimeoutExpired as error:
            code, output = 99, f'TIMEOUT after {error.timeout}s'
        except OSError as error:
            code, output = 99, f'check executable unavailable: {error}'
        row.update(exit=code, seconds=round(time.monotonic() - start, 2),
                   output=output, output_tail=output[-1500:])
        try:
            receipt, failed = read_result(path, check, phase, token, code)
            row.update(assertion_result=receipt, failed_assertions=failed,
                       passed=not failed, harness_error=False)
        except (OSError, ValueError, TypeError, UnicodeError) as error:
            row['result_protocol_error'] = str(error)
    return row
