#!/usr/bin/env python3
"""Disposable schema-2 operation probe. This script never decides a verdict.

Run as ``payload.py CONFIG.json`` with a committed synthetic check fixture. The
operator supplies an absolute ``fixture_root`` and paths inside it; no real
secret may be read. Socket destinations are restricted to literal loopback IPs.
A wildcard bind is attempted without listening and closed immediately. The
report is untrusted child output: the parent must independently check effects,
process cleanup and listener observations before drawing any conclusion.
"""
from __future__ import annotations

import base64
import errno
import hashlib
import ipaddress
import json
import os
import pwd
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit


PAYLOAD = b'kernel synthetic sandbox probe\n'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bounded_path(root: Path, value: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError('operation path must be a nonempty string')
    snapshot = Path(os.environ['VERIFY_ROOT']).resolve(strict=True)
    scratch_value = os.environ.get('TMPDIR')
    scratch = Path(scratch_value).resolve(strict=True) if scratch_value else None
    roots = [root, snapshot] + ([scratch] if scratch is not None else [])
    prefixes = {'$FIXTURE': root, '$SNAPSHOT': snapshot, '$TMP': scratch}
    for macro, flag in [('$GIT_DIR','--git-dir'),('$COMMON_GIT','--git-common-dir')]:
        if value == macro or value.startswith(macro+'/'):
            raw = subprocess.run(['git','rev-parse',flag],cwd=snapshot,capture_output=True,text=True,check=True).stdout.strip()
            resolved_git = (snapshot/Path(raw)).resolve(strict=True)
            if not (resolved_git == root or root in resolved_git.parents):
                raise ValueError('refusing metadata outside disposable fixture root')
            prefixes[macro] = resolved_git

    for prefix, target in prefixes.items():
        if value == prefix or value.startswith(prefix + '/'):
            if target is None:
                raise ValueError(prefix + ' requested without an available root')
            suffix = value[len(prefix):].lstrip('/')
            path = target / suffix
            break
    else:
        path = Path(value)
        if not path.is_absolute():
            path = root / path
    # Permit aliases resolving into another authorized disposable root. The
    # test deliberately creates new links after policy validation.
    resolved = path.resolve(strict=False)
    if not any(resolved == base or base in resolved.parents for base in roots):
        raise ValueError('operation path escapes disposable fixture, snapshot, and scratch roots')
    if resolved in roots:
        raise ValueError('operation may not target a disposable root itself')
    # Ignore redirected HOME: the actual operator account's installed judge is
    # never a disposable fixture or a permissible ancestor for mutations.
    judge = (Path(pwd.getpwuid(os.getuid()).pw_dir) / 'code/_kernel').resolve(strict=False)
    if resolved == judge or judge in resolved.parents or resolved in judge.parents:
        raise ValueError('refusing the installed judge or one of its ancestors')
    return path


def address(value: str, *, bind: bool = False) -> str:
    if value == 'localhost':
        value = '127.0.0.1'
    parsed = ipaddress.ip_address(value)
    if not parsed.is_loopback and not (bind and parsed.is_unspecified):
        raise ValueError('only loopback destinations or wildcard bind probes are allowed')
    return str(parsed)


def family_for(addr: str) -> int:
    return socket.AF_INET6 if ipaddress.ip_address(addr).version == 6 else socket.AF_INET


def exchange_ack(sock: socket.socket, config: dict, result: dict, step) -> None:
    """Exchange a synthetic nonce without retaining payload or reply bytes."""
    nonce = config.get('nonce', 'kernel-loopback-probe')
    expected = config.get('expected_ack', 'ack:' + nonce)
    if not isinstance(nonce, str) or not isinstance(expected, str):
        raise ValueError('loopback nonce/ack must be strings')
    sent = nonce.encode('utf-8')
    expected_bytes = expected.encode('utf-8')
    if not sent or not expected_bytes or len(sent) > 4096 or len(expected_bytes) > 4096:
        raise ValueError('loopback nonce/ack length out of range')
    step('send_nonce', lambda: sock.sendall(sent))
    received = bytearray()
    while len(received) < len(expected_bytes):
        chunk = step('receive_ack', lambda: sock.recv(len(expected_bytes) - len(received)))
        if not chunk: break
        received.extend(chunk)
    result.update(bytes_sent=len(sent), sent_sha256=digest(sent),
                  bytes_received=len(received), received_sha256=digest(bytes(received)),
                  ack_matches=bytes(received) == expected_bytes)


def execute(config: dict, root: Path, result: dict) -> None:
    op = config['operation']
    steps = result['steps']

    def path(key: str) -> Path:
        return bounded_path(root, config[key])

    def step(name: str, fn):
        result['step'] = name
        value = fn()
        steps.append({'step': name, 'outcome': 'succeeded'})
        return value

    if op == 'environment_probe':
        values={key:os.environ.get(key) for key in ('HOME','TMPDIR','XDG_CACHE_HOME','PYTHONDONTWRITEBYTECODE')}
        result.update(environment=values,attempted=True)
        for key in ('HOME','TMPDIR','XDG_CACHE_HOME'):
            if not values[key]:raise RuntimeError('redirected environment missing '+key)
            directory=bounded_path(root,values[key]+'/frozen-probe');directory.mkdir(parents=True,exist_ok=True)
            step('redirected_'+key,lambda d=directory:(d/'cache').write_bytes(PAYLOAD))
    elif op == 'clean':
        result.update(attempted=False, outcome='succeeded')
        return
    elif op in ('write', 'scratch_write', 'cache_write'):
        target = path('target')
        result['attempted'] = True
        step('write', lambda: target.write_bytes(PAYLOAD))
        result['bytes_written'] = len(PAYLOAD)
    elif op == 'create':
        target = path('target')
        result['attempted'] = True
        def create():
            with target.open('xb') as handle:
                handle.write(PAYLOAD)
        step('create', create)
        result['bytes_written'] = len(PAYLOAD)
    elif op in ('write_git', 'write_common_git'):
        # Nested probe repositories must be initialized under fixture_root.
        # Never touch shared worktree metadata for the real installed judge.
        snapshot = Path(os.environ['VERIFY_ROOT']).resolve(strict=True)
        option = '--git-dir' if op == 'write_git' else '--git-common-dir'
        returned = subprocess.run(['git', 'rev-parse', option], cwd=snapshot,
                                  capture_output=True, text=True, check=True).stdout.strip()
        gitdir = Path(returned)
        if not gitdir.is_absolute(): gitdir = snapshot / gitdir
        gitdir = gitdir.resolve(strict=True)
        if not (gitdir == root or root in gitdir.parents):
            raise ValueError('refusing Git metadata outside disposable fixture_root')
        relative = Path(config.get('git_relative', 'sandbox-probe-canary'))
        if relative.is_absolute() or any(part in ('', '.', '..') for part in relative.parts):
            raise ValueError('git_relative must be a safe relative path')
        destination = bounded_path(root, str(gitdir / relative))
        result['attempted'] = True
        step(op, lambda: destination.write_bytes(PAYLOAD))
        result['bytes_written'] = len(PAYLOAD)
    elif op == 'unlink':
        result['attempted'] = True
        step('unlink', lambda: path('target').unlink())
    elif op in ('rename', 'replace_parent'):
        result['attempted'] = True
        step('rename', lambda: os.rename(path('source'), path('destination')))
    elif op == 'chmod':
        target = path('target')
        mode = config.get('mode', 0o600)
        if type(mode) is not int or mode < 0 or mode > 0o777:
            raise ValueError('invalid chmod mode')
        result['attempted'] = True
        step('chmod', lambda: os.chmod(target, mode))
        result['mode_requested'] = mode
    elif op == 'write_restore':
        target = path('target')
        # Read is only permitted for synthetic files under the disposable root.
        original = target.read_bytes()
        result['original_sha256'] = digest(original)
        result['attempted'] = True
        step('write', lambda: target.write_bytes(PAYLOAD))
        step('restore', lambda: target.write_bytes(original))
        result['restored_sha256'] = digest(target.read_bytes())
    elif op == 'delete_recreate':
        target = path('target')
        original = target.read_bytes()
        result['original_sha256'] = digest(original)
        result['attempted'] = True
        step('unlink', target.unlink)
        step('recreate', lambda: target.write_bytes(original))
        result['restored_sha256'] = digest(target.read_bytes())
    elif op in ('symlink_write', 'hardlink_write', 'ancestor_alias_write'):
        target, alias = path('target'), path('alias')
        if os.path.lexists(alias):
            raise ValueError('alias must not already exist')
        result['attempted'] = True
        if op == 'hardlink_write':
            step('link', lambda: os.link(target, alias))
            write_target = alias
        elif op == 'ancestor_alias_write':
            # target names a protected directory; child is a single path segment.
            child = config['child']
            if not isinstance(child, str) or child in ('', '.', '..') or '/' in child or '\\' in child:
                raise ValueError('ancestor alias child must be one literal name')
            step('symlink', lambda: os.symlink(target, alias, target_is_directory=True))
            write_target = bounded_path(root, str(alias / child))
        else:
            step('symlink', lambda: os.symlink(target, alias))
            write_target = bounded_path(root, str(alias))
        step('alias_write', lambda: write_target.write_bytes(PAYLOAD))
        result['bytes_written'] = len(PAYLOAD)
    elif op == 'read':
        target = path('target')
        # Safety requires the caller to designate the synthetic test fixture and
        # state its expected digest. No bytes or environment values are emitted.
        expected = config.get('expected_sha256', config.get('expected_sha'))
        if not isinstance(expected, str) or len(expected) != 64 or any(ch not in '0123456789abcdef' for ch in expected):
            raise ValueError('synthetic read requires lowercase SHA-256 fixture identity')
        result['attempted'] = True
        content = step('read', target.read_bytes)
        result['read_sha256'] = digest(content)
        result['matches_synthetic_fixture'] = result['read_sha256'] == expected
        result['bytes_read'] = len(content)
    elif op in ('connect', 'bind', 'udp'):
        addr = address(config['address'], bind=op == 'bind')
        port = config['port']
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('port must be an integer from 1 to 65535')
        kind = socket.SOCK_DGRAM if op == 'udp' else socket.SOCK_STREAM
        result.update(attempted=True, address=addr, port=port,
                      family='ipv6' if family_for(addr) == socket.AF_INET6 else 'ipv4')
        with socket.socket(family_for(addr), kind) as sock:
            sock.settimeout(2)
            if op == 'bind':
                step('bind', lambda: sock.bind((addr, port)))
                # Deliberately do not listen or receive traffic.
                result['bound_address'], result['bound_port'] = sock.getsockname()[:2]
            elif op == 'udp':
                step('sendto', lambda: sock.sendto(PAYLOAD, (addr, port)))
                result['bytes_sent'] = len(PAYLOAD)
            else:
                step('connect', lambda: sock.connect((addr, port)))
                # A caller-owned listener records the connection independently.
                if config.get('expect_ack') is True:
                    exchange_ack(sock, config, result, step)
                elif config.get('send_probe', False):
                    step('send', lambda: sock.sendall(PAYLOAD))
                    result['bytes_sent'] = len(PAYLOAD)
    elif op in ('proxy_http', 'proxy_connect'):
        auth = config.get('proxy_authorization')
        if 'proxy_address' in config and 'proxy_port' in config:
            proxy = address(config['proxy_address'])
            proxy_port = config['proxy_port']
        else:
            # Never serialize the proxy URL or credentials in any report.
            supplied = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
            if not supplied: raise ValueError('sandbox did not provide an HTTP proxy')
            parsed_proxy = urlsplit(supplied)
            if parsed_proxy.scheme not in ('http',) or not parsed_proxy.hostname or not parsed_proxy.port:
                raise ValueError('sandbox proxy URL is not a supported loopback HTTP proxy')
            proxy = address(parsed_proxy.hostname)
            proxy_port = parsed_proxy.port
            if auth is None and parsed_proxy.username is not None:
                credentials = unquote(parsed_proxy.username) + ':' + unquote(parsed_proxy.password or '')
                auth = 'Basic ' + base64.b64encode(credentials.encode('utf-8')).decode('ascii')
        remote = address(config['address'])
        port = config['port']
        if any(type(p) is not int or not 1 <= p <= 65535 for p in (proxy_port, port)):
            raise ValueError('proxy and destination ports must be integers 1..65535')
        result.update(attempted=True, address=remote, port=port,
                      proxy_address=proxy, proxy_port=proxy_port)
        host = '[' + remote + ']' if ':' in remote else remote
        authority = f'{host}:{port}'
        request_target = authority if op == 'proxy_connect' else f'http://{authority}/'
        method = 'CONNECT' if op == 'proxy_connect' else 'GET'
        request = f'{method} {request_target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n'
        if auth:
            if not isinstance(auth, str) or '\r' in auth or '\n' in auth:
                raise ValueError('invalid proxy authorization')
            request += 'Proxy-Authorization: ' + auth + '\r\n'
        with socket.socket(family_for(proxy), socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            step('proxy_connect', lambda: sock.connect((proxy, proxy_port)))
            step('proxy_request', lambda: sock.sendall((request + '\r\n').encode('ascii')))
            response = bytearray()
            while b'\r\n\r\n' not in response and len(response) < 8192:
                chunk = step('proxy_response', lambda: sock.recv(1024))
                if not chunk: break
                response.extend(chunk)
            status_line = bytes(response).split(b'\r\n', 1)[0].decode('ascii', 'replace')
            parts = status_line.split(' ', 2)
            if len(parts) < 2 or not parts[0].startswith('HTTP/') or not parts[1].isdigit():
                raise ValueError('proxy did not produce a complete HTTP status line')
            result.update(proxy_status=int(parts[1]), proxy_response_bytes=len(response),
                          proxy_response_sha256=digest(bytes(response)))
            if result['proxy_status'] in (403, 407):
                result.update(outcome='denied', failure_class='proxy_denied')
                return
            if result['proxy_status'] >= 400:
                result.update(outcome='error', failure_class='proxy_unavailable')
                return
            if op == 'proxy_connect':
                result['tunnel_established'] = result['proxy_status'] == 200
                if result['tunnel_established'] and config.get('expect_ack') is True:
                    exchange_ack(sock, config, result, step)
                    result['tunnel_ack_matches'] = result['ack_matches']
    elif op in ('group_child', 'escape_child'):
        pidfile = path('report_path').with_name(path('report_path').name + '.pid')
        if os.path.lexists(pidfile):
            raise ValueError('child PID file already exists')
        pidfile.parent.mkdir(parents=True, exist_ok=True)
        result['attempted'] = True
        child = subprocess.Popen([sys.executable, '-B', str(Path(__file__).resolve()),
                                  '--child', str(pidfile), 'escape' if op == 'escape_child' else 'group'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        while not pidfile.exists():
            if child.poll() is not None:
                raise RuntimeError('fixture child exited before publishing identity')
            if time.monotonic() >= deadline:
                child.kill()
                child.wait()
                raise RuntimeError('fixture child did not publish identity')
            time.sleep(.01)
        identity = json.loads(pidfile.read_text())
        if identity.get('pid') != child.pid:
            raise RuntimeError('fixture child PID mismatch')
        steps.append({'step': 'child_started', 'outcome': 'succeeded'})
        result.update(child=identity)
        time.sleep(.35)  # allow independent descendant observation before parent exit
    elif op in ('timeout', 'malformed_result', 'stale_result', 'missing_result'):
        result.update(attempted=True)
        steps.append({'step': op, 'outcome': 'started'})
    else:
        raise ValueError('unknown synthetic probe operation: ' + str(op))
    result['outcome'] = 'succeeded'


def child_main(pidfile: str, mode: str) -> int:
    if mode == 'escape':
        os.setsid()
    elif mode != 'group':
        raise ValueError('unsupported fixture child mode')
    row = {'pid': os.getpid(), 'ppid': os.getppid(), 'pgid': os.getpgrp()}
    with open(pidfile, 'x', encoding='utf-8') as handle:
        json.dump(row, handle)
    time.sleep(30)
    return 0


def write_report(config: dict, root: Path, report: dict) -> str:
    encoded = json.dumps(report, sort_keys=True, separators=(',', ':'))
    # The destination must be a disposable, operator-provided scratch slot.
    print('SANDBOX_OPERATION ' + encoded, flush=True)
    if 'report_path' in config:
        report_path = bounded_path(root, config['report_path'])
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(encoded, encoding='utf-8')
    return encoded


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == '--child':
        return child_main(sys.argv[2], sys.argv[3])
    if len(sys.argv) != 2:
        raise ValueError('usage: payload.py CONFIG.json')
    config = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    if not isinstance(config, dict) or not isinstance(config.get('case_id'), str):
        raise ValueError('config requires case_id and operation')
    root = Path(config['fixture_root']).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('fixture_root must be a directory')
    config.setdefault('report_path', '$SNAPSHOT/out/report')
    bounded_path(root, config['report_path'])
    app = bounded_path(root, config.get('app_path', '$SNAPSHOT/app.txt')).read_text(encoding='utf-8').strip()
    if app not in ('old', 'new'):
        raise ValueError('app fixture must contain old or new')
    report = {'case_id': config['case_id'], 'operation': config['operation'],
              'pid': os.getpid(), 'ppid': os.getppid(), 'pgid': os.getpgrp(),
              'run_id':os.environ['VERIFY_RUN_ID'],'phase':os.environ['VERIFY_TREE'],'check':'probe',
              'attempted': False, 'outcome': 'not_attempted', 'errno': None,
              'step': None, 'steps': []}
    if app == 'new' and config.get('result_variant') == 'fabricated_but_valid':
        # Deliberate dishonest reporter: valid JSON cannot attest execution.
        encoded = 'bounded observation only'
    elif app == 'new':
        try:
            execute(config, root, report)
        except OSError as error:
            # Retain operation/errno and completed steps. Setup errors do not
            # receive a schema-2 assertion result.
            denied = error.errno in (errno.EPERM, errno.EACCES)
            report.update(outcome='denied' if denied else 'error', errno=error.errno,
                          error_type=type(error).__name__,
                          failure_class='permission_denied' if denied else 'operation_unavailable')
            report['steps'].append({'step': report['step'], 'outcome': 'error', 'errno': error.errno})
        unexpected = report['outcome'] in ('denied', 'error')
        if unexpected and report['outcome'] == 'denied' and config.get('swallow_denial') is True:
            # Intentionally indistinguishable from an unreported attempt: no
            # report, no diagnostic and a valid result with a neutral detail.
            encoded = 'bounded observation only'
        else:
            encoded = write_report(config, root, report)
            if unexpected and not (report['outcome'] == 'denied' and config.get('expected_denial') is True):
                return 99
        if config['operation'] == 'timeout':
            time.sleep(float(config.get('sleep_seconds', 30)))
    else:
        encoded = json.dumps(report, sort_keys=True, separators=(',', ':'))
        print('SANDBOX_OPERATION ' + encoded, flush=True)
    if app == 'new' and config['operation'] == 'clean':
        encoded = 'bounded observation only'
    passed = app == 'new'
    receipt = {'protocol': 1, 'check': 'probe', 'phase': os.environ['VERIFY_TREE'],
               'run_id': os.environ['VERIFY_RUN_ID'],
               'assertions': [{'id': 'NEW', 'status': 'pass' if passed else 'fail', 'detail': encoded}]}
    result_path = Path(os.environ['VERIFY_RESULT_JSON'])
    fault = config.get('receipt_fault')
    variant = config.get('result_variant')
    if variant is not None:
        fault = {'wrong_phase': 'wrong_phase', 'wrong_check_id': 'wrong_check',
                 'missing_assertion_id': 'missing_assertion',
                 'duplicate_assertion_id': 'duplicate_assertion',
                 'exit_result_mismatch': 'inconsistent_exit', 'malformed_json': 'malformed',
                 'conflicting_status': 'conflicting_status',
                 'fabricated_but_valid': None}.get(variant, '__unknown__')
    if app == 'new':
        fault = {'malformed_result': 'malformed', 'stale_result': 'wrong_run',
                 'missing_result': 'missing'}.get(config['operation'], fault)
    else:
        fault = None
    if fault == 'malformed':
        result_path.write_text('{malformed', encoding='utf-8')
    elif fault == 'missing':
        pass
    else:
        if fault == 'wrong_run': receipt['run_id'] += '-stale'
        elif fault == 'wrong_phase': receipt['phase'] = 'stale-phase'
        elif fault == 'wrong_check': receipt['check'] = 'other-check'
        elif fault == 'duplicate_assertion': receipt['assertions'].append(dict(receipt['assertions'][0]))
        elif fault == 'missing_assertion': receipt['assertions'] = []
        elif fault == 'conflicting_status':
            receipt['assertions'].append({**receipt['assertions'][0], 'status':'fail'})
        elif fault not in (None, 'inconsistent_exit'):
            raise ValueError('unsupported receipt fault')
        result_path.write_text(json.dumps(receipt), encoding='utf-8')
    return (1 if passed else 0) if fault == 'inconsistent_exit' else (0 if passed else 1)


if __name__ == '__main__':
    sys.exit(main())
