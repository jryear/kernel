"""Synthetic operations only; never read secret contents or dial external hosts."""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit, unquote

cfg = json.loads(Path(sys.argv[1]).read_text())
mode = sys.argv[2]
out = {'mode':mode}

def write(path):
    try:
        Path(path).write_text('probe-write')
        return {'outcome':'written'}
    except OSError as error:
        return {'outcome':'error', 'errno':error.errno}


def opened(path):
    try:
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)  # Never read bytes from the real ~/.ssh directory.
        return {'outcome':'opened-without-reading'}
    except OSError as error:
        return {'outcome':'error', 'errno':error.errno}

if mode == 'canary':
    out['write'] = write(cfg['canary'])
elif mode == 'burst':
    results = [write(cfg['canary'] + str(i)) for i in range(150)]
    out['attempts'] = len(results)
    out['errors'] = sum(r['outcome']=='error' for r in results)
    out['errno_counts'] = {str(n):sum(r.get('errno')==n for r in results) for n in set(r.get('errno') for r in results)}
elif mode == 'confinement':
    out['inside'] = write(cfg['allowed'] + '/inside.txt')
    out['outside'] = write(cfg['outside'])
    out['unlisted_temp_path'] = write(cfg['unlisted'])
elif mode == 'reads':
    out['synthetic_ssh'] = opened(cfg['synthetic_ssh'])
    out['actual_ssh_directory'] = opened(cfg['actual_ssh'])
    out['dotenv'] = opened(cfg['dotenv'])
elif mode == 'network':
    try:
        with socket.create_connection(('127.0.0.1', cfg['port']), timeout=2) as sock:
            sock.sendall(b'loopback-probe')
            out['localhost'] = sock.recv(64).decode()
    except OSError as error:
        out['localhost'] = {'errno':error.errno, 'error':str(error)}
    # Exercise a proxy refusal using only another loopback address. Even a
    # broken allowlist cannot dial an external host during this probe.
    proxy = urlsplit(os.environ.get('HTTP_PROXY', os.environ.get('http_proxy','')))
    try:
        if not proxy.hostname: raise RuntimeError('no proxy exposed to child')
        headers = f'GET http://127.0.0.2:{cfg["port"]}/ HTTP/1.1\r\nHost: 127.0.0.2\r\nConnection: close\r\n'
        if proxy.username is not None:
            auth = unquote(proxy.username) + ':' + unquote(proxy.password or '')
            headers += 'Proxy-Authorization: Basic ' + base64.b64encode(auth.encode()).decode() + '\r\n'
        with socket.create_connection((proxy.hostname,proxy.port),timeout=2) as sock:
            sock.sendall((headers+'\r\n').encode())
            out['disallowed_loopback_proxy_status'] = sock.recv(2048).split(b'\r\n',1)[0].decode()
    except (OSError, RuntimeError) as error:
        out['disallowed_loopback_proxy_status'] = {'error':str(error)}
    out['external'] = 'not dialed: task forbids outbound network beyond package installation'
elif mode == 'late':
    child = subprocess.Popen([sys.executable, __file__, sys.argv[1], 'late-child'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out['child_pid'] = child.pid
elif mode == 'late-child':
    time.sleep(.5)
    out['write'] = write(cfg['canary'] + '-late')
else:
    raise ValueError(mode)
print(json.dumps(out), flush=True)
