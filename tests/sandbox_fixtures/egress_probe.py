"""Separately authorized isolated-network probe; never used by baseline.

Only the trusted outer harness may supply the prequalified numeric RFC1918/ULA
endpoint. It sends a synthetic nonce, never credentials or host file contents.
No DNS, endpoint discovery, listener provisioning or arbitrary Internet target.
"""
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import sys

cfg=json.loads(Path(sys.argv[1]).read_text())
app=Path('app.txt').read_text().strip()
report={'case_id':cfg['case_id'],'operation':'external_connect','attempted':False,'outcome':'not_attempted','errno':None}
if app=='new':
    if cfg.get('qualified_isolated_fixture') is not True:raise RuntimeError('isolated endpoint qualification missing')
    address=ipaddress.ip_address(cfg['address'])
    if not address.is_private or address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
        raise RuntimeError('only separately qualified isolated private endpoints are permitted')
    report['attempted']=True
    try:
        with socket.socket(socket.AF_INET6 if address.version==6 else socket.AF_INET) as sock:
            sock.settimeout(3);sock.connect((str(address),cfg['port']))
            nonce=cfg['nonce'].encode();sock.sendall(nonce);reply=sock.recv(4096)
            report.update(outcome='succeeded',ack_matches=reply==nonce,reply_sha256=hashlib.sha256(reply).hexdigest())
    except OSError as error:report.update(outcome='denied' if error.errno in (errno.EPERM,errno.EACCES) else 'error',errno=error.errno)
print('SANDBOX_OPERATION '+json.dumps(report),flush=True)
if app=='new' and report['outcome']!='succeeded':sys.exit(99)
result={'protocol':1,'check':'probe','phase':os.environ['VERIFY_TREE'],'run_id':os.environ['VERIFY_RUN_ID'],
        'assertions':[{'id':'NEW','status':'pass' if app=='new' else 'fail','detail':json.dumps(report)}]}
Path(os.environ['VERIFY_RESULT_JSON']).write_text(json.dumps(result))
sys.exit(0 if app=='new' else 1)
