"""Trusted test adapter: invokes the subject, never implements sandbox policy.

Faults patch only this disposable interpreter. No installed judge is imported.
The classifier seam is an explicit freeze interface, reviewed before production.
"""
import importlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

sys.dont_write_bytecode = True
mode, package, request_path = sys.argv[1:4]
package = Path(package).resolve()
request = json.loads(Path(request_path).read_text())
sys.path.insert(0, str(package))
if mode == 'classify':
    subject = importlib.import_module('kernel_sandbox')
    result = subject.classify_sandbox_evidence(request)
    print('SANDBOX_CLASSIFICATION ' + json.dumps(result, sort_keys=True))
else:
    fault = request.get('fault')
    marker = Path(request['fault_marker'])
    real_run, real_popen, real_which = subprocess.run, subprocess.Popen, shutil.which
    if fault == 'kill':
        def denied(*args, **kwargs):
            marker.write_text('kill injected')
            raise PermissionError('frozen fixture: killpg unavailable')
        os.killpg = denied
    if fault == 'ps_or_identity_observation':
        def failed_ps(argv, *args, **kwargs):
            if isinstance(argv, list) and Path(argv[0]).name == 'ps':
                marker.write_text('ps injected')
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
    if fault == 'supervisor_death':
        def killed(argv, *args, **kwargs):
            proc = real_popen(argv, *args, **kwargs)
            if isinstance(argv, list) and any('supervisor' in str(v) and str(v).endswith(('.mjs','.js')) for v in argv):
                marker.write_text('supervisor killed')
                proc.kill()
            return proc
        subprocess.Popen = killed
    subject = importlib.import_module('verify')
    sys.argv = [str(package/'verify.py'), *sys.argv[4:]]
    sys.exit(subject.main())
