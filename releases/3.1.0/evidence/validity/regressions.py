#!/usr/bin/env python3
"""Run unchanged six historical selftests and twenty timeout cases, bounded."""
import argparse, hashlib, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path
sys.dont_write_bytecode=True
EXPECTED_SELF='c39278627dd19b718060ad5f1c0c9cfa91e894af25d99d51e58cb1ff8b569a69'
EXPECTED_TIMEOUT='799c464441b2499a1d09108bf847ee1223914204e18ecb209dd3a62e3828e217'
def main():
    p=argparse.ArgumentParser(); p.add_argument('--verifier',required=True,type=Path); p.add_argument('--receipt',required=True,type=Path); a=p.parse_args()
    root=Path(__file__).resolve().parents[2]; old=root/'selftest.py'; timeout=root/'evidence/legacy/test_timeout_boundary.py'; rows=[]
    try:
        if hashlib.sha256(old.read_bytes()).hexdigest()!=EXPECTED_SELF or hashlib.sha256(timeout.read_bytes()).hexdigest()!=EXPECTED_TIMEOUT: raise AssertionError('HISTORICAL_BYTES: original evidence changed')
        with tempfile.TemporaryDirectory(prefix='kernel-original-regressions-') as temp:
            t=Path(temp); shutil.copyfile(a.verifier,t/'verify.py'); shutil.copyfile(old,t/'selftest.py')
            for helper in ['kernel_runtime.py','kernel_report.py']:
                source=a.verifier.resolve().parent/helper
                if source.exists(): shutil.copyfile(source,t/helper)
            commands=[[sys.executable,str(t/'selftest.py')],[sys.executable,str(timeout),'--verifier',str(a.verifier.resolve()),'--receipt',str(t/'timeout.json')]]
            for cmd in commands:
                r=subprocess.run(cmd,text=True,capture_output=True,timeout=100,env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(t),'PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_CONFIG_SYSTEM':os.devnull,'GIT_TERMINAL_PROMPT':'0'})
                rows.append({'argv':cmd,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
            timeout_result=json.loads((t/'timeout.json').read_text()) if (t/'timeout.json').exists() else None
        rc=99 if any(r['exit']==99 for r in rows) else 1 if any(r['exit']!=0 for r in rows) else 0
    except AssertionError as e: rows.append({'invariant':'HISTORICAL_BYTES','error':str(e)}); timeout_result=None; rc=1
    except (OSError,subprocess.TimeoutExpired,ValueError) as e: rows.append({'unavailable':str(e)}); timeout_result=None; rc=99
    a.receipt.parent.mkdir(parents=True,exist_ok=True); a.receipt.write_text(json.dumps({'protocol':1,'exit':rc,'rows':rows,'timeout_suite':timeout_result,'expected_counts':{'selftests':6,'timeout_cases':20}},indent=2)+'\n')
    print('historical regression exit',rc); return rc
if __name__=='__main__': sys.exit(main())
