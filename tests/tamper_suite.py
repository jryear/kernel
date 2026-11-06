#!/usr/bin/env python3
"""Frozen sandbox qualification entrypoint; no product implementation."""
import json
import os
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent/'sandbox_fixtures'))
from harness import exercise, GROUPS


def main():
    groups = [sys.argv[1]] if len(sys.argv) == 2 else list(GROUPS)
    if len(sys.argv) > 2 or any(group not in GROUPS for group in groups):
        raise ValueError('usage: tamper_suite.py [' + '|'.join(GROUPS) + ']')
    results = []
    for group in groups:
        passed,detail=exercise(group)  # Unavailable escapes without JSON.
        results.append((group, passed, detail))
    passed = all(row[1] for row in results)
    detail = {'groups': [row[2] for row in results]}
    print(json.dumps(detail,sort_keys=True))
    if 'VERIFY_RESULT_JSON' in os.environ:
        if len(groups) != 1: raise ValueError('schema-2 invocation requires one explicit group')
        result={'protocol':1,'check':'sandbox '+groups[0],'phase':os.environ['VERIFY_TREE'],
                'run_id':os.environ['VERIFY_RUN_ID'],
                'assertions':[{'id':'SANDBOX_'+groups[0].upper().replace('-','_')+'_BOUNDARY','status':'pass' if passed else 'fail',
                               'detail':json.dumps(detail,sort_keys=True)}]}
        Path(os.environ['VERIFY_RESULT_JSON']).write_text(json.dumps(result))
    return 0 if passed else 1


if __name__=='__main__':sys.exit(main())
