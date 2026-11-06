#!/usr/bin/env python3
"""Frozen sandbox qualification entrypoint; no product implementation."""
import json
import os
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent/'sandbox_fixtures'))
from harness import exercise


def main():
    passed,detail=exercise()  # Setup/unavailable errors must escape without JSON.
    print(json.dumps(detail,sort_keys=True))
    if 'VERIFY_RESULT_JSON' in os.environ:
        result={'protocol':1,'check':'sandbox evidence matrix','phase':os.environ['VERIFY_TREE'],
                'run_id':os.environ['VERIFY_RUN_ID'],
                'assertions':[{'id':'SANDBOX_MATRIX_BOUNDARY','status':'pass' if passed else 'fail',
                               'detail':json.dumps(detail,sort_keys=True)}]}
        Path(os.environ['VERIFY_RESULT_JSON']).write_text(json.dumps(result))
    return 0 if passed else 1


if __name__=='__main__':sys.exit(main())
