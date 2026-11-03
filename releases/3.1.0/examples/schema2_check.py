#!/usr/bin/env python3
"""Runnable schema2 example: observe app.txt; setup errors exit without a result.

Review this harness and freeze it with its declared helpers before delegation.
JSON proves receipt completeness/freshness, not independent semantic execution.
"""
import json
import os
import sys
from pathlib import Path

value = Path('app.txt').read_text(encoding='utf-8').strip()
passed = value == 'new'
result = {
    'protocol': 1, 'check': 'app exposes new behavior',
    'phase': os.environ['VERIFY_TREE'], 'run_id': os.environ['VERIFY_RUN_ID'],
    'assertions': [{'id': 'NEW_BEHAVIOR', 'status': 'pass' if passed else 'fail',
                    'detail': 'observed=' + value}],
}
Path(os.environ['VERIFY_RESULT_JSON']).write_text(json.dumps(result), encoding='utf-8')
sys.exit(0 if passed else 1)
