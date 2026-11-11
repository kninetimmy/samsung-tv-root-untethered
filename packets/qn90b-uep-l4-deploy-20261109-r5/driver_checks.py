"""Runner for the r5 HOST-ONLY rehearsal: executes every suite module,
raises a nonzero exit on any failure, writes rehearsal-results.json.

Run from the repo root:
  .venv/Scripts/python.exe -B .memhub/prep/qn90b-uep-l4-deploy-20261109-r5/driver_checks.py
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path('C:/Users/Kninetimmy/samtv')
PACK = Path(__file__).resolve().parent
sys.path.insert(0, str(PACK))

import packet as p
import prepare

passed = 0
failed = []


def suite(kind, import_name, run_function_name='run'):
    global passed
    module = __import__(import_name)
    try:
        results = getattr(module, run_function_name)()
        for name in results:
            passed += 1
            print('PASS  ' + kind + '  ' + name)
    except BaseException as error:
        failed.append({'suite': kind, 'error': str(error)[:500]})
        print('FLUNK ' + kind + ': ' + str(error)[:300])


print(json.dumps({'phase': 'static', 'tv_operations': 0}))
static_ruff = subprocess.run(
    [str(REPO / '.venv/Scripts/python.exe'), '-B', '-m', 'ruff', 'check',
     '--no-cache', '--isolated', '--select', 'F821',
     *[str(PACK / n) for n in ('packet.py', 'stage_lib.py', 'deploy.py', 'dirread.py',
                               'activate.py', 'disable.py', 'watch.py', 'prepare.py',
                               'driver_shim.py', 's1_cases.py', 's2_cases.py', 's3_cases.py',
                               's4_cases.py', 's5s6_cases.py', 's7_cases.py', 's8_cases.py',
                               'flow_cases.py')]],
    capture_output=True)
if static_ruff.returncode == 0:
    print('PASS  STATIC  no undefined names in the r5 sources (ruff F821)')
    passed += 1
else:
    failed.append({'suite': 'STATIC-F821', 'error': static_ruff.stdout.decode()[:800]})
    print('FLUNK STATIC-F821')

suite('S1-shell-transitions', 's1_cases')
suite('S2-probe-mechanics', 's2_cases')
suite('S3-proof-capture', 's3_cases')
suite('S4-baseline', 's4_cases')
suite('S5S6-stop-prereqs', 's5s6_cases')
suite('S7-assessment', 's7_cases')
suite('S8-static', 's8_cases')
suite('S9-driver-flows', 'flow_cases')

document = {
    'runner': 'driver_checks.py',
    'tv_operations': 0,
    'passed': passed,
    'failures': failed,
    'verdict': 'PASSED' if not failed else 'FAILED',
}
(PACK / 'rehearsal-results.json').write_text(json.dumps(document, indent=1) + '\n', encoding='utf-8')
print(json.dumps({'verdict': document['verdict'], 'passed': passed, 'failures': failed}))
if failed:
    sys.exit(1)
