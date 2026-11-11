"""Runner for the r7 HOST-ONLY rehearsal: executes the shell-transition cases
and the driver-flow suite, raises a nonzero exit on any failure, writes
rehearsal-results.json.

Run from the repo root:
  .venv/Scripts/python.exe -B .memhub/prep/qn90b-uep-l4-deploy-20261109-r7/driver_checks.py
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path('C:/Users/Kninetimmy/samtv')
PACK = Path(__file__).resolve().parent
sys.path.insert(0, str(PACK))

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
        failed.append({'suite': kind, 'error': type(error).__name__ + ': ' + str(error)[:500]})
        print('FLUNK ' + kind + ': ' + type(error).__name__ + ': ' + str(error)[:300])


print(json.dumps({'phase': 'static', 'tv_operations': 0}))
static_ruff = subprocess.run(
    [str(REPO / '.venv/Scripts/python.exe'), '-B', '-m', 'ruff', 'check',
     '--no-cache', '--isolated', '--select', 'F821',
     *[str(PACK / n) for n in ('packet.py', 'stage_lib.py', 'deploy.py', 'remove.py',
                               'inspect_tv.py', 'prepare.py', 'offline_checks.py',
                               'driver_shim.py', 'flow_cases.py')]],
    capture_output=True)
if static_ruff.returncode == 0:
    print('PASS  STATIC  no undefined names in the r7 sources (ruff F821)')
    passed += 1
else:
    failed.append({'suite': 'STATIC-F821', 'error': static_ruff.stdout.decode()[:800]})
    print('FLUNK STATIC-F821', static_ruff.stdout.decode()[:600])

suite('F1-remove-shell-transitions', 'flow_cases')

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
