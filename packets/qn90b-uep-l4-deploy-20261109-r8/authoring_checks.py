"""r7 authoring-time verification: compile the trimmed agent + bash -n sweep.

Bakes a SYNTHETIC gate-remove.sh (the live bake happens at TV-contact after
the inspection), compiles BridgeRepairAgent.csproj with the pinned SDK into a
temp tree, checks zero warnings/errors, runs bash -n on every shell artifact,
then deletes the synthetic bake and the temp build so the packet directory
matches its true pre-inspection state (no stale agent bytes for the seal).
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
import driver_shim
import packet as p
import prepare

PACK = p.HERE
SDK = Path(r'C:/Users/Kninetimmy/.dotnet-sdks/3.1.426')

results = {}

# 1) synthetic bake (rehearsal values; deleted afterwards)
synthetic = prepare.bake_gate_remove(
    driver_shim.REHEARSAL_BOOT, '_', PACK, uep_config=p.UEP_CONFIG,
    stage=p.STAGE, canon=p.CANON, pkg=p.PKG)
p.require(list(synthetic) == ['gate-remove.sh'], 'unexpected synthetic bake surface')
results['synthetic_bake'] = '_'

# 2) integrity gates against the SYNTHETIC bake (mirrors offline_checks'
#    sealed-bytes gates; proves the reviewed template lands correctly)
synthetic_text = None
with open(PACK / 'gate-remove.sh', 'r', encoding='ascii') as stream:
    synthetic_text = stream.read()
p.require(p.UEP_READONLY_SHA in synthetic_text, 'baked removal script lost the read-only pin')
p.require(p.UEP_ACTIVE_SHA not in synthetic_text, 'baked removal script permits the active content; refuse path required')
p.require('GATE_ABSENT' in synthetic_text, 'baked removal script lost the absence assertion')
p.require('GATE_METADATA' not in synthetic_text and 'H_END' not in synthetic_text
          and 'H_SOURCE' not in synthetic_text and 'H_ACTIVE' not in synthetic_text,
          'baked removal script kept a surviving-file fallback or unreplaced template algebra')
p.require(synthetic_text.rstrip('\n').endswith("printf 'GATE_ABSENT\\n'"),
          'the tail must end with the absence assertion')
results['integrity_gates'] = 'ok'

# 3) compile into a temp tree
with tempfile.TemporaryDirectory(prefix='r7-agent-build-', dir=driver_shim.REHEARSAL_TEMP) as temp:
    command = [str(SDK / 'dotnet.exe'), 'build', str(PACK / 'BridgeRepairAgent.csproj'),
               '-c', 'Release', '-f', 'netcoreapp3.1',
               '-p:BaseIntermediateOutputPath=' + str(Path(temp) / 'obj') + os.sep,
               '-p:OutputPath=' + str(Path(temp) / 'build') + os.sep]
    env = dict(os.environ, DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_ROOT=str(SDK))
    built = subprocess.run(command, capture_output=True, cwd=str(p.REPO), env=env)
    combined = built.stdout.decode()[-4000:] + built.stderr.decode()[-1200:]
    p.require(built.returncode == 0, 'agent build failed:\n' + combined)
    results['build'] = 'succeeded'
    # Parse MSBuild's own summary line: a substring scan for "warning" is
    # vacuous because MSBuild always prints "0 Warning(s)".
    warnings_summary = re.search(r'(\d+) Warning\(s\)', combined)
    p.require(warnings_summary is not None and warnings_summary.group(1) == '0',
              'agent build reported warnings:\n' + combined)
    results['warnings'] = 0

# 4) shell syntax sweep over the carried + synthetic bytes
for name in ('stage.sh', 'snapshot.sh', 'gate-remove.sh'):
    path = PACK / name
    parsed = subprocess.run([r'C:\Program Files\Git\bin\bash.exe', '-n', str(path)],
                            capture_output=True)
    p.require(parsed.returncode == 0, 'bash -n failed: ' + name + ' ' + parsed.stderr.decode()[:300])
    results['bash_n_' + name] = 'ok'

# 5) ruff sweep over everything the seal will hash as python (stub-free set)
ruff = subprocess.run([str(p.REPO / '.venv/Scripts/python.exe'), '-B', '-m', 'ruff', 'check',
                       '--no-cache', '--isolated', '--select', 'F821', str(PACK)],
                      capture_output=True)
p.require(ruff.returncode == 0, 'undefined names survived: ' + ruff.stdout.decode()[:1200])
results['ruff'] = 'ok'

# 6) return the packet to its true pre-inspection state
(PACK / 'gate-remove.sh').unlink()
p.require(not (PACK / 'gate-remove.sh').exists(), 'synthetic bake survived')
results['cleanup'] = 'synthetic bake removed; build units were temp-tree only'

print(json.dumps(results, indent=1))
