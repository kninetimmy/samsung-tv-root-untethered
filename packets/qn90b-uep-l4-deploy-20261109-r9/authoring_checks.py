"""r9 authoring-time verification: bake, integrity gates, agent build, syntax.

Bakes the three scripts with production constants (the live bake after the
inspection is byte-identical: no boot pin is baked), compiles UepGateAgent with
the pinned SDK into a temp tree, checks zero warnings, verifies the embedded
resources and the script algebra, runs bash -n and ruff F821, then deletes the
bake so the packet stays in its true pre-inspection state. No TV operation.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
import packet as p
import prepare

PACK = p.HERE
SDK = Path(r'C:/Users/Kninetimmy/.dotnet-sdks/3.1.426')

results = {}

# A failed earlier authoring run may have left its (identical) bake behind;
# only an exact re-bake is treated as a leftover, never a hand edit.
STALE = ('gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh')
if any((PACK / name).exists() for name in STALE):
    with tempfile.TemporaryDirectory(prefix='r9-stale-bake-') as probe_dir:
        probe = {}
        probe.update(prepare.bake_install(Path(probe_dir)))
        probe.update(prepare.bake_active(Path(probe_dir)))
        probe.update(prepare.bake_remove(Path(probe_dir)))
        for name in STALE:
            path = PACK / name
            if path.exists():
                p.require(path.read_text(encoding='ascii') == probe[name], 'stale script drift: ' + name)
                path.unlink()
    results['stale_bake_removed'] = True

baked = {}
baked.update(prepare.bake_install(PACK))
baked.update(prepare.bake_active(PACK))
baked.update(prepare.bake_remove(PACK))
p.require(sorted(baked) == ['gate-config-active.sh', 'gate-install.sh', 'gate-remove.sh'],
          'unexpected bake surface')
results['bake'] = sorted(baked)

install = (PACK / 'gate-install.sh').read_text(encoding='ascii')
active = (PACK / 'gate-config-active.sh').read_text(encoding='ascii')
remove = (PACK / 'gate-remove.sh').read_text(encoding='ascii')

# Producer -> consumer algebra: each script may only make its one edge.
p.require(p.PREV_MANAGER_SHA in install and p.NEW_MANAGER_SHA in install,
          'install lost a manager pin')
p.require(p.UEP_READONLY_SHA in install, 'install lost the read-only pin')
p.require(p.UEP_ACTIVE_SHA not in install, 'install can write active content')
p.require(p.RECEIPT_READONLY_MANUAL in install and p.LOG_READONLY.format('manual', p.FINGERPRINT) in install,
          'install lost the root-context manual receipt')
p.require(p.UEP_READONLY_SHA in active and p.UEP_ACTIVE_SHA in active,
          'activation lost a content pin')
p.require('GATE_ABSENT' not in active, 'activation can remove a config')
p.require(p.UEP_ACTIVE_SHA in remove, 'removal lost the active pin')
p.require(p.UEP_READONLY_SHA not in remove, 'removal permits the read-only content')
p.require(remove.rstrip('\n').endswith("printf 'GATE_ABSENT\\n'"),
          'removal tail must end with the absence assertion')
for name, text in (('install', install), ('active', active), ('remove', remove)):
    for line in text.splitlines():
        if '&& test' in line:
            p.require('|| return 1' in line, name + ' still uses a non-aborting && guard: ' + line)
    p.require('@' not in text, name + ' kept an unexpanded template marker')
    p.require(text.isascii(), name + ' is not ASCII')
results['integrity_gates'] = 'ok'

with tempfile.TemporaryDirectory(prefix='r9-agent-build-') as temp:
    command = [str(SDK / 'dotnet.exe'), 'build', str(PACK / 'UepGateAgent.csproj'),
               '-c', 'Release', '-f', 'netcoreapp3.1',
               '-p:BaseIntermediateOutputPath=' + str(Path(temp) / 'obj') + os.sep,
               '-p:OutputPath=' + str(Path(temp) / 'build') + os.sep]
    env = dict(os.environ, DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_ROOT=str(SDK))
    built = subprocess.run(command, capture_output=True, cwd=str(p.REPO), env=env)
    combined = built.stdout.decode()[-4000:] + built.stderr.decode()[-1200:]
    p.require(built.returncode == 0, 'agent build failed:\n' + combined)
    results['build'] = 'succeeded'
    warnings_summary = re.search(r'(\d+) Warning\(s\)', combined)
    p.require(warnings_summary is not None and warnings_summary.group(1) == '0',
              'agent build reported warnings:\n' + combined)
    results['warnings'] = 0
    agent_bytes = (Path(temp) / 'build' / 'SamsungTvRootAgent.dll').read_bytes()
    for name in ('gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh'):
        p.require(name.encode('ascii') in agent_bytes, 'agent does not embed ' + name)
results['embedded_resources'] = 'ok'

for name in ('stage.sh', 'snapshot.sh', 'gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh'):
    path = PACK / name
    parsed = subprocess.run([r'C:\Program Files\Git\bin\bash.exe', '-n', str(path)],
                            capture_output=True)
    p.require(parsed.returncode == 0, 'bash -n failed: ' + name + ' ' + parsed.stderr.decode()[:300])
    results['bash_n_' + name] = 'ok'

ruff = subprocess.run([str(p.REPO / '.venv/Scripts/python.exe'), '-B', '-m', 'ruff', 'check',
                       '--no-cache', '--isolated', '--select', 'F821', str(PACK)],
                      capture_output=True)
p.require(ruff.returncode == 0, 'undefined names survived: ' + ruff.stdout.decode()[:1200])
results['ruff'] = 'ok'

for name in ('gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh'):
    (PACK / name).unlink()
    p.require(not (PACK / name).exists(), 'synthetic bake survived: ' + name)
results['cleanup'] = 'bake removed; build units were temp-tree only'

print(json.dumps(results, indent=1))
