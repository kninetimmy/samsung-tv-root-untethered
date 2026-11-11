"""r15 host-only authoring verification: real bake, gates, build and syntax.

Bakes the three scripts with production constants (the live bake after the
inspection is byte-identical: no boot pin is baked), compiles UepGateAgent with
the pinned SDK into a temp tree, checks zero warnings, verifies the embedded
resources and script algebra, runs bash -n and ruff F821. The digest-carried
production bake stays byte-identical; only temporary bake/build trees expire.
No prepare.py entrypoint, probe or TV operation.
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
    results['existing_bake_verified'] = True

baked = {}
with tempfile.TemporaryDirectory(prefix='r15-authoring-bake-') as temp_bake:
    baked.update(prepare.bake_install(Path(temp_bake)))
    baked.update(prepare.bake_active(Path(temp_bake)))
    baked.update(prepare.bake_remove(Path(temp_bake)))
    for name, text in baked.items():
        p.require((PACK / name).read_text(encoding='ascii') == text,
                  'carried production bake differs from real template: ' + name)
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

# M3 ground truth: the receipt constants are tied to the C# that emits them, not
# just to another packet-owned expectation.
uep_gate = (p.REPO / 'boot-agent/UepGate.cs').read_text(encoding='utf-8')
p.require('return "read-only: " + classification;' in uep_gate,
          'UepGate.cs no longer returns the fingerprint-free read-only summary')
p.require('Log("read-only " + phase + ": " + classification + " " + Fingerprint(words) + " (zero stores)");'
          in uep_gate, 'UepGate.cs read-only detail line changed')
p.require('return "config absent (enforcing; no action)";' in uep_gate,
          'UepGate.cs absent-config summary changed')
p.require('return "cleared (" + phase + ")";' in uep_gate,
          'UepGate.cs cleared summary changed')
host_source = (p.REPO / 'boot-agent/uep-gate-host/UepGateHost.cs').read_text(encoding='utf-8')
p.require('output.WriteLine("uep gate (" + options.Phase + ") uid=" + ReadUid()' in host_source
          and '": " + summary);' in host_source,
          'UepGateHost.cs no longer wraps the gate summary in the receipt line')
results['receipt_ground_truth'] = 'ok'

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

results['cleanup'] = 'carried bake retained byte-identically; synthetic bake/build were temp-tree only'
results['passed'] = len([key for key in results if key not in ('warnings', 'cleanup')])
results['failed'] = 0
results['skipped'] = 0

print(json.dumps(results, indent=1))
