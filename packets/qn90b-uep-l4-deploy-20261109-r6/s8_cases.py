"""S8 static asserts (suite module): agent capability wiring, csproj resources,
no boot pin in the baked remove script, no live deploy entrypoint, transport
byte-identity with r1's qualified files, artifact digest pins."""
import hashlib
import re

from driver_shim import p
import prepare

PACK = p.HERE
R1 = p.HERE.parents[0] / 'qn90b-uep-l4-deploy-20261108-r1'


def run():
    results = []
    from pathlib import Path
    cs = (PACK / 'BridgeRepairAgent.cs').read_text(encoding='utf-8')
    p.require('gate-remove:' in cs, 'the agent lacks the boot-parameterized remove op')
    p.require(cs.count('"gate-remove"') == 1 and 'gate-remove requires the boot parameter' in cs,
              'the plain gate-remove command must be rejected by the agent')
    p.require('phase1-snapshot' in cs, 'the agent lost the snapshot op')
    for op in ('"manager-apply"', '"manager-status"', '"manager-rollback"', '"fdet-install"'):
        p.require(op not in cs, 'the r2 agent still embeds a dead deploy op: ' + op)
    results.append('agent ops trimmed to phase1-snapshot + gate ops; '
                   'remove requires the boot parameter; plain remove rejected')

    csproj = (PACK / 'BridgeRepairAgent.csproj').read_text(encoding='utf-8')
    resources = re.findall(r'EmbeddedResource Include="([^"]+)"', csproj)
    p.require(sorted(resources) == ['gate-active.sh', 'gate-readonly.sh', 'gate-remove.sh', 'snapshot.sh'],
              'csproj resources drift: ' + repr(resources))
    results.append('csproj embeds exactly snapshot.sh + the three gate scripts')

    import tempfile
    work = Path(tempfile.mkdtemp(prefix='r2-s8-'))
    grown = prepare.bake_gate_packet('b1111111-2222-3333-4444-555555555555', '_', work)
    try:
        remove_body = grown['gate-remove.sh']
        p.require('boot_id' not in remove_body, 'the remove script still carries a boot pin')
        for name in ('gate-readonly.sh', 'gate-active.sh'):
            p.require(re.search(r"boot_id" + r'', grown[name]) is not None,
                      name + ' lost its boot pin')
        p.require('/proc/sys/kernel/random/boot_id' in grown['gate-readonly.sh'],
                  'readonly script lost the boot assertion line')
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    results.append('baked gate scripts: remove carries no boot pin; the create/replace scripts keep theirs')

    deploy_source = (PACK / 'deploy.py').read_text(encoding='utf-8')
    p.require('asyncio.run' not in deploy_source and "__main__" not in deploy_source,
              'deploy.py must not grow a live entrypoint again')
    results.append('deploy.py is library-only: no live deploy entrypoint')

    stage1 = __import__('pathlib').Path(PACK / 'stage.sh')
    import pathlib
    stage1 = pathlib.Path(PACK / 'stage.sh')
    r1_stage = pathlib.Path(R1 / 'stage.sh')
    p.require(stage1.read_bytes() == r1_stage.read_bytes(), 'stage.sh drifted from r1')
    r1_snapshot = pathlib.Path(R1 / 'snapshot.sh')
    p.require((PACK / 'snapshot.sh').read_bytes() == r1_snapshot.read_bytes(),
              'snapshot.sh drifted from r1')
    results.append('transport scripts are byte-identical to r1 (stage.sh, snapshot.sh)')

    for name, expected in p.ARTIFACT_SHAS.items():
        got = hashlib.sha256((p.HERE / name).read_bytes()).hexdigest()
        p.require(got == expected, 'artifact drift: ' + name)
    results.append('all five stage-1 artifact digests still match the pinned values')

    markers = set(p.MARKERS)
    p.require('LIVE_ARM_DEPLOY' not in markers, 'r2 must not re-arm the spent deploy stage')
    p.require(markers == {'LIVE_ARM_WATCH', 'LIVE_ARM_DIRREAD', 'LIVE_ARM_ACTIVE', 'LIVE_ARM_DISABLE'},
              'marker set drift')
    results.append('marker set: redeploy excluded; watch/dirread/active/disable only')

    plan = (PACK / 'PLAN.md').read_text(encoding='utf-8')
    for token in ('| 1 |', '| 2 |', '| 3 |', '4a', '4b', '4c', '4d', '| 5 |', '| 6 |', '| 7 |'):
        num = token.strip('| ').replace('|', '')
        p.require(token in plan, 'PLAN.md lacks review mapping for finding ' + num)
    results.append('PLAN.md maps every review finding to its repair')
    return results
