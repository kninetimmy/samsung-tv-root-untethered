"""S4 baseline rehearsal (suite module): the corrected per-path 25-file
mapping passes; each drift refuses; the r1-style 23-file blob reply refuses
now (differential for the bug that burned r1's stage-1 closeout)."""
import asyncio
import base64
import json

from driver_shim import p
import deploy

REHEARSAL_BOOT = 'a1111111-2222-3333-4444-555555555555'


def build_model():
    r1 = json.loads((p.HERE / 'inspection-r1-predeploy.json').read_text(encoding='utf-8'))
    document = json.loads((p.HERE / 'port-proof-source.json').read_text(encoding='utf-8'))
    modelled = dict(r1)
    modelled['boot'] = REHEARSAL_BOOT
    modelled['hash'] = p.NEW_SHA + '  ' + p.TARGET
    modelled['fdet_home'] = 'present'
    modelled['ip'] = r1['ip']
    modelled['mode'] = r1['mode']
    modelled['pairing_hash'] = r1['pairing_hash']
    modelled['unit'] = r1['unit']
    modelled['startup'] = r1['startup']
    return modelled, document


def replies_for(expected, proof_sha, modelled):
    return {
        'current-boot': 'uid=901\nboot=' + REHEARSAL_BOOT + '\nip=' + modelled['ip']
                        + '\nmode=' + modelled['mode'],
        'protected-hashes': '\n'.join(expected[path] + '  ' + path for path in sorted(expected)),
        'manager-hash': p.NEW_SHA + '  ' + p.TARGET,
        'bridge-active': 'active',
        'proof-hash': proof_sha + '  ' + p.EV + '/selfroot-proof.txt',
        'pairing-hash': modelled['pairing_hash'],
        'service-unit': modelled['unit'],
        'startup': modelled['startup'],
        'port-config': 'absent',
    }


def run():
    results = []
    modelled, document = build_model()
    proof_sha = document['proof_sha256']
    expected = dict(p.INHERITED)   # the rehearsal model of the r2 register

    deployment = deploy.Deployment(None, lambda *args, **kwargs: None, REHEARSAL_BOOT, proof_sha)
    replies = replies_for(expected, proof_sha, modelled)

    original_expected_set = p.expected_set
    original_inspection = deploy.INSPECTION
    p.expected_set = lambda: expected
    deploy.INSPECTION = modelled
    try:
        async def baseline(source_replies):
            async def read(label, command):
                return source_replies[label]
            deployment.read = read
            await deployment.baseline()

        asyncio.run(baseline(replies))
        results.append('correct per-path baseline over the 25-file set passes '
                       '(with boot and proof as stage parameters)')

        replies_drift = dict(replies)
        drift_path = sorted(expected)[3]
        old_hash = expected[drift_path]
        new_hash = ('0' * 64) if old_hash[0] != '0' else ('f' * 64)
        replies_drift['protected-hashes'] = '\n'.join(
            (new_hash if path == drift_path else expected[path]) + '  ' + path
            for path in sorted(expected))
        try:
            asyncio.run(baseline(replies_drift))
            raise AssertionError('drift accepted')
        except p.Stop:
            results.append('protected-file drift refuses (' + drift_path.rsplit('/', 1)[1] + ')')

        replies_few = dict(replies)
        short = sorted(expected)[:-1]
        replies_few['protected-hashes'] = '\n'.join(expected[pth] + '  ' + pth for pth in short)
        try:
            asyncio.run(baseline(replies_few))
            raise AssertionError('short response accepted')
        except p.Stop:
            results.append('a short hash response refuses (count mismatch)')

        replies_mgr = dict(replies)
        replies_mgr['manager-hash'] = p.OLD_SHA + '  ' + p.TARGET
        try:
            asyncio.run(baseline(replies_mgr))
            raise AssertionError('manager drift accepted')
        except p.Stop:
            results.append('manager hash drift refuses (pinned v5.18 only)')

        blob = base64.b64decode(modelled['hashes'].encode()).decode().strip()
        replies_blob = dict(replies)
        replies_blob['protected-hashes'] = blob
        try:
            asyncio.run(baseline(replies_blob))
            raise AssertionError('blob reply accepted')
        except p.Stop:
            results.append('DIFFERENTIAL r1: the 23-file blob reply now refuses '
                           '(the stage-1 closeout bug cannot recur silently)')
    finally:
        p.expected_set = original_expected_set
        deploy.INSPECTION = original_inspection
    return results
