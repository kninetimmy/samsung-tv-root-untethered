"""S5+S6 rehearsal (suite module): STOP / one-attempt enforcement and driver
prerequisites on synthetic receipt trees in a TEMP packet tree (p.HERE is
rebound per case and restored; the real packet directory is untouched)."""
import asyncio
import json
import shutil
import tempfile
from pathlib import Path

from driver_shim import p
import stage_lib
import disable as disable_module
import watch as watch_module
import activate as activate_module
import dirread as dirread_module

REHEARSAL_BOOT = 'a1111111-2222-3333-4444-555555555555'
COMMIT = p.DEPLOY_RECEIPT_BOOT


def make_packet_tree():
    original = p.HERE
    tmp = Path(tempfile.mkdtemp(prefix='r2-precheck-rehearsal-'))
    p.HERE = tmp
    (tmp / 'execution' / 'attempts').mkdir(parents=True)
    for name in ('deployment-result.json', 'post-deploy-verification.json',
                 'post-mortem-20261108.md', 'inspection-r1-predeploy.json',
                 'protected-register-20261108.json', 'port-proof-source.json'):
        shutil.copy2(original / name, tmp / name)
    return tmp, original


def write_status(kind, body):
    (p.HERE / ('stage-status-' + kind + '.json')).write_text(
        json.dumps(body, indent=1), encoding='utf-8')


def good_statuses():
    return {
        'watch': {'stage': 'watch', 'passed': True, 'boot': p.DEPLOY_RECEIPT_BOOT},
        'dirread': {'stage': 'dirread', 'passed': True, 'boot': p.DEPLOY_RECEIPT_BOOT},
        'active': {'stage': 'active', 'passed': True,
                   'fresh_boot': 'b1111111-2222-3333-4444-555555555555',
                   'fresh_proof_sha256': '0' * 64},
    }


def run():
    results = []

    # ---- S5: STOP enforcement
    tmp, original = make_packet_tree()
    try:
        (p.HERE / 'STOP').write_text('rehearsal stop\n', encoding='ascii')
        try:
            stage_lib.refuse_if_stopped()
            raise AssertionError('STOP file accepted')
        except p.Stop:
            results.append('STOP present: a stage refuses before any TV operation')
        (p.HERE / 'STOP').unlink()
        stage_lib.refuse_if_stopped()
        results.append('STOP absent: refuse_if_stopped permits a fresh packet')

        stage_lib.OneAttempt('LIVE_ARM_WATCH').take()
        try:
            stage_lib.OneAttempt('LIVE_ARM_WATCH').take()
            raise AssertionError('second attempt accepted')
        except p.Stop:
            results.append('a second invocation of the same stage refuses (attempt receipt)')
        try:
            stage_lib.OneAttempt('LIVE_ARM_DIRREAD').take()
        except p.Stop as error:
            raise AssertionError('a DIFFERENT stage must be allowed its own attempt: ' + str(error))
        results.append('per-stage attempt receipts are independent')

        (p.HERE / 'SPENT').write_text('rehearsal spent\n', encoding='ascii')
        try:
            stage_lib.refuse_if_stopped()
            raise AssertionError('SPENT accepted')
        except p.Stop:
            results.append('SPENT present: nothing replays after a terminal success')
    finally:
        p.HERE = original
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- S6: prerequisites
    tmp, original = make_packet_tree()
    try:
        original_proof = p.BOOT
        p.BOOT = p.DEPLOY_RECEIPT_BOOT
        try:
            def _assert_pop(fn, *names_missing):
                for name in names_missing:
                    path = p.HERE / name
                    if path.exists():
                        path.unlink()
                try:
                    fn()
                    raise AssertionError('expected refusal')
                except (p.Stop, FileNotFoundError):
                    pass

            statuses = good_statuses()
            for kind, body in statuses.items():
                write_status(kind, body)
            dirread_module.prerequisites()
            results.append('dirread prerequisites pass on the good chain')
            activate_module.prerequisites()
            results.append('active prerequisites pass on the dirread receipt')
            fresh, digest = disable_module.prerequisites()
            p.require(fresh == 'b1111111-2222-3333-4444-555555555555', 'fresh boot misread')
            results.append('disable prerequisites pass and bind fresh_boot + proof digest')

            # None fresh_boot: the r1 acceptance bug
            statuses['active']['fresh_boot'] = None
            write_status('active', statuses['active'])
            _assert_pop(disable_module.prerequisites)
            results.append('fresh_boot None refuses (r1 accepted a missing receipt)')

            statuses['active']['fresh_boot'] = 'not-a-boot-id'
            write_status('active', statuses['active'])
            _assert_pop(disable_module.prerequisites)
            results.append('malformed fresh_boot refuses')

            write_status('active', good_statuses()['active'])
            statuses['active']['fresh_proof_sha256'] = 'deadbeef'
            write_status('active', statuses['active'])
            _assert_pop(disable_module.prerequisites)
            results.append('missing/malformed fresh proof digest refuses')

            write_status('active', good_statuses()['active'])
            statuses['dirread']['passed'] = False
            write_status('dirread', statuses['dirread'])
            _assert_pop(activate_module.prerequisites)
            _assert_pop(disable_module.prerequisites)
            results.append('a failed dirread receipt blocks both active and disable')

            (p.HERE / 'stage-status-active.json').unlink()
            _assert_pop(disable_module.prerequisites)
            results.append('a missing active receipt blocks disable')

            write_status('dirread', good_statuses()['dirread'])
            # wrong stage kind
            write_status('dirread', {'stage': 'watch', 'passed': True})
            _assert_pop(activate_module.prerequisites)
            results.append('a wrong-stage receipt refuses (stage kind checked)')

            write_status('dirread', good_statuses()['dirread'])
            # boot mismatch vs the deploy receipt
            dirread = {'stage': 'dirread', 'passed': True, 'boot': 'cccccccc-2222-3333-4444-555555555555'}
            write_status('dirread', dirread)
            _assert_pop(activate_module.prerequisites)
            results.append('a dirread receipt bound to another boot refuses')

            write_status('dirread', good_statuses()['dirread'])
            # watch prerequisites need r1 provenance receipts
            (p.HERE / 'post-mortem-20261108.md').unlink()
            _assert_pop(watch_module.prerequisites)
            results.append('missing r1 provenance receipts refuse at stage 2')
        finally:
            p.BOOT = original_proof
    finally:
        p.HERE = original
        shutil.rmtree(tmp, ignore_errors=True)
    return results
