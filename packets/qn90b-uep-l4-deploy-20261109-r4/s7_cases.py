"""Gate evidence and real manager timestamps, including rejection checks that must fail on acceptance."""
from datetime import datetime
from pytest import raises

from driver_shim import p
from stage_lib import gate_event_assessment, gate_stamp_seconds

TS = '[2026-11-09T01:02:03.1234567Z] '
TS2 = '[2026-11-09T02:02:03.1234567Z] '
ABSENT = TS + 'uep gate (boot): config absent (enforcing; no action)'
REOPEN = TS + 'uep gate (reopen): config absent (enforcing; no action)'
READONLY_SUM = TS + 'uep gate (boot): read-only: enforcing'
READONLY_DET = TS + 'uep gate: read-only boot: enforcing ' + p.FINGERPRINT + ' (zero stores)'
CLEARED_SUM = TS2 + 'uep gate (boot): cleared (boot)'
CLEARED_DET = TS2 + 'uep gate: cleared boot: ' + p.CLEARED + ' (one word, neighbourhood pinned)'
FOREIGN = TS + 'uep gate (boot): unexpected config (fail closed)'
EXCEPTION = TS + 'uep gate EXCEPTION RuntimeError: gate exploded'
MALFORMED = 'not a timestamped line uep gate (boot): config absent (enforcing; no action)'


def epoch(text):
    return datetime.fromisoformat(text.replace('Z', '+00:00')).timestamp()


def run():
    results = []
    window = dict(boot_epoch=epoch('2026-11-09T00:00:00Z'),
                  epoch_at_fetch=epoch('2026-11-09T03:00:00Z'))
    gate_event_assessment([ABSENT, REOPEN], 'watch', **window)
    results.append('watch accepts real fractional timestamps without sampling pids')
    for name, lines in (
        ('foreign event', [ABSENT, FOREIGN]),
        ('malformed timestamp', [ABSENT, MALFORMED]),
        ('gate exception', [ABSENT, EXCEPTION]),
        ('no gate events', []),
    ):
        with raises(p.Stop):
            gate_event_assessment(lines, 'watch', **window)
        results.append('watch refuses ' + name)
    gate_event_assessment([], 'watch', needle_required=False, **window)
    results.append('an observation poll may have no gate events yet')
    gate_event_assessment([READONLY_SUM, READONLY_DET], 'dirread', **window)
    results.append('read-only requires both summary and pinned fingerprint detail')
    for lines in ([READONLY_SUM], [READONLY_DET], [READONLY_SUM, READONLY_DET, ABSENT]):
        with raises(p.Stop):
            gate_event_assessment(lines, 'dirread', **window)
    results.append('read-only refuses incomplete evidence and a conflicting fresh event')
    active_window = dict(boot_epoch=epoch('2026-11-09T02:00:00Z'),
                         epoch_at_fetch=window['epoch_at_fetch'])
    matched = gate_event_assessment([ABSENT, CLEARED_SUM, CLEARED_DET], 'active',
                                    regime='legacy', **active_window)
    assert matched == [CLEARED_SUM, CLEARED_DET]
    results.append('active accepts its current-boot pair and excludes older log lines')
    for lines in ([ABSENT], [CLEARED_SUM], [CLEARED_DET], [CLEARED_SUM, CLEARED_DET, FOREIGN.replace(TS, TS2)]):
        with raises(p.Stop):
            gate_event_assessment(lines, 'active', regime='legacy', **active_window)
    results.append('active refuses old absent evidence, missing pair members and foreign events')
    disable_window = dict(boot_epoch=epoch('2026-11-09T03:00:00Z'),
                          epoch_at_fetch=epoch('2026-11-09T03:10:00Z'))
    disabled = ABSENT.replace(TS, '[2026-11-09T03:02:03.1234567Z] ')
    gate_event_assessment([CLEARED_SUM, disabled], 'disable', regime='legacy', **disable_window)
    with raises(p.Stop):
        gate_event_assessment([CLEARED_SUM, CLEARED_DET], 'disable', regime='legacy', **disable_window)
    results.append('disable requires an absent-config event on its new boot')
    with raises(p.Stop):
        gate_event_assessment([CLEARED_SUM, CLEARED_DET], 'active', regime='legacy')
    results.append('legacy evidence cannot bypass the current-boot clock requirement')
    stamp = gate_stamp_seconds(ABSENT, **window)
    assert epoch('2026-11-09T01:02:03Z') < stamp < epoch('2026-11-09T01:02:04Z')
    gate_stamp_seconds(ABSENT.replace('.1234567Z', 'Z'), **window)
    results.append('timestamp parser supports round-trip and whole-second UTC stamps')
    for line, boot, fetched in (
        (ABSENT, epoch('2026-11-09T02:00:00Z'), window['epoch_at_fetch']),
        (ABSENT, window['boot_epoch'], epoch('2026-11-09T01:00:00Z')),
        (ABSENT.replace('2026-11-09', '1999-01-01'), window['boot_epoch'], window['epoch_at_fetch']),
        (ABSENT.replace('01:02:03', '09:99:03'), window['boot_epoch'], window['epoch_at_fetch']),
    ):
        with raises(p.Stop):
            gate_stamp_seconds(line, boot, fetched)
    results.append('stale, future and malformed timestamps refuse against an independent clock')
    return results
