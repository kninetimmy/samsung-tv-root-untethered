"""Shared stage machinery for the L4 stage 2-5 drivers (r2).

Every driver: verifies its marker and prerequisite stage status, REFUSES while
a STOP file exists, records one exclusive local attempt before any TV work,
keeps ALL remote commands inside SDK-staging + root-agent guarded writes,
receipts every SDK conversation into the packet's receipts.jsonl, and consumes
its marker only after a terminal success receipt. Any exception outside an
explicit bounded scenario path writes the durable failure state itself
(status file + STOP) before being raised. Importing this module performs no
TV operations.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone
from shlex import quote

sys.dont_write_bytecode = True
import packet as p
from inspect_tv import save

SUID = '901'
TARGET_HASH = p.NEW_MANAGER_SHA
UEP_STATE = p.UEP_STATE
# Log line shapes produced by the v5.19 root host (UepGateHost.cs):
#   uep gate (<phase>) uid=0: <summary>   phase = boot | manual
#   uep gate: <log text>                  detail lines; absent path logs none.
ABSENT_SUMMARY = re.compile(r'uep gate \((?:boot|manual)\) uid=0: config absent \(enforcing; no action\)$')
READONLY_SUMMARY = re.compile(r'uep gate \((?:boot|manual)\) uid=0: read-only: enforcing$')
READONLY_DETAIL = re.compile(r'uep gate: read-only (?:boot|manual): enforcing '
                             + re.escape(p.FINGERPRINT) + r' \(zero stores\)$')
CLEARED_SUMMARY = re.compile(r'uep gate \(boot\) uid=0: cleared \(boot\)$')
CLEARED_DETAIL = re.compile(r'uep gate: cleared boot: ' + re.escape(p.CLEARED) +
                            r' \(one word, neighbourhood pinned\)$')
GATE_EVENT_SHAPES = {
    'install': (READONLY_SUMMARY, READONLY_DETAIL),
    'active': (CLEARED_SUMMARY, CLEARED_DETAIL),
    'disable': (ABSENT_SUMMARY,),
}


def log(event, **data):
    save(event, **data)


def refuse_if_stopped(standalone_marker_only=False):
    """No stage, retry, or replay may pass a STOP under any standing marker."""
    p.require(not (p.HERE / 'STOP').is_file(),
              'the packet is stopped permanently (STOP present); never replay')
    p.require(not (p.HERE / 'SPENT').is_file(),
              'the packet is spent; never replay')


def protect_seal():
    deploy_seal = p.HERE / 'seal.json'
    p.require(deploy_seal.is_file(), 'seal.json missing; the sealed packet is not consumable')
    seal = json.loads(deploy_seal.read_text(encoding='utf-8'))
    # r10 M4: the manifest must be exactly the reviewed entry set. r9 hashed
    # whatever names the file happened to contain, so an empty or trimmed
    # manifest passed the live integrity gate.
    p.require(sorted(seal) == sorted(p.SEAL_ENTRIES),
              'sealed manifest is not the reviewed ' + str(len(p.SEAL_ENTRIES)) + '-entry set')
    for name in p.SEAL_ENTRIES:
        p.require(p.digest(p.HERE / name) == seal[name], 'sealed packet changed: ' + name)
    p.require(p.digest(p.TOOLS_DIR / 'packet.py') == p.TOOLS_SHA,
              'inherited controller changed after the seal')
    p.require(p.digest(p.TOOLS_DIR / 'baseline.json') == p.BASELINE_SHA,
              'inherited controller baseline changed after the seal')
    p.tools.local_checks()


def marker_for(stage):
    p.require(p.marker(stage) is True,
              'explicit ' + stage + ' approval is not standing; refuse no touch')
    p.require(repo_head() == p.COMMIT, 'source head changed while the marker stood')
    refuse_if_stopped()


def repo_head():
    import subprocess
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=p.REPO).decode().strip()


class OneAttempt:
    """Exclusive local attempt receipt; a second invocation of any stage in
    this packet directory refuses before constructing its SDK session.

    The receipt lives under execution/attempts/, separate from the marker so a
    failed attempt cannot be masked by re-arming: the attempt stamp alone
    blocks the retry, and only the dedicated cleanup entrypoint may move an
    abandoned attempt aside (kept for evidence)."""

    def __init__(self, stage):
        self.path = p.HERE / 'execution' / 'attempts' / (stage + '.attempt')
        self.taken = False

    def take(self):
        if self.taken:
            return
        p.require(not self.path.exists(),
                  'an earlier attempt of this stage exists; the packet is one attempt per stage; STOP')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open('x', encoding='utf-8') as stream:
            stream.write(datetime.now(timezone.utc).isoformat() + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        self.taken = True


def fields(text):
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        p.require(sep and key not in result, 'malformed capture: ' + key[:40])
        result[key] = value
    return result


def gate_stamp_seconds(line, boot_epoch, epoch_at_fetch):
    match = re.match(r'^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z)\] ', line)
    p.require(match is not None, 'gate line has no parseable timestamp envelope: ' + line[:120])
    try:
        stamp = datetime.fromisoformat(match[1].replace('Z', '+00:00')).timestamp()
    except ValueError as error:
        raise p.Stop('invalid gate timestamp: ' + match[1]) from error
    p.require(stamp >= boot_epoch - 5, 'a pre-boot gate line cannot serve as boot evidence: ' + line[:120])
    p.require(stamp <= epoch_at_fetch + 5, 'gate line is timestamped in the future: ' + line[:120])
    return stamp


async def boot_clock(sdk):
    out = fields(await capture(sdk, 'boot-clock',
                               "printf 'epoch='; date +%s\nprintf 'uptime='; cat /proc/uptime\n"))
    epoch = int(out['epoch'])
    uptime = float(out['uptime'].split()[0])
    started = epoch - int(uptime)
    p.require(started > 0, 'boot clock reasoning failed')
    log('boot-clock-verified', boot_epoch=started, uptime=uptime)
    return started, epoch


async def sdk_state(sdk, label='state'):
    out = fields(await capture(sdk, 'state', (
        "printf 'uid='; id -u\n"
        "printf 'boot='; cat /proc/sys/kernel/random/boot_id\n"
        "printf 'service='; systemctl is-active tvroot-bridge.service\n"
        "printf 'target_hash='; sha256sum " + p.TARGET + "\n"
        "printf 'proof_hash='; sha256sum " + p.EV + "/selfroot-proof.txt\n"
        "printf 'log_size='; stat -c %s " + p.EV + "/agent.log\n"
        "printf 'manager_pids='; pgrep -f '/com[.]samsung[.]tv[.]ghservice[.]dll' | tr '\\n' ','; echo\n"
        "printf 'gate_config='; if test -e " + p.UEP_CONFIG + " || test -L " + p.UEP_CONFIG + "; then echo present; else echo absent; fi\n"
        "printf 'gate_state='; if test -e " + UEP_STATE + " || test -L " + UEP_STATE + "; then echo present; else echo absent; fi\n"
        "printf 'port_config='; if test -e /opt/usr/share/selfroot/bridge-port.conf || test -L /opt/usr/share/selfroot/bridge-port.conf; then echo present; else echo absent; fi\n"
    )))
    p.require(out['uid'] == SUID, 'SDK identity mismatch')
    p.require(out['service'] == 'active', 'bridge inactive')
    p.require(out['target_hash'] == TARGET_HASH + '  ' + p.TARGET,
              'installed manager drifted from ' + 'v5.18; STOP')
    p.require(out['gate_config'] in ('absent', 'present'), 'malformed gate capture')
    p.require(out['gate_state'] in ('absent', 'present'), 'malformed gate-state capture')
    p.require(out['port_config'] == 'absent', 'management port configuration changed; STOP')
    log(label + '-state', **out)
    return out


async def protected_hashes(sdk, expected=None):
    command = ('sha256sum ' + ' '.join(map(quote, (expected if expected is not None else p.expected_set()))))
    out = await capture(sdk, 'protected-hashes', command)
    paths = command.split()[1:]
    # r11: an extra output line must not be silently ignored by zip(); the
    # response must be exactly one line per requested path.
    p.require(len(out.splitlines()) == len(paths), 'protected hash response count mismatch')
    got = {}
    for line, requested_path in zip(out.splitlines(), paths):
        digest, sep, path = line.partition('  ')
        p.require(sep and re.fullmatch(r'[0-9a-f]{64}', digest), 'malformed hash line: ' + line[:60])
        p.require(path == requested_path, 'hash output does not follow the requested path order: ' + line[:120])
        got[path] = digest
    p.require(len(got) == len(paths), 'protected hash response count mismatch')
    baseline = expected if expected is not None else p.expected_set()
    p.require(set(got) == set(baseline), 'protected path set changed; STOP')
    drift = [path for path in baseline if got[path] != baseline[path]]
    p.require(not drift, 'protected file drift: ' + str(drift[:4]))
    log('protected-hashes-verified', count=len(baseline))
    return got


async def capture(sdk, label, command):
    save('sdk-request', name=label, command=command)
    code, output = await sdk.capture(command)
    save('sdk', name=label, command=command, exit=code)
    p.require(code == 0, label + ' refused or failed: ' + output[:200])
    return output


async def agent_log_lines(sdk, count=80):
    out = await capture(sdk, 'agent-log-tail',
                        'tail -n ' + str(int(count)) + ' -- ' + p.EV + '/agent.log')
    for line in out.splitlines():
        p.require(len(line) <= 2000, 'agent log line exceeds receipt bound')
    return out.splitlines()


async def agent_log_lines_from_offset(sdk, offset_bytes):
    """Log lines written strictly after this byte offset: session-fresh evidence.

    tail -c +N emits from byte N (1-based). A partial line at the cut (a line
    that does not begin the documented `[` timestamp envelope) is dropped.
    """
    out = await capture(sdk, 'agent-log-tail-from',
                        'tail -c +' + str(int(offset_bytes) + 1) + ' -- ' + p.EV + '/agent.log')
    lines = out.splitlines()
    if lines and not lines[0].startswith('['):
        lines = lines[1:]
    for line in lines:
        p.require(len(line) <= 2000, 'agent log line exceeds receipt bound')
    return lines


def gate_lines(lines, needle_text):
    found = [line for line in lines if 'uep gate ' in line and 'uep gate EXCEPTION' not in line]
    exact = [line for line in found if needle_text in line]
    details = [line for line in lines
               if needle_text in line and not line.startswith('[')]
    return found, exact, details


KNOWN_SHAPES = (ABSENT_SUMMARY, READONLY_SUMMARY, READONLY_DETAIL, CLEARED_SUMMARY, CLEARED_DETAIL)


def gate_event_assessment(lines, stage, needle_required=True, regime='fresh',
                          boot_epoch=None, epoch_at_fetch=None):
    """Assess the gate-event lines of one freshly fetched log slice.

    Independent of any process-liveness sampling: the caller decides when a
    slice is fresh evidence and binds its acceptance to this invocation.

    regime 'fresh'  = the slice may only contain lines of THIS stage's shape
    (used for offset-fresh slices and the pre-creation log audit).
    regime 'legacy' = the slice may additionally contain any known log shape
    from the packet's earlier stages (used for whole-boot tails that
    legitimately span eras, e.g. a post-reboot tail still showing the lines
    the previous stage's gate wrote).

    A legacy slice requires the TV's current boot clock and discards older
    boots. It must still contain every required shape of THIS stage. Current
    boot exceptions or malformed gate events stop the stage for owner review.
    """
    p.require(stage in GATE_EVENT_SHAPES, 'unknown stage shape set')
    p.require(regime in ('fresh', 'legacy'), 'unknown gate evidence regime')
    p.require((boot_epoch is None) == (epoch_at_fetch is None), 'incomplete gate clock window')
    p.require(regime != 'legacy' or boot_epoch is not None, 'legacy logs require the current boot clock')
    shapes = GATE_EVENT_SHAPES[stage]
    gate = [line for line in lines if 'uep gate ' in line or 'uep gate:' in line]
    for line in gate:
        gate_stamp_seconds(line, 0, float('inf'))
    if boot_epoch is not None:
        gate = [line for line in gate if gate_stamp_seconds(line, 0, epoch_at_fetch) >= boot_epoch - 5]
    exceptions = [line for line in gate if 'uep gate EXCEPTION' in line]
    p.require(not exceptions, 'gate exception in the log slice: ' + (exceptions[0][:160] if exceptions else ''))
    universe = KNOWN_SHAPES if regime == 'legacy' else shapes
    unexpected = [line for line in gate if not any(shape.search(line) for shape in universe)]
    p.require(not unexpected, 'unexpected gate event: ' +
              (unexpected[0][:160] if unexpected else ''))
    matched = [line for line in gate if any(shape.search(line) for shape in shapes)]
    if needle_required:
        p.require(all(any(shape.search(line) for line in matched) for shape in shapes),
                  'required ' + stage + ' gate evidence is missing from the log slice')
    return matched


def record_failure(stage, status_name, kind, reason):
    for path, content in (
        (p.HERE / 'STOP', 'Stage ' + stage + ' failed; packet stops permanently (no replay).\n'),
        (p.HERE / status_name, json.dumps({
            'stage': kind, 'passed': False, 'reason': reason,
            'utc': datetime.now(timezone.utc).isoformat()}, indent=2) + '\n'),
    ):
        with path.open('w', encoding='utf-8', newline='\n') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    log('stage-failed', stage=stage, kind=kind, reason=reason)


def succeed(stage, status_name, kind, **extra):
    result = dict({'stage': kind, 'passed': True,
                   'utc': datetime.now(timezone.utc).isoformat()}, **extra)
    (p.HERE / status_name).write_text(json.dumps(result, indent=2) + chr(10), encoding='utf-8', newline=chr(10))
    log('stage-passed', stage=stage, kind=kind)
    p.clear_marker(stage)
    return result
