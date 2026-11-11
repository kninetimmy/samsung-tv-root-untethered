"""r13 host-only mutation harness for the session/shell coverage.

Each entry applies one exact defect to the real packet source, runs the case
that is supposed to catch it, and requires that case to fail with the intended
assertion message (a nonzero exit for an unrelated crash does not count). The
original bytes are restored in a finally block and verified by SHA-256; any
mutant that survives or dies for the wrong reason is reported and makes this
harness exit non-zero.

No TV contact. `session` runners call the specific case function; `flow`
runners execute the full gate-script rehearsal.
"""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
VENV = REPO / '.venv/Scripts/python.exe'
BAKED = ('gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh')


class HiddenBaked:
    """Temporarily hide the live bake so flow_cases exercises the template.

    With the sealed scripts present, a mutated prepare.py is first caught by
    the sealed-vs-template equality check. Hiding the bake makes the specific
    receipt/temp case run against the mutated template, which is what the
    mutant is supposed to prove.
    """

    def __init__(self):
        self.backup = Path(tempfile.mkdtemp(prefix='r12-mutation-bake-'))
        self.saved = {}

    def __enter__(self):
        for name in BAKED:
            source = HERE / name
            if source.is_file():
                copy = self.backup / name
                shutil.copy2(source, copy)
                self.saved[name] = (copy, hashlib.sha256(copy.read_bytes()).hexdigest())
                source.unlink()
        return self

    def __exit__(self, exc_type, exc, tb):
        for name, (copy, digest_value) in self.saved.items():
            target = HERE / name
            shutil.copy2(copy, target)
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest_value:
                raise SystemExit('bake restoration digest mismatch: ' + name)
        shutil.rmtree(self.backup, ignore_errors=True)
        return False

# name, file, old, new, runner (module:function or 'flow'), reason, expected message
MUTANTS = [
    ('state-tmp-key-dropped', 'stage_common.py',
     '        "printf \'state_tmp=\'; if test -e " + p.UEP_STATE + ".tmp || test -L "',
     '        "printf \'state_tmpx=\'; if test -e " + p.UEP_STATE + ".tmp || test -L "',
     'session_checks:state_capture_contract',
     'a capture that stops emitting state_tmp must fail the command contract',
     'state capture lost'),
    ('state-tmp-check-removed', 'stage_common.py',
     "    p.require(out['state_tmp'] == 'absent',",
     "    p.require(True or out['state_tmp'] == 'absent',",
     'session_checks:state_present_temp',
     'a present budget temp path must still STOP',
     'budget temp path'),
    ('module-exit-presence-removed', 'stage_common.py',
     '            if complete and exits:',
     '            if complete:',
     'session_checks:module_gate_rejects_missing_exit',
     'a persistent missing exit line must STOP',
     'expected STOP: missing module exit line'),
    ('module-exit-nonzero-accepted', 'stage_common.py',
     "                p.require(exits[0].strip() == 'uep gate module exit=0',",
     '                p.require(True,',
     'session_checks:module_gate_rejects_nonzero_exit',
     'a nonzero module exit must STOP',
     'expected STOP: nonzero module exit'),
    ('module-exit-wait-removed', 'stage_common.py',
     '            if exits:\n'
     "                p.require(exits[0].strip() == 'uep gate module exit=0',",
     "            p.require(exits, 'the gate module exit receipt is missing; STOP')\n"
     '            if exits:\n'
     "                p.require(exits[0].strip() == 'uep gate module exit=0',",
     'session_checks:module_gate_waits_for_exit',
     'a partial first log must be polled, not STOPped',
     'gate module exit receipt is missing'),
    ('module-unexpected-immediate', 'stage_common.py',
     "            if complete and exits:\n"
     "                p.require(not unexpected, 'unexpected gate event: '\n"
     "                          + (unexpected[0][:160] if unexpected else ''))",
     "            p.require(not unexpected, 'unexpected gate event: '\n"
     "                      + (unexpected[0][:160] if unexpected else ''))\n"
     "            if complete and exits:\n"
     "                p.require(not unexpected, 'unexpected gate event: '\n"
     "                          + (unexpected[0][:160] if unexpected else ''))",
     'session_checks:module_gate_waits_for_partial_line',
     'a partial last line must not be treated as an immediate unexpected event',
     'unexpected gate event'),
    ('module-shape-check-removed', 'stage_common.py',
     '            if complete and exits:',
     '            if exits:',
     'session_checks:module_gate_rejects_missing_detail',
     'the required-shape guard must still STOP a summary-only log',
     'expected STOP: missing required detail shape'),
    ('module-content-check-removed', 'stage_common.py',
     "        p.require(out[key] == line, 'module file drift: ' + key)",
     "        p.require(True, 'module file drift: ' + key)",
     'session_checks:module_files_rejects_content',
     'a changed module byte must STOP',
     'expected STOP: module file content drift'),
    ('upload-whitelist-widened', 'sdk.py',
     '    "manager.dll",',
     '    "manager.dll",\n    "arbitrary.dll",',
     'session_checks:upload_contract',
     'an unreviewed upload name must be refused',
     'whitelist widened too far'),
    ('upload-stage-containment-removed', 'sdk.py',
     '        and str(remote.parent) == prior.STAGE',
     '        and True  # mutant: no stage containment',
     'session_checks:upload_contract',
     'an upload target outside the owned stage must be refused',
     'expected STOP: target outside the owned stage'),
    ('protected-set-keeps-runtimeconfig', 'packet.py',
     '    EXPECTED.pop(TARGET_RC, None)',
     '    pass  # mutant: keep the replaced runtimeconfig in the closeout set',
     'session_checks:protected_set',
     'the post-install set must exclude the runtimeconfig the install replaces',
     'expected protected set must be the 24-file post-install baseline'),
    ('removal-r11-guard-restored', 'prepare.py',
     "test \"$(stat -c '%F:%u:%g:%h' -- \"$state\")\" = 'regular file:0:0:1'\n"
     'receipt_sha=$(printf \'boot=%s clear=1 restore=0\\n\' "$current_boot" | sha256sum)\n'
     'test "$(hash "$state")" = "${receipt_sha%% *}"',
     "test \"$(stat -c '%F:%u:%g:%h' -- \"$state\")\" = 'regular file:0:0:1'\n"
     "grep -Eqx 'boot=[0-9a-f-]{36} clear=1 restore=0' \"$state\"",
     'flow',
     'the r11 grep guard accepts a stale receipt from another boot',
     'different boot'),
    ('removal-nul-receipt-accepted', 'prepare.py',
     "test \"$(stat -c '%F:%u:%g:%h' -- \"$state\")\" = 'regular file:0:0:1'\n"
     'receipt_sha=$(printf \'boot=%s clear=1 restore=0\\n\' "$current_boot" | sha256sum)\n'
     'test "$(hash "$state")" = "${receipt_sha%% *}"',
     "test \"$(stat -c '%F:%u:%g:%h' -- \"$state\")\" = 'regular file:0:0:1'\n"
     'test "$(wc -l < "$state")" -eq 1\n'
     'grep -Fxq "boot=$current_boot clear=1 restore=0" "$state"',
     'flow',
     'a wc/grep guard accepts an LF+NUL padded receipt',
     'NUL-padded receipt'),
    ('removal-multiline-first-line', 'prepare.py',
     "test \"$(stat -c '%F:%u:%g:%h' -- \"$state\")\" = 'regular file:0:0:1'\n"
     'receipt_sha=$(printf \'boot=%s clear=1 restore=0\\n\' "$current_boot" | sha256sum)\n'
     'test "$(hash "$state")" = "${receipt_sha%% *}"',
     "test \"$(stat -c '%F:%u:%g:%h' -- \"$state\")\" = 'regular file:0:0:1'\n"
     'test "$(head -n 1 "$state")" = "boot=$current_boot clear=1 restore=0"',
     'flow',
     'a first-line-only guard accepts a multiline receipt',
     'multiline receipt'),
    ('temp-guard-removed', 'prepare.py',
     'test ! -e "$state.tmp"\ntest ! -L "$state.tmp"',
     '',
     'flow',
     'a planted budget temp path must be refused before the install/activation write',
     'planted budget temp path'),
    ('stage-absence-check-removed', 'stage.sh',
     '    if absent "$name"; then test "$action" = clean && test "$started" = 0 || exit 1; continue; fi',
     '    if absent "$name"; then continue; fi',
     'session_checks:stage_sh_rejects_missing',
     'an absent manifest-listed file must stop publish',
     'manifest entry that is absent'),
    ('stage-eof-skip', 'stage.sh',
     'while read -r hash name || test -n "$hash"; do',
     'while read -r hash name; do',
     'session_checks:stage_sh_rejects_unterminated',
     'a final row without a newline must still be verified',
     'unverified final row'),
    ('protected-order-check-removed', 'stage_lib.py',
     "        p.require(path == requested_path, 'hash output does not follow the requested path order: ' + line[:120])",
     '        pass',
     'session_checks:protected_closeout_rejects_order_synthetic',
     'a reordered response with duplicate digests must still STOP',
     'expected STOP: hash output did not follow the requested path order'),
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_case(runner):
    if runner == 'flow':
        code = ('import sys; sys.path.insert(0, "."); '
                'import flow_cases; flow_cases.run()')
        with HiddenBaked():
            return subprocess.run([str(VENV), '-B', '-c', code],
                                  capture_output=True, cwd=str(HERE))
    module, function = runner.split(':')
    code = ('import sys; sys.path.insert(0, "."); '
            'import stage_lib; stage_lib.save = lambda *a, **k: None; '
            'import ' + module + ' as m; m.' + function + '()')
    return subprocess.run([str(VENV), '-B', '-c', code],
                          capture_output=True, cwd=str(HERE))


def main():
    results = []
    for name, filename, old, new, runner, reason, expected in MUTANTS:
        path = HERE / filename
        original = path.read_bytes()
        original_digest = hashlib.sha256(original).hexdigest()
        text = original.decode('utf-8')
        count = text.count(old)
        if count < 1:
            raise SystemExit('mutant ' + name + ' did not match ' + filename)
        try:
            path.write_bytes(text.replace(old, new).encode('utf-8'))
            outcome = run_case(runner)
        finally:
            path.write_bytes(original)
            if digest(path) != original_digest:
                raise SystemExit('restoration digest mismatch: ' + filename)
        output = (outcome.stdout.decode('utf-8', 'replace')
                  + outcome.stderr.decode('utf-8', 'replace'))
        failed = outcome.returncode != 0
        matched = failed and expected.lower() in output.lower()
        results.append({
            'name': name, 'file': filename, 'runner': runner,
            'reason': reason, 'expected': expected,
            'killed': matched, 'exit': outcome.returncode,
            'diagnostic': output[-700:],
        })
        print(('KILLED ' if matched else 'WRONG-REASON ' if failed else 'SURVIVED ')
              + name, flush=True)
    survived = [item for item in results if not item['killed']]
    record = {
        'runner': 'mutation_checks.py', 'tv_operations': 0,
        'mutants': len(results), 'killed': len(results) - len(survived),
        'survived': [item['name'] for item in survived],
        'verdict': 'PASSED' if not survived else 'FAILED',
        'cases': results,
    }
    (HERE / 'mutation-results.json').write_text(
        json.dumps(record, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({key: value for key, value in record.items() if key != 'cases'}))
    return 0 if not survived else 1


if __name__ == '__main__':
    sys.exit(main())
