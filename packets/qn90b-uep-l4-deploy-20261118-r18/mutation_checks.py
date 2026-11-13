"""r14 host-only mutation harness for the session/shell coverage.

Each entry applies one exact defect to the real packet source, runs the case
that is supposed to catch it, and requires that case to fail with the intended
assertion message on the terminal exception line (a nonzero exit from an
unrelated crash, or a source line displayed in the traceback, does not count).
The original bytes are restored in a finally block and verified by SHA-256; any
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

import driver_shim

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
     '            if complete and exits and exit_complete:',
     '            if complete:',
     'session_checks:module_gate_rejects_missing_exit',
     'a persistent missing exit line must STOP',
     'expected STOP: missing module exit line'),
    ('module-exit-nonzero-accepted', 'stage_common.py',
     "                    p.require(exits[0].strip() == 'uep gate module exit=0',",
     '                    p.require(True,',
     'session_checks:module_gate_rejects_nonzero_exit',
     'a nonzero module exit must STOP',
     'expected STOP: nonzero module exit'),
    ('module-exit-wait-removed', 'stage_common.py',
     '            if exits:\n'
     '                exit_complete = (exits[0] is not lines[-1]) or ends_with_newline',
     "            p.require(exits, 'the gate module exit receipt is missing; STOP')\n"
     '            if exits:\n'
     '                exit_complete = (exits[0] is not lines[-1]) or ends_with_newline',
     'session_checks:module_gate_waits_for_exit',
     'a partial first log must be polled, not STOPped',
     'gate module exit receipt is missing'),
    ('module-unexpected-immediate', 'stage_common.py',
     "            if complete and exits and exit_complete:\n"
     "                p.require(not unexpected, 'unexpected gate event: '\n"
     "                          + (unexpected[0][:160] if unexpected else ''))",
     "            p.require(not unexpected, 'unexpected gate event: '\n"
     "                      + (unexpected[0][:160] if unexpected else ''))\n"
     "            if complete and exits and exit_complete:\n"
     "                p.require(not unexpected, 'unexpected gate event: '\n"
     "                          + (unexpected[0][:160] if unexpected else ''))",
     'session_checks:module_gate_waits_for_partial_line',
     'a partial last line must not be treated as an immediate unexpected event',
     'unexpected gate event'),
    ('module-exit-partial-terminal', 'stage_common.py',
     '                exit_complete = (exits[0] is not lines[-1]) or ends_with_newline',
     '                exit_complete = True',
     'session_checks:module_gate_waits_for_partial_exit',
     'a partial exit suffix must stay pending until the line completes',
     'the gate module exited non-zero'),
    ('module-exception-format-removed', 'stage_common.py',
     "            exceptions = [line for line in unexpected\n"
     "                          if re.search(r'uep gate(?: \\([^)]+\\))? EXCEPTION ', line)]",
     "            exceptions = [line for line in unexpected\n"
     "                          if 'uep gate EXCEPTION' in line]",
     'session_checks:module_gate_rejects_exception',
     'the host\'s real "uep gate (boot) EXCEPTION" format must take the fast path',
     'expected STOP: gate exception in the log'),
    ('module-shape-check-removed', 'stage_common.py',
     '            if complete and exits and exit_complete:',
     '            if exits and exit_complete:',
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


# r15: mutate the real command generator, real driver ordering and closeout.
# Each runner executes that production source, not a parallel command template.
RELAY_GUARDS = [
    ('directory-mode', 'test "$(stat -c \'%F:%u:%a\' .)" = \'directory:901:700\' || refuse \'relay directory owner or mode changed\''),
    ('directory-owner', 'test "$(stat -c \'%F:%u:%a\' .)" = \'directory:901:700\' || refuse \'relay directory owner or mode changed\''),
    ('file-mode', 'test "$(stat -c \'%u:%a:%h\' "$file")" = \'901:600:1\' || refuse \'relay child metadata changed\''),
    ('file-owner', 'test "$(stat -c \'%u:%a:%h\' "$file")" = \'901:600:1\' || refuse \'relay child metadata changed\''),
    ('hardlink', 'test "$(stat -c \'%u:%a:%h\' "$file")" = \'901:600:1\' || refuse \'relay child metadata changed\''),
    ('dll-hash', 'test "$(sha256sum recovery.dll)" = \'@OLD@  recovery.dll\' || refuse \'stale relay dll hash changed\''),
    ('runtime-hash', 'test "$(sha256sum recovery.runtimeconfig.json)" = \'@RUNTIME_SHA@  recovery.runtimeconfig.json\' || refuse \'stale runtimeconfig hash changed\''),
    ('source-hash', 'test "$(sha256sum @TARGET@)" = \'@OLD@  @TARGET@\' || refuse \'source relay hash changed\''),
    ('live-pid', 'test ! -e /proc/$pid || refuse \'recorded pid still exists (live or reused)\''),
    ('listener', 'test "$listeners" = 0 || refuse \'port 26105 has a listener\''),
    ('listener6', 'test "$listeners" = 0 || refuse \'port 26105 has a listener\''),
    ('boot', 'test "$(cat /proc/sys/kernel/random/boot_id)" = \'@BOOT@\' || refuse \'stage boot changed\''),
    ('proof', 'test "$(sha256sum @PROOF@)" = \'@PROOF_SHA@  @PROOF@\' || refuse \'stage proof changed\''),
    ('uid', 'test "$(id -u)" = 901 || refuse \'SDK uid is not 901\''),
    ('pid-nul', 'test "${actual%% *}" = "${expected%% *}" || refuse \'pid file is not byte-exact\''),
    ('pid-newline', 'test "${actual%% *}" = "${expected%% *}" || refuse \'pid file is not byte-exact\''),
    ('extra', 'test "$(find . -mindepth 1 -maxdepth 1 -printf \'%f\\n\' | sort)" = \'pid\nrecovery.dll\nrecovery.runtimeconfig.json\' || refuse \'relay inventory is not the exact known shape\''),
]
for kind, guard in RELAY_GUARDS:
    MUTANTS.append(('relay-' + kind + '-accepted', 'recovery.py', guard, 'true',
                    'relay_checks:refuses_' + kind.replace('-', '_'),
                    'the real shell must refuse ' + kind + ' before unlink',
                    ('relay refusal wrote files: extra' if kind == 'extra' else 'relay refusal missing: ' + kind)))
MUTANTS.extend([
    ('relay-fresh-prerequisite-skipped', 'recovery.py',
     '    await verify_absent(factory, save, boot, proof)', '    pass',
     'relay_checks:fresh_reappearance', 'a successful removal receipt must not hide another session view',
     'fresh-session reappearance was trusted'),
    ('relay-fresh-cleanup-skipped', 'deploy.py',
     '            await recovery.verify_absent(lambda: BridgeSDK(self.save), self.save,\n'
     '                                         self.expected_boot, self.expected_proof_hash)',
     '            pass', 'relay_checks:cleanup_reappearance',
     'post-op closeout must verify absence with a fresh ordinary SDK',
     'cleanup trusted removal without a fresh-session check'),
    ('relay-active-prerequisite-skipped', 'active.py',
     '    await recovery.reconcile(lambda: BridgeSDK(save), save, BOOT, PROOF_SHA)',
     '    pass', 'relay_checks:before_attempt', 'active must reconcile before taking an attempt',
     'relay prerequisites must refuse before attempt: active'),
    ('relay-disable-prerequisite-skipped', 'disable.py',
     '    await recovery.reconcile(lambda: BridgeSDK(save), save, BOOT, PROOF_SHA)',
     '    pass', 'relay_checks:before_attempt', 'disable must reconcile before taking an attempt',
     'relay prerequisites must refuse before attempt: disable'),
    ('inherited-install-digest-skipped', 'active.py',
     '    p.require(p.digest(path) == p.INHERITED_INSTALL_SHA,', '    p.require(True,',
     'relay_checks:anchor_digest', 'the stage-1 anchor must be digest-verified inherited evidence',
     'inherited install digest refusal missing'),
    ('relay-stop-and-list-restored', 'recovery.py',
     'test ! -e @PATH@\ntest ! -L @PATH@\nprintf',
     'test ! -e @PATH@ && test ! -L @PATH@\nprintf',
     'relay_checks:stop_absence_guard', 'a same-view reappearance must not pass the receipt tail',
     'stop trusted non-aborting absence guard'),
])


def relay_block(start, end):
    """Literal source slice for mutants that remove a redundant guard family."""
    text = (HERE / 'recovery.py').read_text(encoding='utf-8')
    first = text.index(start)
    return text[first:text.index(end, first)]


child_guards = relay_block('    for file in recovery.dll recovery.runtimeconfig.json pid; do',
                           '    test "$(sha256sum recovery.dll)"')
path_guards = relay_block("    test ! -L @PATH@ || refuse 'relay directory is a symlink'",
                          '    test "$(stat -c \'%F:%u:%a\' .)"')
inventory_and_files = relay_block('    test "$(find . -mindepth 1 -maxdepth 1',
                                  '    test "$(stat -c %s pid)"')
pid_guards = relay_block('    record=$(cat pid)',
                         '    # Stricter than pid+birth nonexistence')
listener_guards = relay_block('for table in /proc/net/tcp /proc/net/tcp6; do',
                              "'''\n    if remove:")
directory_family = relay_block('if test -e @PATH@ || test -L @PATH@; then',
                                "    test ! -e @PATH@ || refuse 'relay remains after removal'")
directory_family_broken = directory_family.replace(path_guards, '    cd -P @PATH@\n')
directory_family_broken = '\n'.join(line for line in directory_family_broken.split('\n')
                                     if 'relay path linked before ' not in line
                                     and 'relay path identity changed before ' not in line)
for name, old, new, function, expected in [
    ('child-symlink', child_guards, '', 'refuses_child_symlink', 'relay refusal missing: child-symlink'),
    ('missing-child', inventory_and_files, '', 'refuses_missing', 'relay refusal wrote files: missing'),
    ('directory-symlink', directory_family, directory_family_broken, 'refuses_directory_symlink', 'relay refusal wrote files: directory-symlink'),
    ('non-directory', path_guards, '    cd -P @PATH@\n', 'refuses_not_directory', 'unclear relay refusal: not-directory'),
    ('malformed-pid', pid_guards, '    pid=8998\n    birth=12218909\n', 'refuses_pid_malformed', 'relay refusal missing: pid-malformed'),
    ('unreadable-listeners', listener_guards, '', 'refuses_unreadable_table', 'relay refusal missing: unreadable-table'),
]:
    MUTANTS.append(('relay-' + name + '-guards-skipped', 'recovery.py', old, new,
                    'relay_checks:' + function,
                    'disable the redundant ' + name + ' guard family to falsify its real-shell case', expected))
MUTANTS.append(('install-replay-refusal-skipped', 'install.py',
                "    p.require(False, 'r15 inherits the completed r14 install; stage 1 must never replay')",
                "    p.require(True, 'mutant permits install replay')",
                'relay_checks:install_replay', 'completed inherited install is never an executable r15 stage',
                'inherited install replay was not refused'))
MUTANTS.append(('relay-path-identity-skipped', 'recovery.py',
                '    test "$(stat -c \'%d:%i:%u:%a\' @PATH@)" = "$directory" || refuse \'relay path identity changed before unlink\'',
                '    true', 'relay_checks:path_identity_refusal',
                'a lexical path replacement must refuse before unlink, not only recheck the old cwd',
                'relay path identity refusal missing'))


tidy_source = (HERE / 'tidy.py').read_text(encoding='utf-8')
tidy_inventory = tidy_source[tidy_source.index("        + 'test \"$(find . -mindepth"):
                             tidy_source.index("    if target['receipt']")]
assert len(tidy_inventory.splitlines()) == 4, 'tidy inventory mutation unit source shape changed'
tidy_inventory_removed = ('\n'.join(tidy_inventory.splitlines()[1:-1])
                          + "\n        + 'true\\n')\n")

MUTANTS.extend([
    ('active-duplicate-precheck-skipped', 'active.py', '    OneAttempt(STAGE).require_unused()',
     '    pass', 'r16_checks:duplicate_precheck', 'duplicate cannot touch relay prerequisites',
     'duplicate attempt touched prerequisites: active'),
    ('disable-duplicate-precheck-skipped', 'disable.py', '    OneAttempt(STAGE).require_unused()',
     '    pass', 'r16_checks:duplicate_precheck', 'duplicate cannot touch relay prerequisites',
     'duplicate attempt touched prerequisites: disable'),
    ('native-exit-zero-accepted', 'denial.py', "result['native_exit'] is None", 'True',
     'r16_checks:denial_masked', 'not-started is not a successful child exit',
     'refusal masked as successful child exit'),
    ('native-started-accepted', 'denial.py', "result['exec_started'] is False and result['native_exit'] is None",
     'True', 'r16_checks:denial_started', 'a started native process can never pass',
     'started child was accepted'),
    ('native-errno-unrestricted', 'denial.py', "type(result['errno']) is int and result['errno'] in (1, 13)",
     'True', 'r16_checks:denial_wrong_errno', 'unrelated launch error is not signature denial', 'wrong errno accepted'),
    ('wrapper-zero-accepted', 'denial.py', 'code == 77', 'True',
     'r16_checks:denial_masked_trailer', 'wrapper cannot overwrite the refusal', 'wrapper masked refusal trailer'),
    ('kernel-missing-accepted', 'denial.py',
     "    p.require(len(hits) == 1, 'missing or duplicate exact-path kernel signature denial; STOP')\n    return hits[0]",
     "    return hits[0] if hits else ''",
     'r16_checks:kernel_missing', 'errno alone is not kernel authority', 'missing kernel denial accepted'),
    ('kernel-window-unbounded', 'denial.py', 'start <= float(match[1]) <= end', 'True',
     'r16_checks:kernel_outside', 'timestamp must lie in attempt window', 'out-of-window kernel denial accepted'),
    ('kernel-retention-loss-accepted', 'denial.py', 't_oldest <= start', 'True',
      'r16_checks:kernel_rotated', 'ring loss makes the attempt ambiguous', 'rotated kernel window accepted'),
    ('kernel-end-not-reached-accepted', 'denial.py', 't_newest >= end', 'True',
     'r16_checks:kernel_end_missing', 'the single read must reach the end', 'kernel read did not reach window end'),
    ('kernel-save-after-assertion', 'denial.py',
     "        save(label, output=raw.decode('utf-8', 'replace'), bytes=len(raw),\n"
     "             lines=len(raw.splitlines()))\n", '',
     'r16_checks:denial_saved_before_assertion', 'raw evidence must survive a denial assertion',
     'kernel evidence not saved before assertion'),
    ('certify-boot-unpinned', 'certify.py', "st['boot'] == p.CERTIFY_BOOT", 'True',
     'r16_checks:certify_boot_refusal', 'read-only pass must anchor exact boot', 'certification accepted boot'),
    ('certify-module-shape-unpinned', 'certify.py', "lines == [p.RECEIPT_ABSENT_BOOT, 'uep gate module exit=0']",
     'True', 'r16_checks:certify_module_refusal', 'single read missing module shape is terminal', 'certification accepted missing-module'),
    ('tidy-exact-inventory-validation-removed', 'tidy.py', tidy_inventory, tidy_inventory_removed,
     'r16_checks:tidy_newline_refusal',
     'The count guard and exact-set comparison are one unit under test; the count guard is a fail-fast optimization inside it, not an independently observable defense. One distinct transformation removes both guards.',
     'tidy accepted extra-newline'),
])
for kind in ('dll', 'runtimeconfig', 'pid'):
    MUTANTS.append(('relay-empty-' + kind + '-type-regression', 'recovery.py',
        'test "$(stat -c \'%u:%a:%h\' "$file")" = \'901:600:1\'',
        'test "$(stat -c \'%F:%u:%a:%h\' "$file")" = \'regular file:901:600:1\'',
        'relay_checks:refuses_empty_' + kind,
        'empty regular children must reach their hash/PID refusal, not a type-name comparison',
        'empty child failed before hash/PID refusal'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_case(runner):
    if runner == 'flow':
        code = ('import sys; sys.path.insert(0, "."); '
                'import flow_cases; flow_cases.run()')
        with HiddenBaked():
            return run_with_exception(code)
    module, function = runner.split(':')
    code = ('import sys; sys.path.insert(0, "."); '
            'import stage_lib; stage_lib.save = lambda *a, **k: None; '
            'import ' + module + ' as m; m.' + function + '()')
    return run_with_exception(code)


def run_with_exception(code):
    """Record the interpreter's actual uncaught exception, never trailing text."""
    with tempfile.TemporaryDirectory(prefix='r16-exception-', dir=driver_shim.REHEARSAL_TEMP) as temp:
        path = Path(temp) / 'exception.json'
        hook = ('import sys,json,pathlib\n'
                'def record_exception(kind,value,tb):\n'
                '    pathlib.Path(' + repr(str(path)) + ').write_text(json.dumps({"type":kind.__module__+"."+kind.__qualname__,"message":str(value)}),encoding="utf-8")\n'
                '    sys.__excepthook__(kind,value,tb)\n'
                'sys.excepthook=record_exception\n')
        outcome = subprocess.run([str(VENV), '-B', '-c', hook + code],
                                 capture_output=True, cwd=str(HERE))
        outcome.exception = json.loads(path.read_text()) if path.is_file() else {}
        return outcome


def exception_matches(code, exception, expected):
    return (code != 0 and exception.get('type') in ('manager_tools.Stop', 'builtins.AssertionError')
            and expected.lower() in exception.get('message', '').lower())


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
            mutated = text.replace(old, new).encode('utf-8')
            mutation_sha = hashlib.sha256(filename.encode() + b'\0' + mutated).hexdigest()
            path.write_bytes(mutated)
            outcome = run_case(runner)
        finally:
            path.write_bytes(original)
            if digest(path) != original_digest:
                raise SystemExit('restoration digest mismatch: ' + filename)
        output = (outcome.stdout.decode('utf-8', 'replace')
                  + outcome.stderr.decode('utf-8', 'replace'))
        failed = outcome.returncode != 0
        exception = outcome.exception
        terminal = exception.get('type', '') + ': ' + exception.get('message', '')
        matched = exception_matches(outcome.returncode, exception, expected)
        results.append({
            'name': name, 'file': filename, 'runner': runner,
            'mutation_sha256': mutation_sha,
            'reason': reason, 'expected': expected,
            'killed': matched, 'exit': outcome.returncode,
            'terminal': terminal,
            'exception_type': exception.get('type'), 'exception_message': exception.get('message'),
            'diagnostic': output[-700:],
        })
        print(('KILLED ' if matched else 'WRONG-REASON ' if failed else 'SURVIVED ')
              + name, flush=True)
    survived = [item for item in results if not item['killed']]
    distinct = {item['mutation_sha256'] for item in results}
    surviving_mutations = {item['mutation_sha256'] for item in survived}
    record = {
        'runner': 'mutation_checks.py', 'tv_operations': 0,
        'mutants': len(distinct), 'killed': len(distinct - surviving_mutations),
        'cases_exercised': len(results), 'cases_killed': len(results) - len(survived),
        'counting': 'mutants/killed count distinct transformed sources; cases count fixture executions',
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
