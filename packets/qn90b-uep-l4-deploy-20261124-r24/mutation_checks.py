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
import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r24-pycache-')

import ast
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import packet  # Adopt the bootstrap prefix before loading the rehearsal shim.
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
tidy_count = tidy_inventory.splitlines()[0]
tidy_comparison = tidy_inventory.splitlines()[-1]

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
      'r16_checks:kernel_missing', 'errno alone is not kernel authority', 'expected exact refusal: missing or duplicate'),
    ('kernel-save-after-assertion', 'denial.py',
      "        save('denial-kernel-after', raw_b64=base64.b64encode(raw).decode('ascii'),\n"
      "             bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())\n", '',
     'r16_checks:denial_saved_before_assertion', 'raw evidence must survive a denial assertion',
     'kernel evidence not saved before assertion'),
    ('certify-boot-unpinned', 'certify.py', "st['boot'] == p.CERTIFY_BOOT", 'True',
     'r16_checks:certify_boot_refusal', 'read-only pass must anchor exact boot', 'certification accepted boot'),
    ('certify-module-shape-unpinned', 'certify.py', "lines == [p.RECEIPT_ABSENT_BOOT, 'uep gate module exit=0']",
     'True', 'r16_checks:certify_module_refusal', 'single read missing module shape is terminal', 'certification accepted missing-module'),
    ('tidy-count-only-removed', 'tidy.py', tidy_count, "        + 'true\\n'",
      'r16_checks:tidy_composite_refusal', 'one LF-composite entry impersonates three rendered names',
      'inventory prefix guard missing: composite-lf'),
    ('tidy-comparison-only-removed', 'tidy.py', tidy_comparison, "        + 'true\\n')",
      'r16_checks:tidy_comparison_refusal', 'three entries with one wrong name pass only the count predicate',
      'inventory prefix guard missing: wrong-name'),
])
for kind in ('dll', 'runtimeconfig', 'pid'):
    MUTANTS.append(('relay-empty-' + kind + '-type-regression', 'recovery.py',
        'test "$(stat -c \'%u:%a:%h\' "$file")" = \'901:600:1\'',
        'test "$(stat -c \'%F:%u:%a:%h\' "$file")" = \'regular file:901:600:1\'',
        'relay_checks:refuses_empty_' + kind,
        'empty regular children must reach their hash/PID refusal, not a type-name comparison',
         'empty child failed before hash/PID refusal'))


def require_mutant(token, function, argument=None):
    """Remove exactly one reviewed host predicate, retaining its error plumbing."""
    source = (HERE / 'denial.py').read_text(encoding='utf-8')
    calls = [node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == 'require'
             and len(node.args) == 2 and any(isinstance(item, ast.Constant) and isinstance(item.value, str)
             and token in item.value for item in ast.walk(node.args[1]))]
    assert len(calls) == 1, 'host predicate must be unique: ' + token
    call = calls[0]
    old = ast.get_source_segment(source, call)
    predicate = ast.get_source_segment(source, call.args[0])
    runner = 'r16_checks:' + function + ("(" + repr(argument) + ")" if argument is not None else '')
    suffix = '-' + argument if token.startswith('refused-before-exec') else ''
    MUTANTS.append(('host-' + token + '-removed' + suffix, 'denial.py', old, old.replace(predicate, 'True', 1),
                    runner, 'independent host refusal: ' + token, token))


for token, case in (
    ('kernel-envelope-version-or-shape', 'version'), ('kernel-capture-incomplete: ', 'complete'),
    ('kernel-pre-fence-missing', 'pre'), ('kernel-post-fence-missing', 'post'),
    ('kernel-cursor-continuity-unproved', 'cursor'), ('kernel-mid-bracket-overrun-EPIPE', 'epipe'),
    ('kernel-boot-drift', 'boot'), ('kernel-access-dmesg-restrict-drift', 'restrict'),
    ('kernel-access-smack-drift', 'smack'), ('kernel-access-helper-identity-drift', 'identity'),
    ('kernel-access-owning-group-drift', 'group'), ('kernel-capacity-unmeasured', 'capacity'),
    ('kernel-access-profile-drift', 'post-profile'),
    ('kernel-timestamp-reversal', 'order'), ('kernel-emission-suppressed', 'suppression'),
    ('kernel-witness-not-kernel-origin', 'facility'), ('kernel-record-oversize-or-empty', 'oversize'),
):
    require_mutant(token, 'kernel_guard_case', case)
for token, case in (
    ('kernel-profile-shape', 'profile'), ('kernel-capture-shape', 'cap-shape'),
    ('kernel-capture-counters-invalid', 'counters'), ('kernel-capture-raw-bound', 'raw-bound'),
    ('kernel-post-byte-count-mismatch', 'post-bytes'), ('kernel-record-count-bound', 'record-count'),
    ('kernel-record-header-range', 'priority'),
):
    require_mutant(token, 'kernel_structure_case', case)
require_mutant('kernel-envelope-framing-bound', 'kernel_decode_case', 'framing-bound')
require_mutant('direct exec accounting keys changed; STOP', 'exec_shape_case', 'schema')
for kind in ('timeout', 'timeout-type', 'stdout', 'stderr'):
    require_mutant('refused-before-exec output or timeout shape changed; STOP', 'exec_shape_case', kind)
for name, predicate, function, expected in (
    ('baseline-step', 'current[1] == baseline[1] + 1', 'kernel_endpoint_preserving_loss', 'expected=101 observed=102'),
    ('sequence-step', 'current[1] == previous[1] + 1', 'kernel_middle_gap', 'expected=102 observed=103'),
):
    MUTANTS.append(('host-' + name + '-removed', 'denial.py', predicate, 'True',
                    'r16_checks:' + function, 'endpoint-preserving loss must refuse before witness counting', expected))
MUTANTS.extend([
    ('host-flags-accepted', 'denial.py', ",-;([^\\r\\n\\x00]*)\\n'", ",[-c];([^\\r\\n\\x00]*)\\n'",
     "r16_checks:kernel_structure_case('flags')", 'unsupported continuation flags refuse', 'kernel-record-malformed-or-unsupported'),
    ('host-dictionary-accepted', 'denial.py', ",-;([^\\r\\n\\x00]*)\\n'", ",-;([^\\r\\x00]*)\\n'",
     "r16_checks:kernel_structure_case('dictionary')", 'dictionary framing cannot be silently flattened', 'kernel-record-malformed-or-unsupported'),
    ('host-utf8-replacement', 'denial.py', "raw.decode('utf-8', 'strict')", "raw.decode('utf-8', 'replace')",
     "r16_checks:kernel_decode_case('utf8')", 'replacement-decoded evidence is not complete', 'UnicodeDecodeError'),
    ('host-record-base64-lax', 'denial.py', '            raw = base64.b64decode(encoded, validate=True)', '            raw = base64.b64decode(encoded, validate=False)',
     "r16_checks:kernel_structure_case('record-decode')", 'invalid raw framing encoding refuses precisely', 'kernel-record-decode-incomplete'),
    ('host-envelope-base64-lax', 'denial.py', '        compressed = base64.b64decode(encoded, validate=True)', '        compressed = base64.b64decode(encoded, validate=False)',
     "r16_checks:kernel_decode_case('base64')", 'invalid envelope encoding refuses precisely', 'kernel-capture-transport-decode-incomplete: Error'),
    ('partial-save-removed', 'sdk.py', "if partial_evidence and state['accepted']:", 'if False:',
     'r16_checks:transport_overflow', 'partial raw receipt precedes transport failure', 'partial receipt missing or emitted more than once'),
    ('partial-prefix-unbounded', 'sdk.py', "chunk[:max(0, MAX_REPLY - len(evidence['prefix']))]", 'chunk',
     'r16_checks:transport_overflow', 'crossing chunk cannot overrun the raw prefix budget', 'partial prefix not byte-exact or overlong'),
    ('partial-before-accepted-peer', 'sdk.py', "if partial_evidence and state['accepted']:", 'if partial_evidence:',
     "r16_checks:transport_case('peer-only')", 'rejected-only requests never get raw receipts', 'incomplete receipt escaped opt-in/failure boundary'),
    ('transport-bound-removed', 'sdk.py', 'if len(data) + len(chunk) > MAX_REPLY:', 'if False:',
     'r16_checks:transport_overflow', 'wire overflow remains a named refusal', 'overflow changed the terminal limit error'),
    ('transport-closure-ignored', 'sdk.py', 'if status not in (0, 1) or "callback-error" in phases:', 'if False:',
     "r16_checks:transport_case('local-exit')", 'a trailer cannot override local failure', 'incomplete transport returned output'),
    ('transport-opt-in-capture-removed', 'sdk.py', "evidence_label in (None, 'denial-evidence')", 'True',
     "r16_checks:evidence_scope_case('capture')", 'raw evidence opt-in has one reviewed label', 'unreviewed evidence label'),
    ('transport-opt-in-request-removed', 'sdk.py', "not partial_evidence or label == 'denial-evidence'", 'True',
     "r16_checks:evidence_scope_case('request')", 'direct request cannot bypass the reviewed opt-in', 'unreviewed partial-evidence request'),
])

# Each managed transform compiles the real changed source with zero warnings,
# then runs its one intended transcript. Compiler errors/unrelated crashes never count.
for name, old, new, case in (
    ('restrict', 'profile["dmesg_restrict"] != "0"', 'false', 'restrict'),
    ('identity', 'profile["CapEff"] != ExpectedCapEff', 'false', 'identity'),
    ('uid', r'!Regex.IsMatch(profile["Uid"], @"\A901\s+901\s+901\s+901\z")', 'false', 'uid'),
    ('gid', r'!Regex.IsMatch(profile["Gid"], @"\A901\s+901\s+901\s+901\z")', 'false', 'gid'),
    ('group', '!Regex.IsMatch(profile["Groups"], @"(?:\\A|\\s)1901(?:\\s|\\z)")', 'false', 'group'),
    ('smack', 'profile["smack"] != ExpectedSmack', 'false', 'smack'),
    ('boot', 'profile["boot"] != "299d6f3f-c014-43e5-a487-59c47c833f6f"', 'false', 'boot'),
    ('pre-time', 'milliseconds() - begun >= 2000) throw new InvalidDataException("kernel-pre-time-bound")', 'milliseconds() - begun >= 20000) throw new InvalidDataException("kernel-pre-time-bound")', 'pre-time'),
    ('post-time', 'milliseconds() - begun >= 2000) throw new InvalidDataException("kernel-post-time-bound")', 'milliseconds() - begun >= 20000) throw new InvalidDataException("kernel-post-time-bound")', 'post-time'),
    ('pre-record-bound', 'preCount > RecordLimit', 'preCount > RecordLimit + 1', 'pre-record-bound'),
    ('post-record-bound', 'records.Count >= RecordLimit', 'records.Count > RecordLimit', 'post-record-bound'),
    ('pre-raw-bound', 'preBytes > ByteLimit', 'preBytes > ByteLimit * 2', 'pre-byte-bound'),
    ('post-raw-bound', 'preBytes + postBytes > ByteLimit', 'preBytes + postBytes > ByteLimit * 2', 'post-byte-bound'),
    ('combined-raw-bound', 'preBytes + postBytes > ByteLimit', 'postBytes > ByteLimit', 'raw-combined-over'),
    ('pre-sequence', 'previous != null && (previous.sequence == ulong.MaxValue || record.sequence != previous.sequence + 1)', 'false', 'pre-gap'),
    ('post-sequence', 'previous.sequence == ulong.MaxValue || record.sequence != previous.sequence + 1', 'false', 'baseline-gap'),
    ('pre-order', 'previous != null && record.timestamp < previous.timestamp', 'false', 'pre-order'),
    ('post-order', 'if (record.timestamp < previous.timestamp)', 'if (false)', 'post-order'),
    ('suppression', 'if (Suppressed(Encoding.UTF8.GetString(buffer, 0, count)))', 'if (false)', 'suppression'),
    ('empty-baseline', 'if (baseline == null) throw new InvalidDataException("kernel-baseline-empty");',
     'if (baseline == null) { baseline = previous = new Record { sequence = 100, timestamp = 94000000, raw = Convert.ToBase64String(Encoding.UTF8.GetBytes("6,100,94000000,-;invented fence\\n")) }; }', 'pre-empty'),
    ('epipe', '"kernel-mid-bracket-overrun-EPIPE"', '"ignored EPIPE"', 'post-epipe'),
    ('einval', 'errno == 22 ? "kernel-record-oversize"', 'errno == 22 ? "ignored EINVAL"', 'post-einval'),
    ('eagain', 'error.NativeErrorCode == 11', 'error.NativeErrorCode == 99', 'good'),
    ('reader-errno', ': "kernel-reader-errno";', ': "ignored read error";', 'post-errno'),
    ('open', '            fd = open();', '            fd = 42;', 'open'),
    ('close', 'try { close(fd); }', 'try { if (fd < 0) close(fd); }', 'good'),
    ('close-error', 'failure = "kernel-close-errno"', 'failure = "ignored close error"', 'close'),
    ('utf8', 'new UTF8Encoding(false, true)', 'new UTF8Encoding(false, false)', 'utf8'),
    ('oversize', 'count >= ReadLimit', 'count > ReadLimit', 'oversize'),
    ('flags', r'([0-9]{1,20}),-;([^\r\n\x00]*)\n\z', r'([0-9]{1,20}),[-c];([^\r\n\x00]*)\n\z', 'flags'),
    ('dictionary', r',-;([^\r\n\x00]*)\n\z', r',-;([^\r\x00]*)\n\z', 'dictionary'),
    ('priority', 'priority > 191', 'priority > 255', 'priority'),
    ('profile-drift', 'if (FileProfileChanged(profile, postProfile))', 'if (false)', 'profile-drift'),
    ('pre-observation', 'failureRecord = Observation("pre", buffer, count);', 'failureRecord = null;', 'pre-malformed'),
    ('post-observation', 'failureRecord = Observation("post", buffer, count);', 'failureRecord = null;', 'post-byte-bound'),
    ('post-profile-observation', 'post_profile = postProfile', 'post_profile = (object)null', 'post-cap-drift'),
    ('reopen', '            begun = milliseconds();', '            fd = open();\n            begun = milliseconds();', 'good'),
    ('exec-retry', 'try { child = start(); }', 'try { try { child = start(); } catch (Win32Exception) { child = start(); } }', 'good'),
):
    new = new.replace('false', 'string.IsNullOrEmpty("present")')
    MUTANTS.append(('managed-' + name, 'DenialRunner.cs', old, new,
                    "r16_checks:managed_case(" + repr(case) + ")", 'managed transcript must kill only ' + name,
                    'managed guard missing: ' + case))

for case, old, new in (
    ('restrict', 'test "$kmsg_restrict" = 0', 'true'),
    ('node', 'test "$kmsg_meta" = ', 'true # '),
    ('group', 'refuse_kmsg owning-group-drift', 'true'),
    ('smack', 'test "$kmsg_label" = ', 'true # '),
):
    MUTANTS.append(('shell-access-' + case + '-removed', 'denial.py', old, new,
                    'r16_checks:access_case(' + repr(case) + ')', 'access drift refuses before exec',
                    'access guard missing: ' + case))
for kind, token in (('restrict-read', 'dmesg-restrict-read-failed'), ('node-read', 'node-metadata-read-failed'),
                    ('group-read', 'owning-group-read-failed'), ('smack-read', 'node-smack-read-failed')):
    MUTANTS.append(('shell-access-' + kind + '-removed', 'denial.py', ' || refuse_kmsg ' + token, '',
                    'r16_checks:access_case(' + repr(kind) + ')',
                    'failed security observation must have a named exit69 refusal, even with valid stdout',
                    'access guard missing: ' + kind))

sdk_source = (HERE / 'sdk.py').read_text()
partial_call = next(node for node in ast.walk(ast.parse(sdk_source)) if isinstance(node, ast.Call)
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == 'sdk-reply-incomplete')
partial_text = ast.get_source_segment(sdk_source, partial_call)
MUTANTS.append(('partial-receipt-twice', 'sdk.py', partial_text,
                partial_text + '\n' + ' ' * partial_call.col_offset + partial_text,
                'r16_checks:transport_overflow', 'each accepted failed request emits once',
                'partial receipt missing or emitted more than once'))
for kind, statement in (('root', '    p.private_acl(p.HERE)'), ('evidence', "    p.private_acl(p.HERE / 'evidence')")):
    MUTANTS.append(('certify-private-' + kind + '-skipped', 'certify.py', statement, '    pass',
                    'r16_checks:certification_privacy_case(' + repr(kind) + ')',
                     'private receipt roots must validate before attempt/SDK construction', 'privacy guard missing: ' + kind))
    MUTANTS.append(('tidy-private-' + kind + '-skipped', 'tidy.py', statement, '    pass',
                    'r16_checks:tidy_privacy_case(' + repr(kind) + ')',
                    'tidy receipt roots must validate before attempt/SDK construction', 'tidy privacy guard missing: ' + kind))
MUTANTS.extend([
    ('authoring-stale-pin-accepted', 'stage_lib.py', 'repo_head() == p.COMMIT', 'True',
     'r16_checks:authoring_pin_refusal', 'a copied stale provenance pin must refuse authoring', 'authoring source HEAD differs'),
    ('marker-source-digest-skipped', 'stage_lib.py', '    p.require_source_integrity()', '    pass',
     "r16_checks:source_preflight_case('marker')", 'standing marker cannot hide real dependency drift', 'source dependency digest changed'),
    ('certify-source-digest-skipped', 'certify.py', '    p.require_source_integrity()', '    pass',
     "r16_checks:source_preflight_case('certify')", 'readiness cannot hide real dependency drift', 'source preflight missing: certify'),
])


# r21: behavioral regressions on real entrypoint imports and non-consuming writes.
MUTANTS.extend([
    ('private-cache-prefix-removed', 'packet.py', '    sys.pycache_prefix = str(prefix)',
     '    sys.pycache_prefix = None', "r21_checks:bytecode_case('prefix')",
     'with preflight disabled, a header-valid poison must still be ignored',
     'private prefix did not isolate poisoned source cache'),
    ('populated-cache-preflight-removed', 'packet.py', '    require_empty_source_caches()\n',
     '    pass\n', "r21_checks:bytecode_case('preflight')",
     'real entrypoint import must name populated source-cache paths before source imports',
     'populated-cache preflight missing'),
    ('private-cache-acl-removed', 'packet.py', '    harden_cache_prefix(prefix)',
     '    pass', 'r21_checks:cache_policy',
     'the fresh prefix must use owner+SYSTEM-only ACLs', 'private ACL/owner verification failed'),
    ('packet-bytecode-write-suppression-removed', 'packet.py', 'sys.dont_write_bytecode = True',
     'sys.dont_write_bytecode = False', 'r21_checks:cache_policy',
     'the packet must disable writes independently of interpreter -B', 'packet bytecode writes were not disabled'),
    ('refusal-record-removed', 'packet.py', '        record_refusal(stage, kind, error)',
     '        pass', "r21_checks:refusal_case('readiness')",
     'a non-consuming fatal preflight requires exactly one durable row', 'fatal preflight did not persist exactly one refusal'),
    ('refusal-fsync-removed', 'packet.py', '            os.fsync(stream.fileno())',
     '            pass', "r21_checks:refusal_storage('success')",
     'every refusal row must be fsynced', 'refusal row was not fsynced exactly once'),
    ('refusal-append-removed', 'packet.py', "with path.open('a', encoding='utf-8', newline='\\n') as stream:",
     "with path.open('w', encoding='utf-8', newline='\\n') as stream:", "r21_checks:refusal_storage('success')",
     'subsequent refusal rows must not overwrite previous evidence', 'refusal stream is not append-only'),
    ('refusal-consumption-overclaim', 'packet.py', 'consumed=False)', 'consumed=True)',
     "r21_checks:refusal_case('certify')", 'refusal must not be represented as a consumed stage outcome', 'refusal outcome schema drift'),
    ('refusal-persistence-failure-hidden', 'packet.py',
     "        raise BaseExceptionGroup('preflight refusal and refusal persistence failure', [error, persistence]) from None",
     '        raise error', "r21_checks:refusal_storage('failure')",
     'persistence failure must surface rather than vanish behind the original refusal', 'refusal persistence failure was hidden'),
    ('certify-refusal-boundary-removed', 'certify.py', "    with p.preflight(STAGE, 'readiness' if readiness else 'certify'):",
     '    if True:', "r21_checks:refusal_case('readiness')",
     'certification host preflights must persist non-consuming refusals', 'fatal preflight did not persist exactly one refusal'),
    ('tidy-refusal-boundary-removed', 'tidy.py', "    with p.preflight(STAGE, 'tidy'):",
     '    if True:', "r21_checks:refusal_case('tidy')",
     'tidy host preflights must persist non-consuming refusals', 'fatal preflight did not persist exactly one refusal'),
    ('encoded-transport-digest-removed', 'denial.py',
     ",\n         sha256=hashlib.sha256(encoded.encode('utf-8')).hexdigest()", '',
     'r21_checks:encoded_hash', 'encoded representation must be hashed in the first saved event',
     'encoded transport digest missing or covers different bytes'),
])
for entry, boundary in (
    ('install', 'p.preflight(STAGE, KIND)'), ('active', 'p.preflight(STAGE, KIND)'),
    ('disable', 'p.preflight(STAGE, KIND)'), ('inspect_tv', "p.preflight('inspect_tv', 'inspection')"),
    ('prepare', "p.preflight('prepare', 'preparation')"),
):
    MUTANTS.append(('retired-' + entry + '-refusal-removed', entry + '.py', 'with ' + boundary + ':',
                    'if True:', 'r21_checks:retired_case(' + repr(entry) + ')',
                     'retired entrypoint refusal is non-consuming and durable', 'retired entrypoint refusal missing: ' + entry))


# r22: bootstrap source selection and private-before-write refusal routing.
bootstrap = """import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r24-pycache-')
"""
certify_source = (HERE / 'certify.py').read_text(encoding='utf-8')
bootstrap_to_packet = certify_source[certify_source.index(bootstrap):certify_source.index('import packet as p') + len('import packet as p')]
MUTANTS.extend([
    ('bootstrap-prologue-missing', 'certify.py', bootstrap, '', 'r21_checks:import_graph',
     'every sealed first-import surface needs its stdlib-only prologue', 'cache prologue missing or reordered: certify'),
    ('bootstrap-prologue-reordered', 'certify.py', bootstrap_to_packet,
     'import packet as p\n' + bootstrap_to_packet.removesuffix('import packet as p'), 'r21_checks:import_graph',
     'packet import cannot precede the prologue', 'cache prologue missing or reordered: certify'),
    ('forged-packet-cache-loads', 'certify.py', bootstrap, '', 'r21_checks:packet_bytecode_case',
     'a header-valid forged packet cache must not replace source', 'forged packet cache executed: certify'),
    ('refusal-privacy-check-skipped', 'packet.py', '            private_acl(directory)', '            pass',
     'r21_checks:refusal_acl_case', 'no refusal may be written into the rejected packet directory',
     'refusal wrote into ACL-rejected directory'),
    ('refusal-fallback-routed-to-rejected-root', 'packet.py', '            directory = Path(sys.pycache_prefix)',
     '            directory = HERE', 'r21_checks:refusal_acl_case', 'fallback must escape the rejected root',
     'private refusal fallback persistence failed'),
    ('refusal-fallback-path-not-named', 'packet.py', "        error.add_note('refusal recorded at: ' + str(path))",
     '        pass', 'r21_checks:refusal_acl_case', 'raised refusal must name its durable fallback',
     'private refusal fallback path not named in raised error'),
    ('receipt-packet-label-stale', 'certify.py', "log('r24-readiness-passed'", "log('r20-readiness-passed'",
     'r16_checks:certification_evidence_fields', 'readiness audit trail names the producing packet', 'r20-readiness-passed'),
    ('suite-packet-case-unregistered', 'r21_checks.py', "    check('packet-bytecode', packet_bytecode_case)\n", '',
     'r21_checks:run', 'the forged-packet regression must have a declared passing result',
     'case missing direct run registration: packet_bytecode_case'),
    ('suite-acl-case-unregistered', 'r21_checks.py', "    check('refusal-acl', refusal_acl_case)\n", '',
     'r21_checks:run', 'formerly indirect cases require explicit registration under the strict policy',
     'case missing direct run registration: refusal_acl_case'),
    ('suite-future-case-unregistered', 'r21_checks.py', 'def run():',
     "def unwired_future_case():\n    raise AssertionError('unwired fixture must be detected structurally')\n\n\ndef run():",
     'r21_checks:run', 'a future case cannot silently exist outside the suite',
     'case missing direct run registration: unwired_future_case'),
    ('suite-registration-guard-unregistered', 'r21_checks.py', "    check('case-registration', case_registration)\n", '',
     'r21_checks:case_registration', 'the structural guard itself must remain registered',
     'case missing direct run registration: case_registration'),
])


# r23: both attribution fields and literal output outside certify must be guarded.
MUTANTS.extend([
    ('receipt-other-module-label-stale', 'denial.py', "save('denial-attempt-context'", "save('r22-denial-attempt-context'",
     'r21_checks:packet_attribution_case', 'the seal-wide label guard must cover a different emitting module',
     'packet label is stale: denial.py'),
    ('receipt-attempt-packet-stale', 'denial.py', "packet='r24', predecessor='r23'", "packet='r20', predecessor='r23'",
     'r21_checks:packet_attribution_case', 'attempt context must name its current packet independently of predecessor',
     'packet attribution is stale: denial.py'),
    ('receipt-attempt-predecessor-stale', 'denial.py', "packet='r24', predecessor='r23'", "packet='r24', predecessor='r19'",
     'r21_checks:packet_attribution_case', 'attempt context must name the actual derivation predecessor independently of packet',
     'packet attribution is stale: denial.py'),
    ('receipt-spent-packet-stale', 'tidy.py', "write_text('r24 certified", "write_text('r21 certified",
     'r21_checks:packet_attribution_case', 'space-delimited SPENT attribution is not an rNN-event label',
     'packet label is stale: tidy.py'),
    ('suite-attribution-case-unregistered', 'r21_checks.py', "    check('packet-attribution', packet_attribution_case)\n", '',
     'r21_checks:run', 'the widened guard must be directly registered under the inherited strict policy',
     'case missing direct run registration: packet_attribution_case'),
])


# r24: every permission gate is independently load-bearing, including gates
# unreachable in the current linear pre-drain (execution and established fence).
for name, old, new, case in (
    ('accepted', 'accepted == 0', 'accepted >= 0', 'resync-gate-accepted'),
    ('baseline', 'baseline == null && previous == null', 'previous == null', 'resync-gate-baseline'),
    ('previous', 'baseline == null && previous == null', 'baseline == null', 'resync-gate-previous'),
    ('pre-fence', '!preFence && !postFence', '!postFence', 'resync-gate-pre-fence'),
    ('post-fence', '!preFence && !postFence', '!preFence', 'resync-gate-post-fence'),
    ('invoked', '!invoked && fd >= 0', 'fd >= 0', 'resync-gate-invoked'),
    ('unopened', 'fd >= 0 && fd == openedFd', 'fd == openedFd', 'resync-gate-unopened'),
    ('fd', 'fd == openedFd && !used', '!used', 'resync-gate-fd'),
    ('used', 'fd == openedFd && !used', 'fd == openedFd', 'resync-gate-used'),
    ('baseline-integration', 'accepted == 0 && baseline == null && previous == null', 'accepted >= 0', 'pre-epipe-baseline'),
    ('repeat-integration', 'fd == openedFd && !used', 'fd == openedFd', 'pre-epipe-twice'),
    ('mid-bracket', 'catch (Win32Exception error) when (error.NativeErrorCode == 11) { count = 0; rawReturn = -1; again = true; }',
     'catch (Win32Exception error) when (error.NativeErrorCode == 11 || error.NativeErrorCode == 32) { count = 0; rawReturn = -1; again = true; }', 'post-epipe'),
    ('persist', 'persistResync(JsonSerializer.Serialize(ev));', ';', 'resync-good'),
    ('durable', 'resyncDurable = true;', 'resyncDurable = false;', 'resync-good'),
    ('reset-time', 'resyncDurable = true;', 'resyncDurable = true; begun = milliseconds();', 'resync-time-cumulative'),
    ('resync-gap', 'previous != null && (previous.sequence == ulong.MaxValue || record.sequence != previous.sequence + 1)', 'false', 'resync-gap'),
    ('resync-empty', 'if (baseline == null) throw new InvalidDataException("kernel-baseline-empty");',
     'if (baseline == null) { baseline = previous = new Record { sequence = 99, timestamp = 94000000 }; }', 'resync-empty'),
    ('resync-no-eagain', 'preCount > RecordLimit', 'preCount > RecordLimit + 1', 'resync-no-eagain'),
    ('resync-fabricated-fence', '                if (milliseconds() - begun >= 2000) throw new InvalidDataException("kernel-pre-time-bound");\n                int count;',
     '                if (baseline != null) { preFence = true; break; }\n                int count;', 'resync-good'),
    ('resync-byte', 'preBytes > ByteLimit', 'preBytes > ByteLimit * 2', 'resync-byte-bound'),
    ('resync-malformed', 'throw new InvalidDataException("kernel-record-malformed-or-unsupported");',
     'return new Record { sequence = 99, timestamp = 94000000, raw = Convert.ToBase64String(buffer, 0, count) };', 'resync-malformed'),
    ('pre-final-time', 'if (milliseconds() - begun >= 2000) throw new InvalidDataException("kernel-pre-time-bound");\n                if (again)',
     'if (milliseconds() - begun >= 20000) throw new InvalidDataException("kernel-pre-time-bound");\n                if (again)', 'pre-final-time'),
    ('post-final-time', 'if (milliseconds() - begun >= 2000) throw new InvalidDataException("kernel-post-time-bound");\n                if (again)',
     'if (milliseconds() - begun >= 20000) throw new InvalidDataException("kernel-post-time-bound");\n                if (again)', 'post-final-time'),
    ('same-fd', 'same_fd = fd >= 0 && fd == openedFd', 'same_fd = true', 'open'),
    ('raw-provenance', 'rawFailure ? rawFailure.rawReturn : -1', 'rawFailure ? 0 : -1', 'post-epipe'),
    ('syscall-provenance', 'native ? native.operation : operation', 'native ? "open" : operation', 'post-epipe'),
    ('invoked-provenance', 'execution_invoked = executionInvoked, failure_operation', 'execution_invoked = false, failure_operation', 'good'),
    ('pre-name', '"kernel-pre-acquisition-EPIPE"', '"kernel-mid-bracket-overrun-EPIPE"', 'pre-epipe-twice'),
):
    new = new.replace('false', 'string.IsNullOrEmpty("present")')
    MUTANTS.append(('r24-managed-' + name, 'DenialRunner.cs', old, new,
                    'r16_checks:managed_case(' + repr(case) + ')', 'decision 50 guard: ' + name,
                    'managed guard missing: ' + case))
for token, case in (
    ('kernel-execution-provenance-invalid', 'invoked'), ('kernel-resync-count-invalid', 'twice'),
    ('kernel-resync-durability-unproved', 'durable'), ('kernel-resync-gates-invalid', 'baseline'),
    ('kernel-EPIPE-provenance-invalid', 'epipe-raw'), ('kernel-EPIPE-phase-name-mismatch', 'epipe-name'),
):
    require_mutant(token, 'resync_host_case', case)
MUTANTS.append(('r24-host-journal-hash', 'denial.py', "observed == hashes[name] + '  ' + name", 'True',
                'r16_checks:denial_flow(resync=True, journal_bad=True)', 'journal bytes must match the saved event',
                'kernel-resync-journal-mismatch'))
for name, old, new, expected in (
    ('buffer-after-open', '            var buffer = new byte[ReadLimit];\n            long begun = milliseconds();\n            operation = "open";\n            fd = open();',
     '            long begun = milliseconds();\n            operation = "open";\n            fd = open();\n            var buffer = new byte[ReadLimit];', 'buffer must precede open'),
    ('journal-flush', 'stream.Flush(true);', 'stream.Flush();', 'resync journal must be exclusive and file-synced'),
    ('journal-exclusive', 'FileMode.CreateNew', 'FileMode.Create', 'resync journal must be exclusive and file-synced'),
    ('journal-directory-sync', 'int result = Fsync(fd);', 'int result = 0;', 'resync directory sync must fail closed'),
):
    MUTANTS.append(('r24-' + name, 'DenialRunner.cs', old, new, 'r16_checks:runner_structure',
                    'structural Linux boundary guard: ' + name, expected))


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
             'import ' + module + ' as m; m.' + function + ('' if function.endswith(')') else '()'))
    return run_with_exception(code)


def run_with_exception(code):
    """Record the interpreter's actual uncaught exception, never trailing text."""
    with tempfile.TemporaryDirectory(prefix='r16-exception-', dir=driver_shim.REHEARSAL_TEMP) as temp:
        path = Path(temp) / 'exception.json'
        # Preload only stdlib with -B. A write-suppression mutant must reach its
        # behavioral fixture, not fail incidentally while caching stdlib imports.
        hook = ('import sys,json,pathlib,hashlib,importlib.util,ipaddress,os,re,shutil,sqlite3,subprocess,tempfile\n'
                'from contextlib import contextmanager\nfrom datetime import datetime,timezone\n'
                'def record_exception(kind,value,tb):\n'
                '    pathlib.Path(' + repr(str(path)) + ').write_text(json.dumps({"type":kind.__module__+"."+kind.__qualname__,"message":str(value)}),encoding="utf-8")\n'
                '    sys.__excepthook__(kind,value,tb)\n'
                'sys.excepthook=record_exception\n')
        outcome = subprocess.run([str(VENV), '-B', '-u', '-c', hook + code],
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
