"""Offline build of the r7 gate script (remove only).

The single gate op executed live by this packet is the removal via the
authenticated agent command `gate-remove:<boot id>`: the ROOT AGENT asserts
the expected boot inside the root shell (prefix injected from the op
parameter; the baked script carries no boot pin of its own, exactly as in
the reviewed r6 lineage). The baked body removes only the exact verified
`read-only` content:

- the config must present, a regular file, owner 0:0, mode 0644, link count 1,
  smack label `_`, and its content hash must equal sha256("read-only\\n");
- `active` content, foreign content, any symlink (including dangling),
  directories, wrong metadata/link counts and leftover temp files are REFUSE
  paths (exit 74 or aborted before any write), never deletions;
- after the rm the script asserts absence and prints the completion mark; a
  surviving file cannot satisfy the tail, so a silent non-removal stops the
  stage (set -e) instead of receipting success.

bake() is a pure string builder (no packet reads); the packet-time checks
live in main() so rehearsals can import this module host-side.

The create/replace transitions (r6's gate-readonly.sh / gate-active.sh) are
deliberately NOT baked: the read-only gate config already exists (r6 DIRREAD
created it live, exit 0) and no stage in this packet may create or activate
a config.
"""
import base64
import json
import re
import subprocess

import packet as p

h_readonly = p.UEP_READONLY_SHA
h_active = p.UEP_ACTIVE_SHA

PRELUDE = r'''set -euo pipefail
export LC_ALL=C
umask 077
test "$(id -u)" = 0
@BOOT_PIN@
hash() { local result; result=$(sha256sum "$1"); printf '%s' "${result%% *}"; }
cfg=@UEP_CONFIG@
temp=@UEP_CONFIG@.prepared
stage_dir=@STAGE@
test "$(readlink -f "$stage_dir")" = '@CANON@/@PKG@'
test "$(stat -c '%u:%a' "$stage_dir")" = '901:700'
test ! -e "$temp"
test ! -L "$temp"
probe() {
    test -e "$cfg" && test ! -L "$cfg" || return 1
    test "$(stat -c '%F' "$cfg")" = 'regular file' || return 1
    test "$(stat -c '%u:%g:%a' "$cfg")" = '0:0:644' || return 1
    test "$(stat -c %h "$cfg")" = 1 || return 1
    test "$(chsmack "$cfg")" = "$cfg access=\"@LABEL@\"" || return 1
}
if test -e "$cfg" || test -L "$cfg"; then
    probe || exit 74
    current=$(hash "$cfg")
else
    current=absent
fi
'''

REMOVE_BODY = r'''test "$current" = '@H_READONLY@'
test ! -L "$cfg"
test -e "$cfg"
rm -- "$cfg"
'''

RECEIPT_TAIL = r'''printf '@GATE_MARK@\n'
test ! -e "$cfg"
test ! -L "$cfg"
printf 'GATE_ABSENT\n'
'''


def subst(name, template, values):
    for key, value in values.items():
        template = template.replace('@' + key + '@', str(value))
    p.require('@' not in template, 'unexpanded script marker in ' + name)
    p.require(template.isascii(), 'non-ascii byte in ' + name)
    return template


def bake(boot_pin, uep_config, stage, canon, pkg, label, out_dir, name, middle,
         gate_mark, content, h_end, h_source=None):
    """Pure template expansion; writes the ASCII script into out_dir/name.

    r7's remove semantics with the reviewed tail: content is None (nothing is
    written) and the tail asserts absence UNCONDITIONALLY — the @H_END@
    parameter survives only for template-call compatibility and replaces
    nothing in the baked body. No surviving-file fallback exists: a config
    that outlives the rm fails the tail (set -e) instead of receipting
    success.
    """
    values = {
        'BOOT_PIN': boot_pin,
        'UEP_CONFIG': uep_config,
        'STAGE': stage, 'CANON': canon, 'PKG': pkg,
        'H_READONLY': h_readonly, 'H_ACTIVE': h_active,
        'LABEL': label,
        'GATE_MARK': gate_mark, 'H_END': h_end,
    }
    if content is None:
        values['CONTENT'] = ''
        values['CONTENT_BYTES'] = '0'
    else:
        values['CONTENT'] = content
        values['CONTENT_BYTES'] = str(len(content) + 1)
    script = subst(name, PRELUDE + middle + RECEIPT_TAIL, values)
    path = out_dir / name
    p.require(not path.exists(), 'script already baked: ' + str(path))
    path.write_text(script, encoding='ascii', newline='\n')
    return script


def bake_gate_remove(boot_unused, label, out_dir,
                     uep_config=p.UEP_CONFIG, stage=p.STAGE,
                     canon=p.CANON, pkg=p.PKG):
    """Bake exactly the r7 removal script.

    The first parameter stays for shim/template compatibility; the baked
    script bakes NO boot pin (the authenticated agent op command carries the
    expected boot, asserted inside the root shell before the body).
    """
    no_pin = '# the boot expectation arrives via the authenticated agent op command'
    return {
        'gate-remove.sh': bake(
            no_pin, uep_config, stage, canon, pkg, label, out_dir,
            'gate-remove.sh', REMOVE_BODY, 'GATE_CONFIG_REMOVED_COMPLETE',
            None, h_readonly),
    }


def main():
    initial = p.inspection()
    p.require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=p.REPO).decode().strip() == p.COMMIT,
              'source head changed')
    p.require(subprocess.check_output(['git', 'status', '--porcelain', '--', 'boot-agent', '.github/workflows/build.yml'],
                                      cwd=p.REPO) == b'', 'source edits pending')
    p.require(initial['hash'].split('  ')[0] == p.NEW_SHA,
              'the inspected installed manager is not the pinned v5.18; STOP')
    p.require(initial['boot'] == p.BOOT and
              bool(re.fullmatch(r'regular file:(?:[0-9]+:){6}[0-9]+', initial['target_meta'])),
              'invalid inspected target metadata')
    p.require(initial.get('fdet_home') == 'present', 'the installed fdet payload is not present; STOP')
    # The r6 left-behind must be exactly the verified read-only config.
    p.require(initial.get('gate_config', 'absent') == 'present',
              'the read-only gate config is not present; STOP')
    gate_digest = (base64.b64decode(initial.get('gate_hash', '').encode()).decode()
                   .strip().partition('  ')[0])
    p.require(gate_digest == p.UEP_READONLY_SHA,
              'the present gate config is not the read-only bytes; STOP')
    p.require(initial.get('gate_meta') == p.UEP_META,
              'gate config metadata did not survive from the r6 dirread; STOP')
    p.require(initial.get('gate_label') == p.UEP_LABEL,
              'gate config label did not survive from the r6 dirread; STOP')
    p.require(initial.get('gate_state', 'present') == 'absent',
              'the budget state file exists before removal; STOP')
    for packet_marker in ('STOP', 'SPENT'):
        require_ref = p.HERE / packet_marker
        p.require(not require_ref.exists(),
                  'the packet is stopped or spent; the removal packet never re-arms: ' + packet_marker)
    # Bake the CONFIG's own label (the packet constant the inspection verified
    # against UEP_LABEL), never the selfroot directory's label: the baked probe
    # compares the config file's smack label, and a divergent selfroot label
    # must not be able to silently change what the removal accepts.
    label = p.UEP_LABEL_VALUE
    p.require(re.fullmatch(r'[A-Za-z0-9:_-]{1,64}', label),
              'unexpected gate config smack label: ' + repr(label))
    baked = bake_gate_remove(p.BOOT, label, p.HERE)
    print(json.dumps({'prepared': True,
                      'gate_scripts': sorted(baked),
                      'boot': p.BOOT, 'TV_operations': 0}))


if __name__ == '__main__':
    main()
