"""Offline build of the r2 gate scripts.

The three gate ops share one prelude plus receipt tail and differ only in
their transition body:

- create (gate-readonly.sh): absent -> read-only, exclusive.
- replace (gate-active.sh):  the exact verified `read-only` content must be
  present (regular 0:0:644 link-count 1, label `_`) and is atomically replaced
  with `active`, retaining identical metadata/label.
- remove (gate-remove.sh):   either known content (read-only | active) is
  removed; the expected BOOT is asserted by the root agent from the
  authenticated op command (`gate-remove:<boot id>`), so this body bakes no
  boot pin of its own.

Every script refuses instead of deleting foreign state: symlinks (including
dangling ones), directories, wrong metadata/ownership/link counts, foreign
content hashes, and leftover temp files are refuse paths.

bake() is a pure string builder (no packet reads); the packet-time checks
lives in main() so rehearsals can import this module host-side.
"""
import hashlib
import json
import re
import subprocess

import packet as p

h_readonly = hashlib.sha256(b'read-only\n').hexdigest()
h_active = hashlib.sha256(b'active\n').hexdigest()

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
    test "$current" = '@H_READONLY@' || test "$current" = '@H_ACTIVE@'
else
    current=absent
fi
'''

CREATE_BODY = r'''test "$current" = 'absent'
test ! -L "$cfg"
test ! -e "$cfg"
printf '%s\n' '@CONTENT@' > "$temp"
chown 0:0 "$temp"
chmod 0644 "$temp"
chsmack -a '@LABEL@' "$temp"
test "$(stat -c '%u:%g:%a:%h' "$temp")" = '0:0:644:1'
test "$(stat -c '%s' "$temp")" = '@CONTENT_BYTES@'
test "$(hash "$temp")" = '@H_END@'
test "$(chsmack "$temp")" = "$temp access=\"@LABEL@\""
mv -T -- "$temp" "$cfg"
'''

REPLACE_BODY = r'''test -e "$cfg"
test ! -L "$cfg"
test "$current" = '@H_SOURCE@'
printf '%s\n' '@CONTENT@' > "$temp"
chown 0:0 "$temp"
chmod 0644 "$temp"
chsmack -a '@LABEL@' "$temp"
test "$(stat -c '%u:%g:%a:%h' "$temp")" = '0:0:644:1'
test "$(stat -c '%s' "$temp")" = '@CONTENT_BYTES@'
test "$(hash "$temp")" = '@H_END@'
test "$(chsmack "$temp")" = "$temp access=\"@LABEL@\""
mv -T -- "$temp" "$cfg"
'''

REMOVE_BODY = r'''test ! -L "$cfg"
test -e "$cfg"
test "$current" = '@H_SOURCE@' || test "$current" = '@H_END@'
rm -- "$cfg"
'''

RECEIPT_TAIL = r'''printf '@GATE_MARK@\n'
if test -e "$cfg" && test ! -L "$cfg"; then
    test "$(hash "$cfg")" = '@H_END@'
    sha256sum "$cfg"
    stat -c 'GATE_METADATA %u:%g:%a:%h' "$cfg"
else
    printf 'GATE_ABSENT\n'
fi
'''


def subst(name, template, values):
    for key, value in values.items():
        template = template.replace('@' + key + '@', str(value))
    p.require('@' not in template, 'unexpanded script marker in ' + name)
    p.require(template.isascii(), 'non-ascii byte in ' + name)
    return template


def bake(boot_pin, uep_config, stage, canon, pkg, label, out_dir, name, middle,
         gate_mark, content, h_end, h_source=None):
    """Pure template expansion; writes the ASCII script into out_dir/name."""
    values = {
        'BOOT_PIN': boot_pin,
        'UEP_CONFIG': uep_config,
        'STAGE': stage, 'CANON': canon, 'PKG': pkg,
        'H_READONLY': h_readonly, 'H_ACTIVE': h_active,
        'LABEL': label,
        'GATE_MARK': gate_mark, 'H_END': h_end,
        'H_SOURCE': h_source or h_readonly,
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


def bake_gate_packet(boot, label, out_dir,
                     uep_config=p.UEP_CONFIG, stage=p.STAGE,
                     canon=p.CANON, pkg=p.PKG):
    boot_pin = "test \"$(cat /proc/sys/kernel/random/boot_id)\" = '" + boot + "'"
    no_pin = '# the boot expectation arrives via the authenticated agent op command'
    return {
        'gate-readonly.sh': bake(
            boot_pin, uep_config, stage, canon, pkg, label, out_dir,
            'gate-readonly.sh', CREATE_BODY, 'GATE_CONFIG_READONLY_COMPLETE',
            'read-only', h_readonly),
        'gate-active.sh': bake(
            boot_pin, uep_config, stage, canon, pkg, label, out_dir,
            'gate-active.sh', REPLACE_BODY, 'GATE_CONFIG_ACTIVE_COMPLETE',
            'active', h_active, h_source=h_readonly),
        'gate-remove.sh': bake(
            no_pin, uep_config, stage, canon, pkg, label, out_dir,
            'gate-remove.sh', REMOVE_BODY, 'GATE_CONFIG_REMOVED_COMPLETE',
            None, h_active, h_source=h_readonly),
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
    p.require(initial.get('uep_config', 'absent') == 'absent',
              'gate config must be absent before stage 3; STOP')
    p.require(initial.get('fdet_home') == 'present', 'the installed fdet payload is not present; STOP')
    label = initial['selfroot_label']
    p.require(isinstance(label, str) and re.fullmatch(r'[A-Za-z0-9:_-]{1,64}', label),
              'unexpected selfroot smack label: ' + repr(label))
    baked = bake_gate_packet(p.BOOT, label, p.HERE)
    print(json.dumps({'prepared': True,
                      'gate_scripts': sorted(baked),
                      'boot': p.BOOT, 'TV_operations': 0}))


if __name__ == '__main__':
    main()
