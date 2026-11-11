"""Host-only r12 script transitions under the real Git-Bash shim.

Every case runs the SAME bytes the live packet will carry — the sealed script
when the live bake exists, otherwise the identical template render — with only
the absolute paths and the dotnet binary substituted for a temp layout. Content
hashes, cp/mv/rm, symlinks and shell semantics are real; uid/mode/link/smack
are modelled by driver_shim.

The removal cases pin the r12 boundary: the writer's real 0666 state file is
accepted, while a stale-boot, multiline or appended-line receipt is refused. The
install/activation cases pin the pre-write budget-temp refusal (a planted file
and a dangling symlink), without claiming it covers the host's own write.
"""
import base64
import hashlib
import re
import shutil

import driver_shim
import packet as p
import prepare

PREV = p.HERE.parent / 'qn90b-uep-l4-deploy-20261109-r8/artifacts/manager.dll'
PREV_RC = p.HERE.parent / 'qn90b-uep-l4-deploy-20261109-r8/artifacts/manager.runtimeconfig.json'

READONLY_RECEIPT = p.RECEIPT_READONLY_MANUAL
READONLY_DETAIL = p.LOG_READONLY.format('manual', p.FINGERPRINT)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _populate(lay):
    """Baseline layout: the installed v5.18 manager plus the staged artifacts."""
    prev = PREV.read_bytes()
    prev_rc = PREV_RC.read_bytes()
    p.require(_sha(prev) == p.PREV_MANAGER_SHA, 'v5.18 fixture drift')
    p.require(_sha(prev_rc) == p.PREV_MANAGER_RC_SHA, 'v5.18 runtimeconfig fixture drift')
    (lay['tmp'] / 'opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll').write_bytes(prev)
    (lay['tmp'] / 'opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.runtimeconfig.json').write_bytes(prev_rc)
    for name, source in (('manager.dll', p.NEW),
                         ('manager.runtimeconfig.json', p.NEW_RC),
                         ('UepGateHost.dll', p.HOST),
                         ('UepGateHost.runtimeconfig.json', p.HOST_RC),
                         ('boot.sh', p.MODULE_BOOT),
                         ('module.json', p.MODULE_JSON)):
        shutil.copyfile(source, lay['stage_win'] / name)
    fake = lay['bin_win'] / 'dotnet'
    fake.write_text("#!/bin/sh\nprintf '%s\\n' '" + READONLY_RECEIPT + "'\n"
                    + "printf '%s\\n' '" + READONLY_DETAIL + "'\n",
                    encoding='ascii', newline='\n')
    driver_shim.bash('chmod 755 -- ' + driver_shim.to_posix(fake))


def _prelude(lay, extra=''):
    return ('declare -A _META\ndeclare -A _SMACK\n'
            + driver_shim.seed(lay['stage_win'], '901:901:700')
            + driver_shim.seed(lay['tmp'] / 'opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll', '201:0:755')
            + driver_shim.seed(lay['tmp'] / 'opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.runtimeconfig.json', '201:0:755')
            + extra)


def _config(lay, content='read-only', meta='0:0:644', label='_'):
    path = lay['tmp'] / 'opt/usr/share/selfroot/uep-off.conf'
    path.write_text(content + '\n', encoding='ascii', newline='\n')
    return (driver_shim.seed(path, meta)
            + '_SMACK[' + driver_shim.to_posix(path) + ']=' + label + '\n')


def _subst_layout(text, lay):
    """Apply only the layout substitutions to a sealed script, in one pass.

    Several production paths contain one another (TARGET is built from APP,
    STAGE is ROOT/PKG and a suffix of CANON/PKG), so sequential str.replace
    always re-expands an inserted layout path at least once. A single
    alternation, longest pattern first, replaces every occurrence exactly once
    and never rescans what it just inserted.
    """
    mapping = {
        p.APP: lay['app'],
        p.TARGET_RC: lay['target_rc'],
        p.TARGET: lay['target'],
        p.MODULE_DIR: lay['module_dir'],
        p.BACKUP_DIR: lay['backup'],
        p.UEP_CONFIG: lay['cfg'],
        p.UEP_STATE: lay['state'],
        p.STAGE: lay['stage'],
        p.CANON: lay['canon'],
        p.PKG: lay['pkg'],
        '/usr/bin/dotnet': lay['dotnet'],
    }
    pattern = re.compile('|'.join(re.escape(key) for key in
                                  sorted(mapping, key=len, reverse=True)))
    return pattern.sub(lambda match: mapping[match.group(0)], text)


def _script_text(lay, name):
    """The exact sealed script, layout-substituted, or its template bake.

    r10 M3: r9's rehearsal re-baked the templates and never touched the sealed
    bytes, so a sealed script could drift from what the rehearsal proved. When
    the live bake exists, the rehearsal runs it; the substituted sealed text
    must also equal the template render, which is what makes the rehearsal
    evidence about the sealed bytes.
    """
    baked = driver_shim.bake_for(lay)[name]
    sealed = p.HERE / name
    if not sealed.is_file():
        return baked
    text = _subst_layout(sealed.read_text(encoding='ascii'), lay)
    p.require(text == baked, 'sealed ' + name + ' differs from its template bake')
    return text


def _budget(lay, content=None, meta='0:0:666', boot=driver_shim.REHEARSAL_BOOT):
    """The active-boot budget receipt, shaped exactly as the host writes it.

    r12 B1: UepGate.SaveBudget creates the file from a File.WriteAllText temp
    under Umask 0000, so the landed mode is 0666. r12 M1: the receipt must name
    the CURRENT boot and be exactly one line.
    """
    if content is None:
        content = 'boot=' + boot + ' clear=1 restore=0\n'
    path = lay['tmp'] / 'opt/usr/share/selfroot/uep-state.conf'
    path.write_text(content, encoding='ascii', newline='\n')
    return driver_shim.seed(path, meta)


def _case(script, setup, checks=(), inner=()):
    lay = driver_shim.new_layout()
    try:
        _populate(lay)
        script_path = lay['tmp'] / script
        script_path.write_text(_script_text(lay, script), encoding='ascii', newline='\n')
        setup_text = setup(lay) if callable(setup) else setup
        inner_items = inner(lay) if callable(inner) else inner
        outfile = lay['tmp'] / 'case-out'
        inner_text = '\n'
        for key, expression in inner_items:
            inner_text += "printf 'inner_" + key + "=%s\\n' \"$( " + expression + " )\"\n"
        pieces = [driver_shim.shim_text(), _prelude(lay), setup_text,
                  '( . ' + driver_shim.to_posix(script_path) + inner_text
                  + ' ) > ' + driver_shim.to_posix(outfile),
                  "printf 'case_rc=%s\\n' \"$?\"",
                  "printf 'completed=%s\\n' \"$( base64 < " + driver_shim.to_posix(outfile)
                  + " | tr -d '\\n' )\"",
                  "printf 'cfg=%s\\n' \"$( test -e " + lay['cfg'] + " && cat " + lay['cfg'] + " || echo ABSENT )\"",
                  "printf 'module=%s\\n' \"$( test -e " + lay['module_host'] + " && echo present || echo absent )\"",
                  "printf 'backup=%s\\n' \"$( test -e " + lay['backup'] + " && echo present || echo absent )\"",
                  "printf 'target=%s\\n' \"$( sha256sum " + lay['target'] + " | cut -d' ' -f1 )\""]
        for key, expression in checks:
            pieces.append("printf '%s=%s\\n' '" + key + "' \"$( " + expression + " )\"")
        result = driver_shim.bash('\n'.join(pieces) + '\n')
        p.require(result.returncode == 0, 'rehearsal wrapper failed: ' + result.stderr[:300])
        out = {}
        for line in result.stdout.splitlines():
            key, sep, value = line.partition('=')
            if sep:
                out[key] = value
        p.require('case_rc' in out and 'completed' in out, 'case labels missing')
        out['completed'] = base64.b64decode(out['completed']).decode('utf-8', 'replace')
        for line in out['completed'].splitlines():
            key, sep, value = line.partition('=')
            if sep and key.startswith('inner_'):
                out[key[len('inner_'):]] = value
        p.require('cfg' in out and 'module' in out and 'backup' in out and 'target' in out,
                  'state labels missing')
        out['stderr'] = result.stderr
        return out
    finally:
        shutil.rmtree(lay['tmp'], ignore_errors=True)


def run():
    results = []

    # 1. install happy path
    out = _case('gate-install.sh', '', inner=lambda lay: (
        ('cfg_meta', "stat -c '%F:%u:%g:%a:%h' -- " + lay['cfg']),
        ('cfg_label', 'chsmack ' + lay['cfg']),
        ('target_meta', "stat -c '%u:%g:%a:%h' -- " + lay['target']),
        ('target_label', 'chsmack ' + lay['target']),
    ))
    p.require(out['case_rc'] == '0', 'install happy path failed: ' + out['completed'][-400:]
              + ' STDERR: ' + out['stderr'][-300:])
    for marker in ('GATE_BACKUP_COMPLETE', 'GATE_MANAGER_INSTALLED', 'GATE_MODULE_INSTALLED',
                   'GATE_READONLY_CREATED', 'GATE_MANUAL_READ_OK', 'GATE_INSTALL_COMPLETE'):
        p.require(marker in out['completed'], 'install receipt missing ' + marker + ' :: '
                  + out['completed'][:500])
    p.require(out['cfg'] == 'read-only', 'install did not create read-only content')
    p.require(out['cfg_meta'] == 'regular file:0:0:644:1', 'install config metadata: ' + out['cfg_meta'])
    p.require(out['cfg_label'].endswith(' access="_"'), 'install config label: ' + out['cfg_label'])
    p.require(out['target_meta'] == '201:0:755:1', 'manager metadata not preserved: ' + out['target_meta'])
    p.require(out['target_label'].endswith(' access="User::Pkg::com.samsung.tv.ghservice::RO"'),
              'manager label not preserved: ' + out['target_label'])
    p.require(out['module'] == 'present' and out['backup'] == 'present', 'install state incomplete')
    p.require(out['target'] == p.NEW_MANAGER_SHA, 'install did not replace the manager')
    results.append('install: v5.18 backed up, v5.19 installed, read-only config + manual read')

    # 2. install refuses when a config already exists (no write)
    out = _case('gate-install.sh', lambda lay: _config(lay))
    p.require(out['case_rc'] != '0', 'install accepted a pre-existing config: rc=' + out['case_rc']
              + ' out=' + out['completed'][:400] + ' err=' + out['stderr'][-300:])
    p.require(out['target'] == p.PREV_MANAGER_SHA and out['module'] == 'absent',
              'refusal wrote before the config check')
    results.append('install: pre-existing config refused before any write')

    # 3. install refuses when the module directory exists
    out = _case('gate-install.sh', lambda lay: ('mkdir -p ' + lay['module_dir'] + '\n'
                                               + driver_shim.seed(lay['module_win'], '0:0:755')))
    p.require(out['case_rc'] != '0' and out['target'] == p.PREV_MANAGER_SHA,
              'install accepted an existing module directory')
    results.append('install: existing module directory refused before any write')

    # 4. install refuses on wrong installed manager bytes
    def wrong_installed(lay):
        path = lay['tmp'] / 'opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll'
        path.write_bytes(b'not the installed manager')
        return ''

    out = _case('gate-install.sh', wrong_installed)
    p.require(out['case_rc'] != '0' and out['module'] == 'absent',
              'install accepted a foreign installed manager')
    results.append('install: foreign installed manager refused')

    # 5. install refuses on wrong staged bytes
    def wrong_staged(lay):
        (lay['stage_win'] / 'UepGateHost.dll').write_bytes(b'not the pinned host')
        return ''

    out = _case('gate-install.sh', wrong_staged)
    p.require(out['case_rc'] != '0' and out['target'] == p.PREV_MANAGER_SHA,
              'install accepted unpinned staged bytes')
    results.append('install: unpinned staged artifact refused before any write')

    # 6. active happy path
    out = _case('gate-config-active.sh', lambda lay: _config(lay), inner=lambda lay: (
        ('cfg_meta', "stat -c '%F:%u:%g:%a:%h' -- " + lay['cfg']),
        ('cfg_label', 'chsmack ' + lay['cfg']),
    ))
    p.require(out['case_rc'] == '0' and 'GATE_ACTIVE_COMPLETE' in out['completed'],
              'activation happy path failed: ' + out['completed'][-300:])
    p.require(out['cfg'] == 'active', 'activation did not write active content')
    p.require(out['cfg_meta'] == 'regular file:0:0:644:1', 'activation metadata drift')
    p.require(out['cfg_label'].endswith(' access="_"'), 'activation label drift')
    results.append('active: read-only bytes become active with metadata/label preserved')

    # 7. active refuses when the content is already active
    out = _case('gate-config-active.sh', lambda lay: _config(lay, content='active'))
    p.require(out['case_rc'] != '0' and out['cfg'] == 'active', 'active content was re-written')
    results.append('active: already-active content refused')

    # 8. active refuses when a budget state exists
    def budget(lay):
        path = lay['tmp'] / 'opt/usr/share/selfroot/uep-state.conf'
        path.write_text('boot=' + driver_shim.REHEARSAL_BOOT + ' clear=1 restore=0\n', encoding='ascii')
        return _config(lay) + driver_shim.seed(path, '0:0:600')

    out = _case('gate-config-active.sh', budget)
    p.require(out['case_rc'] != '0' and out['cfg'] == 'read-only', 'budget state did not stop activation')
    results.append('active: pre-existing budget state refused')

    # 9. active refuses on unexpected metadata
    out = _case('gate-config-active.sh', lambda lay: _config(lay, meta='0:0:600'))
    p.require(out['case_rc'] != '0' and out['cfg'] == 'read-only', 'mode drift did not stop activation')
    results.append('active: 600-mode config refused')

    # 10. remove happy path: the writer's real 0666 metadata and this boot
    out = _case('gate-remove.sh',
                lambda lay: _config(lay, content='active') + _budget(lay))
    p.require(out['case_rc'] == '0' and 'GATE_ABSENT' in out['completed'],
              'removal happy path failed: ' + out['completed'][-300:])
    p.require(out['cfg'] == 'ABSENT', 'removal did not delete the config')
    results.append('disable: active bytes removed with the writer\'s 0666 receipt')

    # 10b. remove refuses when the active-boot budget receipt is absent
    out = _case('gate-remove.sh', lambda lay: _config(lay, content='active'))
    p.require(out['case_rc'] != '0' and out['cfg'] == 'active',
              'removal proceeded without the active-boot budget receipt')
    results.append('disable: missing budget receipt refused before removal')

    # 10c. remove refuses a stale receipt from another boot
    out = _case('gate-remove.sh',
                lambda lay: _config(lay, content='active')
                + _budget(lay, boot='b2222222-3333-4444-5555-666666666666'))
    p.require(out['case_rc'] != '0' and out['cfg'] == 'active',
              'removal accepted a receipt from a different boot')
    results.append('disable: stale-boot receipt refused')

    # 10d. remove refuses a multiline receipt (two complete lines)
    current = 'boot=' + driver_shim.REHEARSAL_BOOT + ' clear=1 restore=0\n'
    out = _case('gate-remove.sh',
                lambda lay: _config(lay, content='active')
                + _budget(lay, content=current + current))
    p.require(out['case_rc'] != '0' and out['cfg'] == 'active',
              'removal accepted a multiline receipt')
    results.append('disable: multiline receipt refused')

    # 10e. remove refuses a valid line with an appended second line
    out = _case('gate-remove.sh',
                lambda lay: _config(lay, content='active')
                + _budget(lay, content=current + 'extra\n'))
    p.require(out['case_rc'] != '0' and out['cfg'] == 'active',
              'removal accepted a receipt with an appended line')
    results.append('disable: receipt with an appended line refused')

    # 11. remove refuses on read-only content
    out = _case('gate-remove.sh', lambda lay: _config(lay) + _budget(lay))
    p.require(out['case_rc'] != '0' and out['cfg'] == 'read-only', 'read-only config was removed')
    results.append('disable: read-only content refused (no transition from read-only)')

    # 12. remove refuses on a symlink
    def symlink(lay):
        link = lay['tmp'] / 'opt/usr/share/selfroot/uep-off.conf'
        target = lay['tmp'] / 'opt/usr/share/selfroot/other'
        target.write_text('active\n', encoding='ascii')
        link.symlink_to(target)
        return _budget(lay)

    out = _case('gate-remove.sh', symlink)
    p.require(out['case_rc'] != '0', 'symlink was treated as a config')
    p.require(out['cfg'] == 'active', 'the symlink target was modified')
    results.append('disable: symlinked config refused without following the link')

    # 13. install refuses a planted budget temp path before any write
    def planted_state_tmp(lay):
        path = lay['tmp'] / 'opt/usr/share/selfroot/uep-state.conf.tmp'
        path.write_text('boot=' + driver_shim.REHEARSAL_BOOT + ' clear=1 restore=0\n',
                        encoding='ascii')
        return driver_shim.seed(path, '0:0:666')

    out = _case('gate-install.sh', planted_state_tmp)
    p.require(out['case_rc'] != '0' and out['target'] == p.PREV_MANAGER_SHA
              and out['module'] == 'absent',
              'install accepted a planted budget temp path or wrote before refusing')
    results.append('install: planted budget temp path refused before any write')

    # 13b. install refuses a dangling symlink at the budget temp path
    def linked_state_tmp(lay):
        path = lay['tmp'] / 'opt/usr/share/selfroot/uep-state.conf.tmp'
        path.symlink_to(lay['tmp'] / 'missing-temp-target')
        return ''

    out = _case('gate-install.sh', linked_state_tmp)
    p.require(out['case_rc'] != '0' and out['target'] == p.PREV_MANAGER_SHA,
              'install accepted a dangling budget temp symlink')
    results.append('install: dangling budget temp symlink refused before any write')

    # 13c. active refuses a planted budget temp path
    out = _case('gate-config-active.sh',
                lambda lay: _config(lay) + planted_state_tmp(lay))
    p.require(out['case_rc'] != '0' and out['cfg'] == 'read-only',
              'activation accepted a planted budget temp path')
    results.append('active: planted budget temp path refused before the write')

    # 14. static shape: LF, ASCII, no template markers, exact tail markers
    lay = driver_shim.new_layout()
    try:
        baked = prepare.bake_rehearsal(lay['tmp'], lay)
        p.require(set(baked) == {'gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh'},
                  'unexpected bake surface')
        tails = {'gate-install.sh': "printf 'GATE_INSTALL_COMPLETE\\n'",
                 'gate-config-active.sh': "printf 'GATE_ACTIVE_COMPLETE\\n'",
                 'gate-remove.sh': "printf 'GATE_ABSENT\\n'"}
        for name, text in baked.items():
            p.require(text.isascii() and '\r' not in text, 'non-ASCII or CRLF script: ' + name)
            p.require('@' not in text, 'unexpanded template marker: ' + name)
            p.require(text.rstrip('\n').endswith(tails[name]), 'completion tail missing: ' + name)
    finally:
        shutil.rmtree(lay['tmp'], ignore_errors=True)
    results.append('bake: LF/ASCII, no template markers, exact completion tails')
    return results
