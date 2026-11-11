"""S1 gate-transition rehearsal (suite module, imported by driver_checks.py)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from driver_shim import (BASH, bake_for, new_layout, p,
                         shim_text, stage_prelude, AC, AC_HASH, RO, RO_HASH,
                         read_cfg, write_cfg, r1_gate_active_script, bash)


def run():
    results = []
    tmps = []

    def clean(*tmps):
        for tmp in tmps:
            shutil.rmtree(tmp, ignore_errors=True)
    try:
        lay1 = new_layout()
        b1 = bake_for(lay1)
        proc = bash(shim_text() + stage_prelude(lay1) + b1['gate-readonly.sh'])
        p.require(proc.returncode == 0, 'rc=' + str(proc.returncode) + ' ' + proc.stderr[:400])
        p.require('GATE_CONFIG_READONLY_COMPLETE' in proc.stdout, 'missing receipt')
        p.require((RO_HASH + '  ' + lay1['cfg']) in proc.stdout
                  or (RO_HASH + ' *' + lay1['cfg']) in proc.stdout, 'cfg hash receipt wrong')
        p.require(read_cfg(lay1) == RO, 'content wrong')
        results.append('absent -> read-only succeeds')
        tmps = [lay1['tmp']]

        lay2 = new_layout()
        tmps.append(lay2['tmp'])
        b2 = bake_for(lay2)
        setup = stage_prelude(lay2) + '_META[' + lay2['cfg'] + ']=0:0:644\n_SMACK[' + lay2['cfg'] + ']=_\n'
        write_cfg(lay2, RO)
        out = bash(shim_text() + setup + b2['gate-active.sh'])
        p.require(out.returncode == 0, 'rc=' + str(out.returncode) + ' ' + out.stderr[:400])
        p.require('GATE_CONFIG_ACTIVE_COMPLETE' in out.stdout, 'missing active receipt')
        p.require((AC_HASH + '  ' + lay2['cfg']) in out.stdout
                  or (AC_HASH + ' *' + lay2['cfg']) in out.stdout, 'active content hash wrong')
        p.require(re.search(r'GATE_METADATA 0:0:644:1', out.stdout) is not None, 'metadata receipt wrong')
        p.require(read_cfg(lay2) == AC, 'read-only content survived the replace unfixed')
        results.append('verified read-only -> active succeeds')

        lay3 = new_layout()
        tmps.append(lay3['tmp'])
        b3 = bake_for(lay3)
        write_cfg(lay3, 'rain\n')
        setup3 = stage_prelude(lay3) + '_META[' + lay3['cfg'] + ']=0:0:644\n_SMACK[' + lay3['cfg'] + ']=_\n'
        out = bash(shim_text() + setup3 + b3['gate-active.sh'])
        p.require(out.returncode != 0, 'foreign content accepted')
        p.require(read_cfg(lay3) == 'rain\n', 'foreign file was deleted')
        results.append('foreign cfg content refuses; file intact')

        lay4 = new_layout()
        tmps.append(lay4['tmp'])
        b4 = bake_for(lay4)
        import os as os_module
        os_module.symlink('a-nonexistent-target', lay4['cfgwin'])
        for name in ('gate-readonly.sh', 'gate-active.sh', 'gate-remove.sh'):
            out = bash(shim_text() + stage_prelude(lay4) + b4[name])
            p.require(out.returncode != 0, name + ' accepted a symlink')
        p.require(lay4['cfgwin'].is_symlink(), 'the symlink was deleted')
        results.append('symlink cfg refuses everywhere; link intact')

        lay5 = new_layout()
        tmps.append(lay5['tmp'])
        b5 = bake_for(lay5)
        import os as os_module2
        os_module2.symlink('totally-missing', lay5['cfgwin'])
        out = bash(shim_text() + stage_prelude(lay5) + b5['gate-readonly.sh'])
        p.require(out.returncode != 0, 'create accepted a dangling link')
        p.require(lay5['cfgwin'].is_symlink(), 'dangling link deleted')
        results.append('dangling symlink refuses')

        lay6 = new_layout()
        tmps.append(lay6['tmp'])
        b6 = bake_for(lay6)
        lay6['tempwin'].write_text(RO, encoding='ascii')
        out = bash(shim_text() + stage_prelude(lay6) + b6['gate-readonly.sh'])
        p.require(out.returncode != 0, 'create accepted a foreign temp')
        p.require(lay6['tempwin'].exists(), 'the foreign temp was deleted')
        results.append('leftover temp refuses; temp preserved')

        lay7 = new_layout()
        tmps.append(lay7['tmp'])
        b7 = bake_for(lay7)
        lay7['cfgwin'].mkdir()
        out = bash(shim_text() + stage_prelude(lay7) + b7['gate-remove.sh'])
        p.require(out.returncode != 0, 'remove accepted a directory')
        p.require(lay7['cfgwin'].is_dir(), 'the foreign directory was deleted')
        results.append('directory at cfg refuses; dir preserved')

        lay8 = new_layout()
        tmps.append(lay8['tmp'])
        b8 = bake_for(lay8)
        setup8 = stage_prelude(lay8) + '_META[' + lay8['cfg'] + ']=0:0:644\n_SMACK[' + lay8['cfg'] + ']=_\n'
        write_cfg(lay8, AC)
        out = bash(shim_text() + setup8 + b8['gate-remove.sh'])
        p.require(out.returncode == 0, 'rc=' + str(out.returncode) + ' ' + out.stderr[:400])
        p.require(re.search(r'^GATE_ABSENT$', out.stdout, re.M) is not None, 'absence unreceipted')
        p.require(not lay8['cfgwin'].exists(), 'cfg still present')
        results.append('active -> remove succeeds (GATE_ABSENT receipted)')

        lay9 = new_layout()
        tmps.append(lay9['tmp'])
        b9 = bake_for(lay9)
        setup9 = stage_prelude(lay9) + '_META[' + lay9['cfg'] + ']=0:0:644\n_SMACK[' + lay9['cfg'] + ']=_\n'
        write_cfg(lay9, RO)
        out = bash(shim_text() + setup9 + b9['gate-remove.sh'])
        p.require(out.returncode == 0, 'rc=' + str(out.returncode) + ' ' + out.stderr[:400])
        p.require(not lay9['cfgwin'].exists(), 'cfg still present')
        results.append('read-only -> remove succeeds')

        lay10 = new_layout()
        tmps.append(lay10['tmp'])
        b10 = bake_for(lay10)
        write_cfg(lay10, RO)
        # register the cfg model for the probe() prelude assertions
        setup10 = stage_prelude(lay10) + '_META[' + lay10['cfg'] + ']=0:0:644\n_SMACK[' + lay10['cfg'] + ']=_\n'
        out = bash(shim_text() + setup10 + b10['gate-readonly.sh'])
        p.require(out.returncode != 0, 'double creation accepted')
        p.require(read_cfg(lay10) == RO, 'existing content changed')
        results.append('creation stays exclusive (second create refuses; content unchanged)')

        lay11 = new_layout()
        tmps.append(lay11['tmp'])
        b11 = bake_for(lay11)
        setup11 = stage_prelude(lay11) + '_META[' + lay11['cfg'] + ']=0:0:600\n_SMACK[' + lay11['cfg'] + ']=_\n'
        write_cfg(lay11, RO)
        out = bash(shim_text() + setup11 + b11['gate-active.sh'])
        p.require(out.returncode != 0, 'wrong metadata accepted')
        p.require(read_cfg(lay11) == RO, 'file mutated on refusal')
        results.append('wrong metadata (mode 600) refuses; file untouched')

        lay12 = new_layout()
        tmps.append(lay12['tmp'])
        b12 = bake_for(lay12)
        out = bash(shim_text() + stage_prelude(lay12) + b12['gate-remove.sh'])
        p.require(out.returncode != 0, 'remove accepted absent')
        p.require(not lay12['cfgwin'].exists(), 'something appeared')
        results.append('remove on absent cfg refuses')

        lay13 = new_layout()
        tmps.append(lay13['tmp'])
        write_cfg(lay13, 'rain\n')
        setup13 = stage_prelude(lay13) + '_META[' + lay13['cfg'] + ']=0:0:644\n_SMACK[' + lay13['cfg'] + ']=_\n'
        out = bash(shim_text() + setup13 + r1_gate_active_script(lay13))
        p.require(out.returncode == 0, 'r1 unsafe overwrite was not reproduced: ' + out.stderr[:300])
        p.require(read_cfg(lay13) == AC, 'r1 did not reproduce its unguarded overwrite')
        results.append('DIFFERENTIAL r1: an AND-list guard permits overwriting foreign config bytes')

        lay14 = new_layout()
        tmps.append(lay14['tmp'])
        b14 = bake_for(lay14, boot_pin_boot='7fff1111-2222-3333-4444-555555555555')
        out = bash(shim_text(boot='9fff1111-2222-3333-4444-555555555555')
                    + stage_prelude(lay14) + b14['gate-readonly.sh'])
        p.require(out.returncode != 0, 'wrong boot accepted')
        p.require(not lay14['cfgwin'].exists(), 'created under a wrong boot')
        results.append('boot-pin mismatch refuses (create)')

        for metadata in ('901:0:644', '0:901:644'):
            lay = new_layout()
            tmps.append(lay['tmp'])
            baked = bake_for(lay)
            write_cfg(lay, RO)
            setup = stage_prelude(lay) + '_META[' + lay['cfg'] + ']=' + metadata + '\n_SMACK[' + lay['cfg'] + ']=_\n'
            for name in ('gate-active.sh', 'gate-remove.sh'):
                out = bash(shim_text() + setup + baked[name])
                p.require(out.returncode != 0 and read_cfg(lay) == RO,
                          name + ' accepted foreign ownership with the expected label')
            results.append('foreign ownership ' + metadata + ' refuses replace/remove')

        lay = new_layout()
        tmps.append(lay['tmp'])
        baked = bake_for(lay)
        write_cfg(lay, RO)
        os.link(lay['cfgwin'], lay['tmp'] / 'linked-config')
        setup = stage_prelude(lay) + '_META[' + lay['cfg'] + ']=0:0:644\n_SMACK[' + lay['cfg'] + ']=_\n'
        for name in ('gate-active.sh', 'gate-remove.sh'):
            out = bash(shim_text() + setup + baked[name])
            p.require(out.returncode != 0 and read_cfg(lay) == RO, 'linked config accepted')
        results.append('hard-linked config refuses replace/remove')

        cs = (p.HERE / 'BridgeRepairAgent.cs').read_text()
        expression = re.search(r'bootPrefix = ("set -euo.*?);', cs, re.S)[1]
        for boot, succeeds in (('bbbbbbbb-2222-3333-4444-555555555555', False),
                               ('a1111111-2222-3333-4444-555555555555', True)):
            lay = new_layout()
            tmps.append(lay['tmp'])
            baked = bake_for(lay)
            write_cfg(lay, AC)
            setup = stage_prelude(lay) + '_META[' + lay['cfg'] + ']=0:0:644\n_SMACK[' + lay['cfg'] + ']=_\n'
            prefix = ''.join(boot if token == 'expectedBoot' else json.loads(token)
                             for token in re.findall(r'"(?:\\.|[^"\\])*"|expectedBoot', expression))
            out = bash(shim_text() + setup + prefix + baked['gate-remove.sh'])
            p.require((out.returncode == 0) == succeeds, 'authenticated boot guard status wrong')
            p.require(lay['cfgwin'].exists() != succeeds, 'authenticated boot guard mutation wrong')
        results.append('actual agent boot-prefix shell refuses mismatch and permits matching removal')
        return results
    finally:
        clean(*tmps)

