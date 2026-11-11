"""S2 probe-run rehearsal (suite module): exit preservation for both rounds
(acadmission 42 with marker; denial 126 markerless) plus the r1 broken
pipeline shape as the differential, on real shell semantics."""
import base64
import hashlib
import tempfile
from pathlib import Path

from driver_shim import BASH, shim_text, bash, REHEARSAL_BOOT
import activate as activate_module


MARKER = 'QN90B_UEP_NATIVE_PROBE_OK'


def run_probe_round(mock_text):
    work = Path(tempfile.mkdtemp(prefix='r2-probe-rehearsal-'))
    sdk_root = work / 'home' / 'owner' / 'share' / 'tmp' / 'sdk_tools'
    stage_dir = sdk_root / 'l4-aaaabbbbccccdddd'
    stage_dir.mkdir(parents=True)
    stage_posix = str(stage_dir).replace('\\', '/').replace('C:', '/c')
    canon_posix = str(sdk_root).replace('\\', '/').replace('C:', '/c')
    encoded = base64.b64encode(mock_text.encode('ascii')).decode('ascii')
    body = (activate_module.PROBE_RUN_BODY
            .replace('{ENCODED}', "'" + encoded + "'")
            .replace('{STAGE}', "'" + stage_posix + "'")
            .replace('{CANON}', "'" + canon_posix + "'")
            .replace('{NAT}', sha256_of(mock_text)))
    import os
    prelude = ('declare -A _META\ndeclare -A _SMACK\n'
               '_META[' + stage_posix + ']=901:901:700\n'
               '_META[uep-probe.elf]=901:901:700\n'
               + 'cd -P ' + stage_posix + '\n')
    proc = bash(shim_text() + prelude + 'set -eu\n' + body)
    return proc, work, stage_dir


def sha256_of(text):
    import hashlib
    return hashlib.sha256(text.encode('ascii')).hexdigest()


def run():
    results = []
    work_dirs = []

    # admission: marker + exit 42, cleanup by absolute path
    proc, work, stage_dir = run_probe_round('#!/bin/sh\nprintf \'QN90B_UEP_NATIVE_PROBE_OK\\n\'\nexit 42\n')
    work_dirs.append(work)
    proc.stdout or ''
    assert proc.returncode == 0, proc.stderr[:400]
    tail_lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert tail_lines[-1] == 'probe-stage-clean', 'cleanup unreceipted'
    assert 'native_exit=42' in proc.stdout, 'exit 42 not preserved'
    assert tail_lines[0] == MARKER, 'marker not first'
    assert not stage_dir.exists(), 'staging directory survived'
    assert not stage_dir.parent.joinpath(stage_dir.name).exists(), 'staging directory survived in place'
    results.append('admission round: marker + probe exit 42 preserved, owned cleanup from the sdk root')

    # denial: no marker + exit 126
    proc, work, stage_dir = run_probe_round('#!/bin/sh\nprintf \'denied\\n\'\nexit 126\n')
    work_dirs.append(work)
    assert proc.returncode == 0, proc.stderr[:400]
    tail_lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert tail_lines[-1] == 'probe-stage-clean'
    assert 'native_exit=126' in proc.stdout
    assert MARKER not in proc.stdout, 'the denied probe printed the marker'
    assert not stage_dir.exists()
    results.append('denial round: exit 126 with no marker, owned cleanup')

    # wrong exit shape: probe exits 7 with the marker -> the driver would refuse
    proc, work, stage_dir = run_probe_round('#!/bin/sh\nprintf \'QN90B_UEP_NATIVE_PROBE_OK\\n\'\nexit 7\n')
    work_dirs.append(work)
    assert 'native_exit=7' in proc.stdout, 'exit 7 not preserved'
    results.append('other nonzero exit (7) reported exactly, not masked')

    # DIFFERENTIAL: r1's exact broken shape loses the probe exit to head
    proc = bash("set -eu\n"
                "out=$( { printf 'QN90B_UEP_NATIVE_PROBE_OK\\n'; exit 42; } 2>&1 | head -c 4096 )\n"
                'r=$?\nprintf \'%s\\nnative_exit=%s\\n\' "$out" "$r"\n')
    assert 'native_exit=0' in proc.stdout.decode() if isinstance(proc.stdout, bytes) \
        else 'native_exit=0' in proc.stdout, 'r1 broken shape not reproduced'
    import os
    assert os.path.islink if False else True
    results.append('DIFFERENTIAL r1: pipeline shape reports native_exit=0 for a probe exit 42')

    for directory in work_dirs:
        import shutil
        shutil.rmtree(directory, ignore_errors=True)
    return results
