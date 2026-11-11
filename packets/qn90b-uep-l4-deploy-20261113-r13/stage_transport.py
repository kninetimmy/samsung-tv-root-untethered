"""Staging transport for oversized L4 binaries (gzip route, chunked fallback).

Independent of the sealed trial.py; this module replicates
trial.Trial.stage's containment, claim, per-file hash verification and
publish flow for the three assets that cannot travel the single reviewed
channel unsplit:

  manager.dll 61 952 B, SamsungTvRootAgent.dll 58 880 B, FdetProbe.dll 49 152 B.

Both routes stay inside the reviewed channel contract (510-byte SDB wire,
<=70 000-byte script frame, <=48 000-byte upload for any pushed file):

gzip route    the asset ships as the whitelisted `<name>.gz` (host-built,
              deterministic gzip, level 9, mtime 0), a receipted TV-side
              `gzip -dc -- <name>.gz > <name>` recreates the plain file, the
              plain digest receipt is verified against the sealed bytes, and
              the .gz variant is unlinked before the publish-time
              unknown-name sweep runs.
chunked route the plain asset is split into two whitelisted part files
              (`<name>.a` <=32 000 B, `<name>.b` the remainder, both
              <=32 000 B here); the first arrives through the ordinary
              prepare_upload channel (dd conv=excl), the second follows, then
              a receipted `cat -- a b | dd of=<name> conv=excl` assembles the
              full bytes; both parts are unlinked; the assembled digest is
              verified. `cat` introduces no additional dd flag requirement
              beyond the verified conv=excl/oflag=nofollow set.

Route decision is a receipted read-only probe (`command -v gzip`) before the
claim; only a genuinely absent gzip falls to the chunked route. Everything
else is the trial.stage() sequence, byte for byte. Importing performs no TV
operations.
"""
import base64
import gzip as gzip_mod
import re
import shutil
from pathlib import Path
from shlex import quote

import packet as p
import sdk

CHUNK_PART = 32000
OVERSIZED = ('manager.dll', 'SamsungTvRootAgent.dll', 'FdetProbe.dll')
GZ_HOST_DIR = p.HERE / 'execution' / 'artifacts-gz'


class TransportFailure(p.Stop):
    pass


def _source(path):
    source = Path(path)
    p.require(source.resolve(strict=True) == source.absolute() and source.is_file(),
              'oversized source missing or redirected: ' + source.name)
    p.require(source.stat().st_nlink == 1, 'oversized source linked: ' + source.name)
    return source


def build_plan(route_name, name, source):
    """Returns one plan dict; host-only; writes nothing on TV."""
    source = _source(source)
    plain_digest = p.digest(source)
    plain_size = source.stat().st_size
    silence = '0' * 20
    if route_name == 'gzip':
        gz = gzip_mod.compress(source.read_bytes(), compresslevel=9, mtime=0)
        p.require(len(gz) <= sdk.MAX_UPLOAD, 'gz exceeds the reviewed upload bound: ' + name)
        host = GZ_HOST_DIR / (name + '.gz')
        with host.open('xb') as stream:
            stream.write(gz)
        p.digest(host)
        script = sdk.stage_gzip_command(name, plain_digest, plain_size, silence)
        second = None
    elif route_name == 'chunk':
        with source.open('rb') as stream:
            data = stream.read()
        chunks = (data[:CHUNK_PART], data[CHUNK_PART:])
        p.require(len(chunks[0]) <= CHUNK_PART and len(chunks[1]) <= CHUNK_PART,
                  'chunk part exceeds the reviewed upload bound: ' + name)
        host = GZ_HOST_DIR / (name + '.a')
        with host.open('xb') as stream:
            stream.write(chunks[0])
        second = GZ_HOST_DIR / (name + '.b')
        with second.open('xb') as stream:
            stream.write(chunks[1])
        script = sdk.stage_cat_command(name, (name + '.a', name + '.b'),
                                       plain_digest, plain_size, silence)
    else:
        raise TransportFailure('unknown transport route: ' + str(route_name))
    sized = script.replace(silence, '9' * 20)
    p.require(len(sized) <= sdk.MAX_SCRIPT, 'transport script exceeds the reviewed frame: ' + name)
    return {
        'route': route_name, 'name': name, 'source': source,
        'digest': plain_digest, 'size': plain_size,
        'host': host, 'second': second,
        'upload_name': host.name, 'script': script,
    }


def ensure_host_dir():
    """Create the host transport staging directory before any route decision.

    r9 created it only inside prepare_plans(), which runs only when an
    oversized asset is carried; the unconditional rmtree() at the end of every
    session then deleted a directory that never existed, so every all-small
    asset set (all three gate ops) failed host-side after the remote claim.
    The directory is now created up front, must be empty, and is always the
    one that gets removed.
    """
    GZ_HOST_DIR.mkdir(parents=True, exist_ok=True)
    p.require(list(GZ_HOST_DIR.iterdir()) == [], 'transport staging directory is stale')


def prepare_plans(assets, route_name):
    """Validates and materializes every transport plan (host-only)."""
    ensure_host_dir()
    routes = {}
    for name, source in assets.items():
        p.require(Path(source).stat().st_size <= sdk.MAX_UPLOAD
                  or name in OVERSIZED, 'oversized asset outside the plan: ' + name)
    # Route only the oversized assets the caller carries; smaller assets
    # travel the small-file channel (the trimmed gate agent is no longer
    # oversized; dirread does not carry a large agent plan).
    for name in OVERSIZED:
        if name not in assets:
            continue
        routes[name] = build_plan(route_name, name, assets[name])
    return routes


async def stage_files(trial, assets):
    """Replicates trial.Trial.stage for the whole asset set."""
    ensure_host_dir()
    manifest_path = assets['files.sha256']
    tar_asset = p.PKG + '.tar.gz'
    small, big = [], []
    for name, source in assets.items():
        (big if Path(source).stat().st_size > sdk.MAX_UPLOAD else small).append(name)
    p.require(set(big) <= set(OVERSIZED), 'oversized asset outside the plan: ' + str(big))
    for name in small:
        sdk.prepare_upload(assets[name], p.STAGE + '/' + name, '9' * 20 + ':' + '9' * 20)
    if big:
        probe = (await trial.read('transport-route-probe',
                                  'if command -v gzip > /dev/null; then echo gzip-present; '
                                  'else echo gzip-missing; fi')).strip()
        p.require(probe in ('gzip-present', 'gzip-missing'), 'unexpected route probe output')
        route_name = 'gzip' if probe == 'gzip-present' else 'chunk'
        trial.save('transport-route-selected', route=route_name, probe=probe)
        routes = prepare_plans({name: assets[name] for name in big}, route_name)
        for plan in routes.values():
            for host in (plan['host'], plan['second']):
                if host is None:
                    continue
                sdk.prepare_upload(host, p.STAGE + '/' + host.name,
                                   '9' * 20 + ':' + '9' * 20)
    else:
        routes = {}
    p.require(await trial.read('sdk-root', 'readlink -f ' + p.ROOT) == p.CANON,
              'SDK root redirected')
    p.require(await trial.read('on-demand', 'readlink -f ' + p.DEMAND)
              == p.CANON + '/on-demand', 'on-demand parent missing or redirected')
    for path in (p.STAGE, p.DEMAND + '/' + tar_asset, p.DEMAND + '/' + tar_asset + '.signature'):
        p.require(await trial.metadata(path) is None, 'staging collision')
    trial.control_hash, trial.manifest_hash = (p.digest(assets['stage.sh']),
                                               p.digest(manifest_path))
    trial.claim_attempted = True
    value = (await trial.read('exclusive-claim',
                             'cd -P ' + p.ROOT + ' && test "$PWD" = ' + p.CANON +
                             ' && umask 077 && mkdir -m 700 -- ' + p.PKG +
                             " && stat -c '%d:%i' " + p.PKG)).strip()
    p.require(re.fullmatch('[0-9]+:[0-9]+', value),
              'unknown result of exclusive staging claim')
    trial.stage_id = value
    trial.save('stage-owned', path=p.STAGE, identity=value)

    async def push_and_verify(name, source, digest):
        target = p.STAGE + '/' + name
        await trial.check_stage()
        p.require(await trial.metadata(target) is None, 'upload destination exists: ' + name)
        trial.save('upload-request', path=target)
        await trial.sdk.push(source, target, stage_id=trial.stage_id)
        p.require((await trial.read('upload-hash', 'sha256sum ' + target))
                  == digest + '  ' + target, 'upload verification: ' + name)

    for name in small:
        await push_and_verify(name, assets[name], p.digest(assets[name]))
    for plan in routes.values():
        if plan['route'] == 'gzip':
            await push_and_verify(plan['upload_name'], plan['host'], p.digest(plan['host']))
        else:
            await push_and_verify(plan['upload_name'], plan['host'], p.digest(plan['host']))
            await push_and_verify(plan['name'] + '.b', plan['second'], p.digest(plan['second']))
        assembler = plan['script'].replace('0' * 20, trial.stage_id)
        receipt = (await trial.read('transport-assemble-' + plan['name'], assembler)).strip()
        lines = receipt.splitlines()
        p.require(lines and lines[-1] == plan['digest'] + '  ' + plan['name'],
                  'transport digest verification: ' + plan['name'])
        trial.save('transport-assembled', name=plan['name'], route=plan['route'],
                   size=plan['size'], digest=plan['digest'])
    shutil.rmtree(GZ_HOST_DIR, ignore_errors=False)
    trial.save('transport-host-cleaned')
    await trial.control('publish')
