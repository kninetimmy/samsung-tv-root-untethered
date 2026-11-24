"""Read checkout identity without modifying its Git administrative directories."""

import os
from pathlib import Path
import re
import shutil

from tools.evidence_workspace import WorkspaceError, make_private, ordinary


def git_identity(batch, worker, root, env, scratch, run):
    git = shutil.which("git")
    if not git:
        raise WorkspaceError("installed Git unavailable; identity incomplete")
    env = {
        **env,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    prefix = [git, "--no-optional-locks", "-c", "core.fsmonitor=false"]
    # rev-parse only reads repository metadata; it neither refreshes the index
    # nor runs configured filters/hooks. Status below never reads local config.
    metadata = (
        run(
            batch,
            worker,
            "git-metadata",
            [
                *prefix,
                "-C",
                str(root),
                "rev-parse",
                "--path-format=absolute",
                "--git-dir",
                "--git-common-dir",
                "HEAD",
            ],
            env,
            scratch,
        )
        .decode()
        .splitlines()
    )
    if len(metadata) != 3 or not re.fullmatch(r"[0-9a-f]{40}", metadata[2]):
        raise WorkspaceError("unsupported Git metadata; identity incomplete")
    admin, common, head = Path(metadata[0]), Path(metadata[1]), metadata[2]
    for path in (admin, common):
        if not path.is_absolute():
            raise WorkspaceError("Git administrative path is not absolute")
        for ancestor in (*reversed(path.parents), path):
            ordinary(ancestor)
    view = batch.root / worker / "git-view"
    make_private(view)
    for name in ("objects", "refs", "info"):
        make_private(view / name)
    batch.write(worker, "git-view/HEAD", (head + "\n").encode())
    batch.write(
        worker,
        "git-view/config",
        b"[core]\nrepositoryformatversion = 0\nbare = false\n",
    )
    # A private administrative view isolates local configuration (including
    # executable filters/fsmonitor) and all potential index/lock writes on E:.
    copies = [(admin / "index", "index")]
    copies.extend((p, p.name) for p in admin.glob("sharedindex.*"))
    for name in ("exclude", "attributes"):
        path = common / "info" / name
        if path.exists():
            copies.append((path, "info/" + name))
    for source, relative in copies:
        ordinary(source)
        batch.write(worker, "git-view/" + relative, source.read_bytes())
    ordinary(common / "objects")
    status = run(
        batch,
        worker,
        "git-status",
        [
            *prefix,
            "--git-dir=" + str(view),
            "--work-tree=" + str(root),
            "status",
            "--porcelain",
            "--ignore-submodules=all",
        ],
        {**env, "GIT_OBJECT_DIRECTORY": str(common / "objects")},
        scratch,
    ).decode()
    return head, status
