"""Run the demo deployment in an isolated local Molecule project."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path

from vpnforge.ansible_runner import AnsibleRun
from vpnforge.models import DeployRequest

SCENARIOS = Path(__file__).resolve().parent.parent / "ansible" / "demo" / "molecule"


async def run(
    molecule: str, work_dir: Path, req: DeployRequest, timeout: int
) -> AnsibleRun:
    shutil.copytree(SCENARIOS, work_dir / "molecule")
    demo_spec = {
        "target": req.ip.strip(),
        "domain": req.domain,
        "runtime": req.runtime,
        "protocols": [name for name, enabled in req.protocols if enabled],
    }
    (work_dir / "demo-input.json").write_text(
        json.dumps({"demo_spec": demo_spec}), encoding="utf-8"
    )

    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("ANSIBLE_", "MOLECULE_", "VPNFORGE_"))
    }
    env.update(
        ANSIBLE_HOME=str(work_dir / ".ansible"),
        ANSIBLE_NOCOLOR="1",
        ANSIBLE_REMOTE_TEMP=str(work_dir / ".ansible" / "remote-tmp"),
        NO_COLOR="1",
        PYTHONUNBUFFERED="1",
        XDG_CACHE_HOME=str(work_dir / ".cache"),
    )
    process_group = os.name == "posix"
    proc = await asyncio.create_subprocess_exec(
        molecule,
        "test",
        cwd=work_dir,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        start_new_session=process_group,
    )
    return AnsibleRun(proc, timeout=timeout, process_group=process_group)
