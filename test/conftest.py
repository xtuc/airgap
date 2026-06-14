"""Shared fixtures for airgap integration tests.

These tests run the real `airgap` binary, which needs CAP_SYS_ADMIN to create a
mount namespace and mount FUSE. If the binary isn't built or doesn't have the
capability, the whole suite is skipped with an explanatory message rather than
failing — grant it with:

    sudo setcap cap_sys_admin+ep <path-to-airgap>
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _find_binary():
    candidate = REPO_ROOT / "target" / "debug" / "airgap"
    return candidate if candidate.exists() else None


@pytest.fixture(scope="session")
def airgap_bin():
    binary = _find_binary()
    if binary is None:
        pytest.skip("airgap binary not built — run `cargo build`")
    return binary


@pytest.fixture(scope="session")
def airgap_ready(airgap_bin, tmp_path_factory):
    """Skip the suite unless airgap can actually set up its namespace + mount."""
    probe = tmp_path_factory.mktemp("airgap_probe")
    marker = "__airgap_ready__"
    proc = subprocess.run(
        [str(airgap_bin), shutil.which("echo") or "/bin/echo", marker],
        cwd=probe,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or marker not in proc.stdout:
        pytest.skip(
            "airgap is not runnable — it needs CAP_SYS_ADMIN and a working build.\n"
            f"  grant it: sudo setcap cap_sys_admin+ep {airgap_bin}\n"
            f"  exit={proc.returncode} stderr={proc.stderr.strip()!r}"
        )
    return airgap_bin


@pytest.fixture
def workdir(tmp_path):
    """A fresh temp dir pre-populated with the fake-secret fixtures."""
    for src in FIXTURES.iterdir():
        if src.is_file():
            shutil.copy(src, tmp_path / src.name)
    return tmp_path


@pytest.fixture
def airgap(airgap_ready, workdir):
    """Run airgap in the fixture workdir. Call as airgap('cat', '.env').

    HOME is pinned to the workdir so the home overlay targets the fixture dir
    (which equals cwd, collapsing to a single mount) rather than the real home
    of whoever runs the suite — keeping tests hermetic and fast.
    """

    def _run(*args, **kwargs):
        env = {**os.environ, "HOME": str(workdir), **kwargs.pop("env", {})}
        return subprocess.run(
            [str(airgap_ready), *args],
            cwd=workdir,
            capture_output=True,
            text=True,
            env=env,
            **kwargs,
        )

    _run.workdir = workdir
    return _run
