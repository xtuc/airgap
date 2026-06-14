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

# The integration tests always exercise the debug build at this path.
AIRGAP_BIN = REPO_ROOT / "target" / "debug" / "airgap"


@pytest.fixture(scope="session")
def airgap_bin():
    return AIRGAP_BIN


@pytest.fixture(scope="session")
def airgap_ready(airgap_bin, tmp_path_factory):
    """Skip the suite unless airgap can actually set up its namespace + mount."""
    probe = tmp_path_factory.mktemp("airgap_probe")
    marker = "__airgap_ready__"
    # `echo` isn't a recognized program, so the probe opts out of the profile
    # check to test only namespace/mount readiness.
    proc = subprocess.run(
        [
            str(airgap_bin),
            "--allow-unknown-program",
            shutil.which("echo") or "/bin/echo",
            marker,
        ],
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

    The test programs (`cat`, `sh`, `python3`, ...) aren't recognized programs,
    so `--allow-unknown-program` is passed by default to run them ungated. Pass
    `airgap_flags=[...]` to use different leading airgap flags (e.g.
    `["--profile", "npm"]` to exercise the directory gate). Extra subprocess
    kwargs (e.g. `start_new_session=True`) are forwarded to `subprocess.run`.
    """

    def _run(*args, **kwargs):
        flags = kwargs.pop("airgap_flags", ["--allow-unknown-program"])
        env = {**os.environ, "HOME": str(workdir), **kwargs.pop("env", {})}
        return subprocess.run(
            [str(airgap_ready), *flags, *args],
            cwd=workdir,
            capture_output=True,
            text=True,
            env=env,
            **kwargs,
        )

    _run.workdir = workdir
    return _run
