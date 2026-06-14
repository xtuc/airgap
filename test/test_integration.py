"""End-to-end tests for airgap: run a program under it and observe the redacted view.

All tests are skipped automatically unless the airgap binary is built and has
CAP_SYS_ADMIN (see conftest.py).

Program names are passed bare (`cat`, `sh`, `python3`, ...); airgap resolves them
against PATH, so we don't hard-code absolute paths.
"""

import textwrap

import pytest

PLACEHOLDER = "<redacted value>"


def parse_env(text):
    """Parse `.env` text into a dict, stripping surrounding quotes from values."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def expected_env_redaction(original_text):
    """The exact redacted view airgap should serve for a given .env: keys kept,
    in order, every value replaced by the quoted placeholder."""
    keys = parse_env(original_text).keys()
    return "".join(f'{key}="{PLACEHOLDER}"\n' for key in keys)


def expected_key_redaction(original_text):
    """The exact redacted view for a private key: BEGIN/END markers kept
    verbatim, everything between collapsed to a single placeholder line."""
    lines = original_text.splitlines()
    return f"{lines[0]}\n{PLACEHOLDER}\n{lines[-1]}\n"


# --- transparency / passthrough -------------------------------------------


def test_exit_code_propagates(airgap):
    assert airgap("sh", "-c", "exit 7").returncode == 7


def test_stdout_passthrough(airgap):
    result = airgap("echo", "hello-world")
    assert result.returncode == 0
    assert "hello-world" in result.stdout


def test_plain_file_untouched(airgap):
    result = airgap("cat", "notes.txt")
    assert result.returncode == 0
    assert result.stdout == (airgap.workdir / "notes.txt").read_text()


# --- .env redaction on read ------------------------------------------------


# Both `.env` and any `.env.<suffix>` variant (e.g. `.env.production`) are
# detected by name and redacted identically.
@pytest.mark.parametrize("path", [".env", ".env.production"])
def test_env_read_is_exactly_redacted(airgap, path):
    expected = expected_env_redaction((airgap.workdir / path).read_text())
    result = airgap("cat", path)
    assert result.returncode == 0
    assert result.stdout == expected


# --- redaction is inherited by deeply nested children ----------------------

# A program that re-execs itself `depth` times before reading .env, to prove the
# mount namespace (and thus redaction) is inherited all the way down the tree.
NEST = textwrap.dedent(
    """
    import sys, subprocess
    depth, script = int(sys.argv[1]), sys.argv[2]
    if depth > 0:
        sys.exit(subprocess.run(
            [sys.executable, "-c", script, str(depth - 1), script]
        ).returncode)
    sys.stdout.write(open(".env").read())
    """
)


def test_deeply_nested_child_sees_redaction(airgap):
    expected = expected_env_redaction((airgap.workdir / ".env").read_text())
    result = airgap("python3", "-c", NEST, "8", NEST)
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected


# --- .env edits persist back to the real file ------------------------------


def test_env_edit_persists(airgap):
    # The child sees DEBUG="<redacted value>"; change it to a real value.
    script = textwrap.dedent(
        """
        lines = open('.env').read().splitlines()
        out = ['DEBUG=false' if l.startswith('DEBUG=') else l for l in lines]
        open('.env', 'w').write('\\n'.join(out) + '\\n')
        """
    )
    result = airgap("python3", "-c", script)
    assert result.returncode == 0, result.stderr

    persisted = parse_env((airgap.workdir / ".env").read_text())
    assert persisted["DEBUG"] == "false"
    # Untouched values keep their original secret (not the placeholder).
    assert "s3cr3t_pw" in persisted["DATABASE_URL"]


def test_env_add_persists(airgap):
    script = textwrap.dedent(
        """
        with open('.env', 'a') as f:
            f.write('NEW_TOKEN=added-by-agent\\n')
        """
    )
    result = airgap("python3", "-c", script)
    assert result.returncode == 0, result.stderr

    persisted = parse_env((airgap.workdir / ".env").read_text())
    assert persisted.get("NEW_TOKEN") == "added-by-agent"
    assert "s3cr3t_pw" in persisted["DATABASE_URL"]


def test_env_delete_persists(airgap):
    script = textwrap.dedent(
        """
        lines = open('.env').read().splitlines()
        out = [l for l in lines if not l.startswith('API_KEY=')]
        open('.env', 'w').write('\\n'.join(out) + '\\n')
        """
    )
    result = airgap("python3", "-c", script)
    assert result.returncode == 0, result.stderr

    persisted = parse_env((airgap.workdir / ".env").read_text())
    assert "API_KEY" not in persisted
    assert "DATABASE_URL" in persisted


# --- private key redaction (content sniffed) -------------------------------


@pytest.mark.parametrize("path", ["id_rsa", "id_ed25519", "secret.asc"])
def test_private_key_redacted(airgap, path):
    expected = expected_key_redaction((airgap.workdir / path).read_text())
    result = airgap("cat", path)
    assert result.returncode == 0
    assert result.stdout == expected
