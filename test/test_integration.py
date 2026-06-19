"""End-to-end tests for airgap: run a program under it and observe the redacted view.

All tests are skipped automatically unless the airgap binary is built and has
CAP_SYS_ADMIN (see conftest.py).

Program names are passed bare (`cat`, `sh`, `python3`, ...); airgap resolves them
against PATH, so we don't hard-code absolute paths.
"""

import subprocess
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


# Credential keys airgap redacts in .npmrc (matched case-insensitively against
# the key's suffix), mirroring `redact::is_npmrc_secret_key`.
NPMRC_SECRET_SUFFIXES = ("_authtoken", "_auth", "_password")


def _is_npmrc_comment(line):
    return line.lstrip().startswith(("#", ";"))


def _is_npmrc_secret_key(key):
    return key.strip().lower().endswith(NPMRC_SECRET_SUFFIXES)


def parse_npmrc(text):
    """Parse `.npmrc` into a dict, skipping comments. Values are kept verbatim
    (npmrc keys like `//registry/:_authToken` are themselves meaningful)."""
    out = {}
    for line in text.splitlines():
        if _is_npmrc_comment(line) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value
    return out


def expected_npmrc_redaction(original_text):
    """The exact redacted view airgap should serve for a given .npmrc: secret
    values replaced by the placeholder, every other line (registries, scopes,
    email, comments, blanks) preserved verbatim."""
    out = []
    for line in original_text.split("\n"):
        if not _is_npmrc_comment(line) and "=" in line:
            key, _, _value = line.partition("=")
            if _is_npmrc_secret_key(key):
                out.append(f"{key}={PLACEHOLDER}")
                continue
        out.append(line)
    return "\n".join(out)


# --- child-program allowlist -----------------------------------------------

# The allowlist check runs *before* any privileged namespace setup, so these
# work whether or not airgap has CAP_SYS_ADMIN; they drive the binary directly
# rather than through the `airgap` fixture (which always passes the opt-out).


def _raw_run(airgap_bin, *args, cwd):
    return subprocess.run(
        [str(airgap_bin), *args], cwd=cwd, capture_output=True, text=True
    )


def test_unknown_program_is_rejected(airgap_bin, tmp_path):
    result = _raw_run(airgap_bin, "cat", "/etc/hostname", cwd=tmp_path)
    assert result.returncode == 1
    assert "refusing to run" in result.stderr.lower()
    # Pre-flight refusal: the program never ran, so it produced no output.
    assert result.stdout == ""


def test_allow_unknown_program_bypasses_check(airgap_bin, tmp_path):
    # With the opt-out the recognition check no longer fires. (It may still fail
    # later for lack of CAP_SYS_ADMIN, but never with the "refusing to run"
    # refusal.)
    result = _raw_run(airgap_bin, "--allow-unknown-program", "true", cwd=tmp_path)
    assert "refusing to run" not in result.stderr.lower()


# --- npm profile: the file-access gate -------------------------------------


def test_npm_profile_denies_unapproved_file_without_tty(airgap):
    # `--profile npm` forces the package-manager file gate onto any program (here
    # `cat`). With no controlling terminal (start_new_session=True), the gate
    # cannot prompt for a non-pre-approved file and fails closed: the read is
    # denied with EACCES, so cat can't read it at all (let alone the real secret).
    result = airgap(
        "cat",
        ".env",
        airgap_flags=["--profile", "npm"],
        start_new_session=True,
    )
    assert result.returncode != 0
    assert "permission denied" in result.stderr.lower()
    assert PLACEHOLDER not in result.stdout
    assert "s3cr3t_pw" not in result.stdout


def test_npm_profile_allows_preapproved_path_without_prompting(airgap):
    # A pre-approved path ($CWD/package.json) is allowed without ever prompting,
    # so the read succeeds even with no controlling terminal — proving the
    # allowlist short-circuits the gate (a regression that dropped it would deny
    # here, since there's no tty to approve through).
    (airgap.workdir / "package.json").write_text('{"name":"demo"}\n')
    result = airgap(
        "cat",
        "package.json",
        airgap_flags=["--profile", "npm"],
        start_new_session=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == '{"name":"demo"}\n'


def test_npm_profile_reads_npmrc_ungated_and_redacted(airgap):
    # `.npmrc` is pre-approved for the npm profile (npm reads it constantly), so
    # the read succeeds with no controlling terminal — yet credentials are still
    # redacted by the overlay, which is why allowing it is safe.
    expected = expected_npmrc_redaction((airgap.workdir / ".npmrc").read_text())
    result = airgap(
        "cat",
        ".npmrc",
        airgap_flags=["--profile", "npm"],
        start_new_session=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected
    assert "npm_fake0123456789abcdefghijKLMNOPqrstuv" not in result.stdout


# --- agent profile: redaction, no gate -------------------------------------


def test_agent_profile_redacts_without_gating(airgap):
    # The agent profile has no file gate, so reads succeed with no controlling
    # terminal (unlike the npm profile, which would deny) — and secrets are still
    # redacted.
    expected = expected_env_redaction((airgap.workdir / ".env").read_text())
    result = airgap(
        "cat",
        ".env",
        airgap_flags=["--profile", "agent"],
        start_new_session=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected


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


# --- .npmrc redaction on read ----------------------------------------------


def test_npmrc_read_is_exactly_redacted(airgap):
    # The credential values are replaced by the placeholder; registries, scopes,
    # email, and comments survive verbatim.
    original = (airgap.workdir / ".npmrc").read_text()
    result = airgap("cat", ".npmrc")
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected_npmrc_redaction(original)


def test_npmrc_secret_values_never_leak(airgap):
    # No fake credential from the fixture appears in the redacted view, while the
    # public config the child legitimately needs stays readable.
    result = airgap("cat", ".npmrc")
    assert result.returncode == 0, result.stderr
    for secret in (
        "npm_fake0123456789abcdefghijKLMNOPqrstuv",  # npmjs _authToken
        "ghp_fakeGITHUBpackagestokenABCDEF123456",  # github pkg _authToken
        "czNjcjN0X3B3",  # _password (base64)
        "dXNlcjpzM2NyM3RfcHc=",  # _auth (base64)
    ):
        assert secret not in result.stdout
    for visible in (
        "registry=https://registry.npmjs.org/",
        "@acme:registry=https://npm.pkg.github.com/",
        "email=dev@example.com",
        "always-auth=true",
    ):
        assert visible in result.stdout


def test_npmrc_nonsecret_edit_persists_and_token_restored(airgap):
    # The child (seeing redacted tokens) edits a non-secret line and writes the
    # file back. The edit persists, and the tokens it never saw are restored to
    # their real values — not left as the placeholder.
    script = textwrap.dedent(
        """
        lines = open('.npmrc').read().splitlines()
        out = ['registry=https://example.com/' if l.startswith('registry=') else l
               for l in lines]
        open('.npmrc', 'w').write('\\n'.join(out) + '\\n')
        """
    )
    result = airgap("python3", "-c", script)
    assert result.returncode == 0, result.stderr

    persisted = parse_npmrc((airgap.workdir / ".npmrc").read_text())
    assert persisted["registry"] == "https://example.com/"
    assert (
        persisted["//registry.npmjs.org/:_authToken"]
        == "npm_fake0123456789abcdefghijKLMNOPqrstuv"
    )
    assert PLACEHOLDER not in (airgap.workdir / ".npmrc").read_text()


def test_npmrc_token_edit_persists(airgap):
    # A deliberate change to a token value is written through verbatim.
    script = textwrap.dedent(
        """
        key = '//registry.npmjs.org/:_authToken='
        lines = open('.npmrc').read().splitlines()
        out = [key + 'npm_rotated' if l.startswith(key) else l for l in lines]
        open('.npmrc', 'w').write('\\n'.join(out) + '\\n')
        """
    )
    result = airgap("python3", "-c", script)
    assert result.returncode == 0, result.stderr

    persisted = parse_npmrc((airgap.workdir / ".npmrc").read_text())
    assert persisted["//registry.npmjs.org/:_authToken"] == "npm_rotated"


# --- symlinked secrets cannot bypass the overlay ---------------------------


def test_symlinked_secret_outside_overlay_is_redacted(airgap, tmp_path_factory):
    # A secret living OUTSIDE any overlay, reached via a symlink INSIDE it, must
    # still be redacted: otherwise the kernel would follow the link to the raw
    # target and leak it. airgap presents the link as a redacted regular file.
    outside = tmp_path_factory.mktemp("dotfiles")
    real = outside / ".npmrc"
    real.write_text(
        "registry=https://registry.npmjs.org/\n"
        "//registry.npmjs.org/:_authToken=npm_SYMLINK_SECRET\n"
    )
    link = airgap.workdir / ".npmrc"
    link.unlink()  # replace the fixture file with a symlink to the outside secret
    link.symlink_to(real)

    result = airgap("cat", ".npmrc")
    assert result.returncode == 0, result.stderr
    assert "npm_SYMLINK_SECRET" not in result.stdout
    assert "//registry.npmjs.org/:_authToken=<redacted value>" in result.stdout
    # The non-secret line is still served.
    assert "registry=https://registry.npmjs.org/" in result.stdout


def test_symlinked_env_outside_overlay_is_redacted(airgap, tmp_path_factory):
    # Same bypass, for a .env symlinked out of the overlay.
    outside = tmp_path_factory.mktemp("envdir")
    real = outside / ".env"
    real.write_text("API_KEY=leakme-via-symlink\n")
    link = airgap.workdir / ".env.linked"  # `.env.<suffix>` matches the handler
    link.symlink_to(real)

    result = airgap("cat", ".env.linked")
    assert result.returncode == 0, result.stderr
    assert "leakme-via-symlink" not in result.stdout
    assert result.stdout == 'API_KEY="<redacted value>"\n'


# --- the home directory gets its own overlay -------------------------------


def test_home_outside_cwd_is_redacted(airgap, tmp_path_factory):
    # A $HOME disjoint from the working directory is mounted as a second overlay,
    # so secrets there are redacted just like those under cwd.
    home = tmp_path_factory.mktemp("fakehome")
    secret = home / ".env"
    secret.write_text("SECRET=topsecret\nTOKEN=abc123\n")

    result = airgap("cat", str(secret), env={"HOME": str(home)})
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected_env_redaction(secret.read_text())


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
