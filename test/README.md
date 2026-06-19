# Integration tests

End-to-end tests that run the real `airgap` binary against fixture files
containing **fake** secrets (`fixtures/`), and assert that:

- the wrapped program's exit code, stdout, and plain files pass through unchanged;
- `.env` values are redacted on read while keys stay visible;
- edits, additions, and deletions to `.env` are persisted to the real file;
- SSH (RSA, ed25519) and PGP private keys are redacted by content sniffing.

## Setup

A virtualenv lives at `.venv` (gitignored). Create/refresh it with:

```
python3 -m venv .venv
.venv/bin/pip install pytest
```

## Running

```
cargo build --release
.venv/bin/pytest test/
```

`airgap` sets up its namespace from an unprivileged user namespace, so the suite
runs as a normal user with no extra setup. If the binary isn't built, or the
kernel disables unprivileged user namespaces (and the binary has no
`CAP_SYS_ADMIN`), the suite **skips** itself with an explanatory message instead
of failing.
