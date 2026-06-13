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
sudo setcap cap_sys_admin+ep ./target/release/airgap   # needed once per build
.venv/bin/pytest test/
```

Without a built binary, or without `CAP_SYS_ADMIN` on it, the suite **skips**
itself with an explanatory message instead of failing.
