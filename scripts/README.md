# `scripts/` - Deco router diagnostic tools

Standalone command-line tools used to reverse-engineer and validate the Deco
router protocol against **real hardware**. They are the manual test harness for
the integration: the protocol logic proven here is what gets ported into
`custom_components/tplink_deco_r4/`. They are **not** part of the shipped Home
Assistant component.

Next actions live in [`../doc/TODO.md`](../doc/TODO.md).

## Prerequisites

- Run everything through uv: `uv run python scripts/<tool>.py ...`.
- **Credentials** come from the untracked repo-root `.env` (copy `.env.example`):
  `DECO_HOST`, `DECO_USERNAME`, `DECO_PASSWORD`. Any script flag (`--host`, ...)
  overrides the env.
- The router serves its admin API over HTTPS with a self-signed certificate, so
  these tools talk to it with certificate verification disabled. Point them only
  at your own router.
- The firmware's TLS stack also needs `OP_LEGACY_SERVER_CONNECT` and
  `SECLEVEL=0` before a modern OpenSSL will complete a handshake at all; see
  `build_ssl_context` in `deco_protocol.py` and section 2.2 of the spec.

## The tools

### `deco_protocol.py` - the protocol client

Not a CLI; the module the other tools import. A working async implementation of
[`../doc/specification.md`](../doc/specification.md): the SSL context this
firmware needs, the crypto primitives (`su_encrypt`, RSA PKCS#1 v1.5 chunking,
AES-128-CBC), the five-step login handshake, logout, the `sign=`/`data=`
envelope, and read-only accessors for the monitoring endpoints. This is the
reference to port into `custom_components/tplink_deco_r4/api.py`.

It is read-only by construction: it only ever sends `operation: read` / `get`,
plus login and logout. No write, reboot or factory operation is implemented.

### `deco_probe.py` - the conformance probe

Runs the protocol against real hardware and checks the specification claim by
claim, printing PASS/FAIL/WARN per claim and exiting non-zero if anything
regressed. Re-run it after a firmware update to see what moved.

```bash
uv run python scripts/deco_probe.py                  # full report, redacted
uv run python scripts/deco_probe.py --check crypto   # offline self-test, no router
uv run python scripts/deco_probe.py --dump           # raw payloads -> scripts/out/
uv run python scripts/deco_probe.py --trace          # log every HTTP request
```

Three checks are **opt-in** because they cost more than a read:

```bash
uv run python scripts/deco_probe.py --check encoding  # logs in once per id encoding
uv run python scripts/deco_probe.py --check soak      # many calls on a fixed seq
uv run python scripts/deco_probe.py --check rates     # downloads tens of MiB
```

`--check rates` settles whether client rates are KB/s or Kbit/s by driving a
known download rate and watching the counters, so it deliberately consumes
household bandwidth (`--rate-kbps`, `--rate-seconds`, `--rate-url` tune it).

### `deco_open_questions.py` - one-off investigations

Answers the specific open questions in
[`../doc/specification.md`](../doc/specification.md) section 10.2, rather than
asserting known answers. Kept separate from the probe because some of these open
several sessions and one runs for the best part of an hour.

```bash
uv run python scripts/deco_open_questions.py all           # the quick ones
uv run python scripts/deco_open_questions.py signal-scale   # range of signal_level
uv run python scripts/deco_open_questions.py slave-perf     # per-node CPU/memory
uv run python scripts/deco_open_questions.py session-evict   # does a login evict?
uv run python scripts/deco_open_questions.py router-mode     # what AP mode shows
uv run python scripts/deco_open_questions.py sessions --max 8      # invasive
uv run python scripts/deco_open_questions.py session-idle --minutes 90  # slow
```

`all` deliberately skips `sessions` (holds several sessions open, so the
household may briefly be unable to log in; always cleaned up) and
`session-idle` (runs for `--minutes`).

## Only one client at a time

**The firmware keeps exactly one session and every login evicts the previous
one.** Two of these tools running at once will fight, and with automatic
re-login they will do so indefinitely. Run one at a time, and expect a live
run to log any human out of the router's web UI. Static `GET`s of
`/config/*.json` and the module JS create no session and are safe to run
alongside anything.

## Output & safety

- **Output is redacted by default.** MACs, IPs, device and client names, SSIDs
  and node identifiers are replaced with stable placeholders (`<mac-1>`,
  `<ip-3>`, ...), so a report can be pasted into an issue as-is. Wireless
  passwords are never printed at all, redacted or otherwise. `--show-values`
  reveals the real values for local use only.
- Captures and decoded artifacts go only to `scripts/out/` (gitignored).
- `.env` (real credentials) is gitignored - keep it out of commits.
- HAR/pcap captures contain admin credentials, session tokens and the household
  device list. They are gitignored (`*.har`, `*.pcap`, `*.pcapng`); redact
  tokens/MACs before pasting output into docs or issues.
- These tools make real calls to the router with the household's own admin
  credentials. Prefer read-only endpoints.
- **A rejected password is never retried.** The router locks the account after
  roughly 10 failed attempts, which would lock the household out of its own
  router. If login fails, the probe stops and says so.
