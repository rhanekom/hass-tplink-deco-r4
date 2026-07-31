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

## The tools

_None yet._ Add each tool here as it lands: what it does, and the command to run it.

## Output & safety

- Captures and decoded artifacts go only to `scripts/out/` (gitignored).
- `.env` (real credentials) is gitignored - keep it out of commits.
- HAR/pcap captures contain admin credentials, session tokens and the household
  device list. They are gitignored (`*.har`, `*.pcap`, `*.pcapng`); redact
  tokens/MACs before pasting output into docs or issues.
- These tools make real calls to the router with the household's own admin
  credentials. Prefer read-only endpoints.
