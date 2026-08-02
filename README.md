# TP-Link Deco R4

Home Assistant integration for monitoring **TP-Link Deco** mesh routers running
2026-era firmware.

[![Validate](https://github.com/rhanekom/hass-tplink-deco-r4/actions/workflows/validate.yml/badge.svg)](https://github.com/rhanekom/hass-tplink-deco-r4/actions/workflows/validate.yml)
[![Lint](https://github.com/rhanekom/hass-tplink-deco-r4/actions/workflows/lint.yml/badge.svg)](https://github.com/rhanekom/hass-tplink-deco-r4/actions/workflows/lint.yml)
[![HACS: Custom](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://hacs.xyz)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

> **Status: early scaffolding.** This repository currently contains the dev
> environment, tooling and CI only. The integration is not implemented yet, so
> there is nothing to install.

## Why this exists

The established Deco integrations ([amosyuen/ha-tplink-deco](https://github.com/amosyuen/ha-tplink-deco)
and [roquerodrigo/ha-tplink-deco](https://github.com/roquerodrigo/ha-tplink-deco),
plus its `tplink-deco-api` library) implement the older `;stok=/login?form=keys`
RSA login flow. Recent Deco firmware replaced that login transport wholesale, so
those integrations cannot authenticate against it at all: every request to the
legacy path returns a fixed HTTP 401 regardless of credentials. This project
implements the new flow so the routers can be monitored again.

## Tested hardware

Everything here is developed and tested against:

| | |
|---|---|
| **Model** | Deco **E4R** (master node) |
| **Firmware** | 1.3.1 Build 20260403 Rel. 8727 |

That is old hardware running recent, hardened firmware. It is not yet known which
other models and firmware builds serve the same login flow, which is why this
integration uses the neutral domain `tplink_deco_r4` rather than claiming the whole
Deco range: it targets the interface this router actually presents. Reports from
other models are welcome.

## Requirements

- **Home Assistant 2026.3.0 or newer** (the release that adopted Python 3.14).
- A TP-Link Deco mesh with admin (web UI) credentials.

## Known limitations of the router's own interface

These are constraints of the Deco firmware, not of this integration. They were
measured against the reference hardware; see
[`doc/specification.md`](./doc/specification.md) for the evidence.

### Polling logs you out of the router's web UI

**The firmware allows exactly one admin session, and every login evicts the
previous one.** Establishing a new session makes the existing one fail
immediately with HTTP 403. There is no session sharing, no read-only session, and
no keep-alive that coexists with a second login.

The practical effect: while this integration is polling, **anyone logged into the
Deco router's local web UI will be kicked out**, repeatedly, at roughly the
refresh interval. Equally, someone logging into the web UI takes the
integration's session away, and the integration silently logs back in on its next
poll.

There is no workaround at the protocol level. What this integration does about it:

- Re-authenticates and retries transparently, so a stolen session costs one
  extra login rather than a failed update.
- Defaults to a **30 second** refresh interval rather than the 5-10 seconds the
  router's own web UI uses.

If you need to work in the router's web UI uninterrupted, disable the integration
for the duration. Raising the refresh interval widens the gaps but does not
remove the problem.

Whether the TP-Link **cloud** mobile app shares this same local session table has
not been established; the local web UI definitely does.

### The admin password is not a least-privilege credential

Worth knowing before you hand it to anything. The router exposes a low-level
read channel alongside its normal API, and an authenticated session can use it
to read the device's stored secrets, not just its status: factory default
credentials, the local account hash, and cloud account tokens are all reachable.
This integration does not use that channel, but the credential you configure is
capable of it, so treat it with the same care as any other device secret.

### CPU load and memory usage are not real

The firmware's `performance` endpoint returns a **static value**. On the
reference hardware it reports the same figures regardless of load, over time, and
across every node in the mesh, while other endpoints from the same session update
continuously. The numbers look plausible, which is precisely why they are worth
warning about: exposed as sensors they would be flat lines that appear to work.
This integration therefore does not present them as usable metrics.

## Development

The repo ships a devcontainer with everything wired up (uv, ruff, mypy, pytest,
pre-commit, a runnable Home Assistant instance).

```bash
.devcontainer/scripts/setup    # bootstrap (runs automatically on container create)
.devcontainer/scripts/develop  # start Home Assistant on port 8123
.devcontainer/scripts/lint     # ruff format + ruff check --fix
uv run pytest tests/           # run the test suite
uv run pre-commit run --all-files
```

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the contribution flow and
[`CLAUDE.md`](./CLAUDE.md) for the working conventions used in this repo.

## License

Apache-2.0. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
