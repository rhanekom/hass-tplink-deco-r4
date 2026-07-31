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
