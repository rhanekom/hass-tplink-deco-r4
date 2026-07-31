# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Home Assistant custom component (`tplink_deco_r4`) that talks to TP-Link **Deco**
mesh routers running 2026-era firmware, for extra monitoring in Home Assistant
(mesh nodes, connected clients, WAN/uplink state).

It exists because the established Deco integrations
([amosyuen/ha-tplink-deco](https://github.com/amosyuen/ha-tplink-deco) and
[roquerodrigo/ha-tplink-deco](https://github.com/roquerodrigo/ha-tplink-deco) plus
its `tplink-deco-api` library) implement the older `;stok=/login?form=keys` RSA
login flow, which this firmware no longer serves: the login transport was replaced
wholesale, so those integrations cannot authenticate at all. This repo implements
the new flow.

**Reference hardware:** Deco **E4R** (master node), firmware **1.3.1 Build 20260403
Rel. 8727**. Old hardware, recent hardened firmware. All protocol work is validated
against that unit. It is not known which other models/builds present the same
interface, so the domain is deliberately `tplink_deco_r4` (this router's interface)
rather than a claim over the whole Deco range. Record the model + firmware of any
other device a finding is confirmed on.

**Status: scaffolding only.** The repository currently holds the dev environment,
tooling and CI; the integration itself is unimplemented (`custom_components/tplink_deco_r4`
is a stub package). Write the protocol spec into `doc/` and keep `doc/TODO.md`
current as work lands.

## Common Commands

Dependencies are managed with **uv**; commands run inside the uv `.venv` via
`uv run`.

### Development

```bash
.devcontainer/scripts/setup    # Bootstrap the container (user setup + uv sync + hooks)
.devcontainer/scripts/develop  # Start a local Home Assistant instance (port 8123)
.devcontainer/scripts/clean    # Reset Home Assistant config directory
uv sync                        # Install/refresh the .venv from pyproject.toml + uv.lock
uv add --dev <pkg>             # Add a dev dependency (updates pyproject.toml + uv.lock)
```

### Linting & Formatting

```bash
.devcontainer/scripts/lint         # uv run ruff format + ruff check --fix
uv run ruff check .                # Lint only (CI uses this)
uv run ruff format . --check       # Format check only (CI uses this)
uv run pre-commit run --all-files  # Run all hooks
```

Pre-commit hooks: pre-commit-hooks (json/yaml/toml validation, hygiene,
detect-private-key), codespell, ruff (+ ruff-format), mypy, markdownlint,
shellcheck, actionlint, check-jsonschema, zizmor, gitleaks (secret scanning),
uv-lock, pip-audit (dependency vulnerabilities), pytest (full test suite, runs
when any `.py` file is staged), duplicate-code (pylint's copy/paste detector over
`custom_components/tplink_deco_r4`; config in `pyproject.toml [tool.pylint]`).

### Testing

```bash
uv run pytest tests/                  # Run all tests
uv run pytest tests/test_foo.py       # Run a single test file
uv run pytest tests/test_foo.py::test_bar -v  # Run a single test
```

Tests use `pytest-homeassistant-custom-component` which provides Home Assistant's test infrastructure.

**Code must be accompanied by tests.** Every change to integration source
(`custom_components/tplink_deco_r4/`) lands with tests that cover it: new behaviour
gets new tests, bug fixes get a regression test. Home Assistant components,
`hass`, config entries, and the like are **mocked out** via
`pytest-homeassistant-custom-component` (its `MockConfigEntry`, `hass` fixture,
and helpers), and router calls are mocked too. Never require a live HA instance or
a real router in a test. The `pytest` pre-commit hook runs the full suite whenever
a `.py` file is staged, so tests must pass before a commit completes.

## Working against real hardware

The router is a live piece of household infrastructure, so treat it as read-mostly:

- **Monitoring first.** Prefer read-only endpoints; anything that changes router
  configuration needs the user's explicit go-ahead before it is called against
  real hardware.
- **Captures are secrets.** HAR/pcap captures of the web UI contain admin
  credentials, session tokens and the household device list. They are gitignored
  (`*.har`, `*.pcap`, `*.pcapng`, `scripts/in/`, `scripts/out/`); keep them out of
  commits and redact tokens/MACs before pasting anything into docs or issues.
- **Credentials** come from the untracked repo-root `.env` (copy `.env.example`);
  never hard-code them or commit them.

## Dependencies

- **Dev/tooling deps** live in `pyproject.toml` (`[dependency-groups] dev`), locked
  in `uv.lock`, installed into `.venv` by `uv sync`. There is **no
  `requirements.txt`** - pyproject + uv.lock are the single source of truth.
- **Runtime deps of the integration** go in
  `custom_components/tplink_deco_r4/manifest.json` (the `requirements` key). Home
  Assistant reads that and pip-installs those packages **at launch**, into the
  running HA environment - they are *not* installed by `uv sync`.
- **Mirror manifest.json requirements into `[project].dependencies`.** Because HA
  only installs them at runtime, our tooling (ruff, mypy, pytest, Pylance) can't
  see them otherwise. Whenever you add/bump a requirement in `manifest.json`, add
  the matching entry to `[project].dependencies` in `pyproject.toml` and run
  `uv sync`. Keep dev/test tooling (HA itself, ruff, pytest, ...) in the `dev`
  group, **not** in `[project].dependencies`.
- **Dependency vuln scanning is scoped to our tree.** The `pip-audit` pre-commit
  hook audits `uv export --no-dev`, i.e. `[project].dependencies` only. HA's large
  transitive tree (the `dev` group) is deliberately excluded, since we don't
  control it. This is why runtime deps must go in `[project].dependencies`.
- **Dependabot** (`.github/dependabot.yml`, `uv` ecosystem) updates dependencies but
  **excludes `homeassistant`** - its version tracks the `hacs.json` floor, so a
  Dependabot bump would break that.

## Dev Environment

The container splits setup by scope, so the frequently-run `setup` stays fast:

- **`.devcontainer/Dockerfile`** - global, machine-wide installs (system apt
  packages, standalone tool binaries: gh, gitleaks, actionlint, uv). Baked into
  the cached image; changes rarely.
- **`.devcontainer/scripts/setup`** - user-specific and project setup (shell
  config, Claude Code, `uv sync`, pre-commit hooks). Runs on every container
  (re)create via `postCreateCommand`.

If you need a tool that isn't installed, install it **and persist it**: global
tools go in the Dockerfile, user/project tools go in the `setup` script. Never
rely on an ad-hoc install that vanishes on the next rebuild.

Container rebuild gotchas:

- `uv sync` restores the venv from `uv.lock` after a rebuild.
- `.git` ownership gotcha: setup can leave `.git/objects/*` root-owned, blocking
  `git add` - fix with `sudo chown -R vscode:vscode .git`.
- `.env` (creds) and `scripts/in/` + `scripts/out/` (captures) are gitignored -
  keep them out of commits.

## MCP Launchpad (`mcpl`)

`mcpl` is a CLI gateway to tools from all configured MCP servers. The user's MCP
config can change at any time, so **when a task needs a capability outside the
current tools, check `mcpl` first.**

- **Always discover before calling - never guess tool names** (they vary by
  server). Search, then call:

  ```bash
  mcpl search "<query>"            # find tools across servers (shows required params)
  mcpl list <server>              # list a server's tools
  mcpl inspect <server> <tool> --example   # full schema + ready-to-use example call
  mcpl call <server> <tool> '{"param": "value"}'   # execute
  mcpl verify                     # test all server connections
  ```

## Ruff Configuration

All lint rules enabled (`select = ["ALL"]`) with specific exclusions. Target: Python 3.14. Max complexity: 25. Test files have relaxed rules (asserts, magic values, missing docstrings allowed). See `.ruff.toml` for details.

- **Prefer inline suppression over global suppression.** To silence a lint rule in
  integration code (`custom_components/`), use a targeted inline `# noqa: <CODE>`
  (with a reason) on the offending line. Do **not** add a rule to `ignore` or
  `per-file-ignores` in `.ruff.toml`. The only exceptions are the `tests/` and
  `scripts/` directories, whose `per-file-ignores` blocks in `.ruff.toml` are the
  accepted place to relax rules wholesale (test/CLI ergonomics). All integration
  code stays under full linting with inline `noqa`.

## CI/CD

Three GitHub Actions workflows on push/PR to main:

- **lint.yml** - `ruff check` and `ruff format --check`
- **test.yml** - `mypy` and `pytest`
- **validate.yml** - Home Assistant `hassfest` manifest validation and HACS validation

## Branching and releases

The repo uses a two-branch model:

- **`main` is protected** - no direct pushes (enforced for admins too); every change
  lands via a **pull request**. Self-merge is allowed (0 required approvals), so a
  solo maintainer opens a PR and merges it once CI is green.
- **`develop`** is the day-to-day integration branch. Do work on `develop` (or feature
  branches off it) and open the PR into `main`.

**Release process:**

1. Land everything for the release on `main` via PR, bumping the `version` in
   `custom_components/tplink_deco_r4/manifest.json` in that PR.
2. From `main` (green CI, clean tree), tag it:
   `git tag -a vX.Y.Z -m "TP-Link Deco R4 vX.Y.Z" && git push origin vX.Y.Z`.
3. Publish: `gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <notes> --latest`.
4. HACS installs the **latest GitHub release**, so real releases are `--latest` (use
   `--prerelease` only for betas). Do **not** bump `homeassistant` in `hacs.json` /
   Dependabot for a routine release - it is the support floor, not the target.

## Working Conventions

- **Never auto-commit or push** - always ask first, **every time**. A prior
  approval to commit/push does **not** carry forward to later commits; re-ask for
  each one, even mid-session.
- **Don't branch automatically** - the user handles branching. Day-to-day work lands
  on `develop`; `main` is protected and reached only via PR (see Branching and
  releases).
- **No self-attribution** - do not add "Authored by / Generated with Claude Code"
  or `Co-Authored-By` lines to commits, PRs, or any artifact.
- **When you do commit, commit all changed and new files** (`git add -A`). Never
  create partial commits - every commit includes the complete set of changes.
- **Before finalizing a commit, check for secrets and accidental files** - scan
  the staged diff for credentials/keys/captures and for anything that shouldn't be
  committed (`.venv`, config artifacts, scratch files) and stop if found.
- **Don't let issues hang.** Surface problems proactively; fix low-impact ones
  directly, ask before fixing high-impact ones. Never bypass failing checks,
  broken tests, or other issues just to keep going.
- **Code must be accompanied by tests.** New/changed integration code lands with
  tests; mock Home Assistant with `pytest-homeassistant-custom-component` (see
  Testing above). The `pytest` pre-commit hook enforces this on every `.py` change.
- **Debugging / diagnostic tools go in `scripts/`, never in
  `custom_components/tplink_deco_r4/`.** The component package ships to users and
  stays runtime-only; standalone CLIs, live-verification probes, and one-off
  debugging helpers live in `scripts/` (see `scripts/README.md`), where `.ruff.toml`
  relaxes CLI-ergonomics rules and the `.env` credential pattern lives. Reusable
  logic a script needs stays in the component (and is tested there); the script only
  imports it. They add the repo root to `sys.path` to import
  `custom_components.tplink_deco_r4.*`.
- **Research, don't assume** - verify options (including via web search) rather
  than assuming APIs/libraries behave as described.
- **If something can be caught by a pre-commit hook, add it** - prefer enforcing a
  rule mechanically over relying on memory.
- **No em-dashes.** Do not use em-dashes in prose, docs, comments, or any
  authored text. Use a plain hyphen (`-`) instead, or restructure the sentence.
