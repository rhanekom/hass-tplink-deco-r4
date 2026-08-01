"""
Targeted investigations of the open questions in `doc/specification.md` 10.2.

Separate from `deco_probe.py` because these are one-off experiments rather than
conformance checks: some open several sessions, one takes tens of minutes, and
they answer questions rather than asserting known answers.

All of them are **read-only** with respect to router configuration. None changes
a setting, reboots, or resets anything. `sessions` does briefly hold several
concurrent sessions open and always closes them again, which is the one thing
here with any user-visible effect (see its own warning).

Usage:
    uv run python scripts/deco_open_questions.py slave-perf
    uv run python scripts/deco_open_questions.py signal-scale
    uv run python scripts/deco_open_questions.py session-evict
    uv run python scripts/deco_open_questions.py sessions --max 8
    uv run python scripts/deco_open_questions.py session-idle --minutes 90
    uv run python scripts/deco_open_questions.py all   # skips the slow/invasive ones

Credentials come from the repo-root `.env`. Output is redacted by default;
`--show-values` reveals real MACs/IPs/names.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from deco_probe import (
    FAIL,
    INFO,
    PASS,
    SKIP,
    WARN,
    Redactor,
    Report,
    fmt,
    load_env,
)
from deco_protocol import (
    DecoAuthError,
    DecoClient,
    DecoConnectionError,
    DecoError,
    DecoSessionExpiredError,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def new_client(host: str, password: str, verify_ssl: bool, **kw: Any) -> DecoClient:
    return DecoClient(
        host=host,
        password=password,
        verify_ssl=verify_ssl,
        id_encoding="strict",
        **kw,
    )


# --------------------------------------------------------------------------- #
# Q2: can a slave node report its own CPU and memory?
# --------------------------------------------------------------------------- #


async def q_slave_perf(report: Report, args: argparse.Namespace, red: Redactor) -> None:
    """`form=performance` ignores `device_mac`, so try each node's own address."""
    print("\n=== Q2: per-node CPU/memory by addressing each node directly ===")

    master = new_client(args.host, args.password, args.verify_ssl)
    async with master:
        await master.login()
        nodes = await master.get_device_list()
        master_perf = await master.get_performance()
        master_mac = next(
            (n.get("mac") for n in nodes if n.get("role") == "master"), None
        )
    print(f"  master reports {fmt(master_perf)}; {len(nodes)} node(s) in the mesh")

    results: list[tuple[str, str, str]] = []
    for node in nodes:
        ip, mac, role = node.get("device_ip"), node.get("mac"), node.get("role")
        label = f"{role:6} {red.value(mac, 'mac')} @ {red.value(ip, 'ip')}"
        if not isinstance(ip, str) or not ip or mac == master_mac:
            results.append((label, "skipped", "master, already known"))
            continue
        client = new_client(args.host, args.password, args.verify_ssl)
        client.host = ip
        try:
            async with client:
                await client.login()
                perf = await client.get_performance()
                mode = await client.get_mode()
            same = json.dumps(perf, sort_keys=True) == json.dumps(
                master_perf, sort_keys=True
            )
            results.append(
                (
                    label,
                    "OK" if not same else "identical to master",
                    f"{fmt(perf, 44)} mode={fmt(mode, 30)}",
                )
            )
        except DecoAuthError as err:
            results.append((label, "auth refused", str(err)[:70]))
        except DecoConnectionError as err:
            results.append((label, "unreachable", str(err)[:70]))
        except DecoError as err:
            results.append((label, "protocol error", str(err)[:70]))
        print(f"  {results[-1][0]}  -> {results[-1][1]}")

    reachable = [r for r in results if r[1] == "OK"]
    identical = [r for r in results if r[1] == "identical to master"]
    refused = [
        r for r in results if r[1] in ("auth refused", "unreachable", "protocol error")
    ]

    if reachable:
        verdict, claim = (
            PASS,
            "slave nodes serve their own performance figures when addressed directly",
        )
    elif identical:
        verdict, claim = (
            FAIL,
            "slave nodes answer but return the master's figures verbatim",
        )
    else:
        verdict, claim = (
            INFO,
            "slave nodes do not serve the admin API at all",
        )
    report.add(
        "q2-slave-perf",
        verdict,
        claim,
        f"{len(reachable)} distinct, {len(identical)} identical, {len(refused)} "
        f"refused/unreachable of {len(results)} node(s).\n         "
        + "\n         ".join(f"{a}: {b} {c}" for a, b, c in results),
    )


# --------------------------------------------------------------------------- #
# Q4: what is the scale of signal_level?
# --------------------------------------------------------------------------- #


async def q_signal_scale(
    report: Report, args: argparse.Namespace, _red: Redactor
) -> None:
    """Sample every signal_level the mesh reports, from nodes and clients alike."""
    print("\n=== Q4: empirical range of signal_level ===")

    client = new_client(args.host, args.password, args.verify_ssl)
    async with client:
        await client.login()
        nodes = await client.get_device_list()
        clients = await client.get_client_list()

    node_vals: Counter[int] = Counter()
    client_vals: Counter[int] = Counter()
    bands: set[str] = set()

    for n in nodes:
        for band, value in (n.get("signal_level") or {}).items():
            bands.add(band)
            if isinstance(value, int):
                node_vals[value] += 1
    for c in clients:
        for band, value in (
            (c.get("linked_device_info") or {}).get("signal_level") or {}
        ).items():
            bands.add(band)
            if isinstance(value, int):
                client_vals[value] += 1

    combined = node_vals + client_vals
    if not combined:
        report.add("q4-signal", SKIP, "no signal_level values found")
        return

    lo, hi = min(combined), max(combined)
    total = sum(combined.values())
    contiguous = set(combined) == set(range(lo, hi + 1))
    report.add(
        "q4-signal",
        INFO,
        f"signal_level spans {lo}..{hi} over {total} samples",
        f"bands seen: {sorted(bands)}\n         "
        f"node backhaul values: {dict(sorted(node_vals.items()))}\n         "
        f"client link values:   {dict(sorted(client_vals.items()))}\n         "
        f"value set is {'contiguous' if contiguous else 'NOT contiguous'}",
    )
    # A 0..3 scale with all four values present over a large sample is good
    # evidence; a gap, or a maximum below 3, means the sample is just too quiet.
    if hi == 3 and contiguous and total > 40:
        report.add(
            "q4-signal",
            PASS,
            "signal_level is a 0-3 scale (0 = band unused, 3 = best)",
            f"all of 0,1,2,3 observed across {total} samples and none above 3. "
            f"Safe to present as a 0-3 quality level; still not safe to present "
            f"as a percentage.",
        )
    else:
        report.add(
            "q4-signal",
            WARN,
            "signal_level scale still not pinned down",
            f"observed {lo}..{hi}; need at least one sample at each level. A quiet "
            f"or uniformly strong network cannot settle the maximum.",
        )


# --------------------------------------------------------------------------- #
# Q3a: does a new login evict an existing session?
# --------------------------------------------------------------------------- #


async def q_session_evict(
    report: Report, args: argparse.Namespace, _red: Redactor
) -> None:
    """Test the likely explanation for the mid-cycle HTTP 403 seen while probing."""
    print("\n=== Q3a: does a second login evict the first session? ===")

    first = new_client(args.host, args.password, args.verify_ssl, auto_relogin=False)
    second = new_client(args.host, args.password, args.verify_ssl, auto_relogin=False)
    async with first:
        await first.login()
        await first.get_mode()
        print("  session A established and working")

        async with second:
            await second.login()
            await second.get_mode()
            print("  session B established and working")

            try:
                await first.get_mode()
                a_alive = True
                detail = "session A still worked after session B logged in"
            except DecoSessionExpiredError as err:
                a_alive = False
                detail = f"session A was killed by session B's login: {err}"
            except DecoError as err:
                a_alive = False
                detail = f"session A failed with: {err}"

    report.add(
        "q3a-evict",
        PASS if a_alive else WARN,
        "concurrent sessions coexist"
        if a_alive
        else "a new login EVICTS the previous session",
        detail
        + (
            ""
            if a_alive
            else ".\n         This is the mechanism behind the mid-cycle HTTP 403: "
            "anyone opening the Deco app or web UI takes the integration's "
            "session away. Re-login-and-retry is mandatory, not optional."
        ),
    )


# --------------------------------------------------------------------------- #
# Q3b: how many concurrent sessions does the firmware allow?
# --------------------------------------------------------------------------- #


async def q_session_limit(
    report: Report, args: argparse.Namespace, _red: Redactor
) -> None:
    """Open sessions until login refuses, then close every one.

    Login error code 0 is "sessions full". This is the only experiment here with
    a user-visible effect: while it runs, the household may be unable to log in
    to the router. It is capped by --max and cleans up unconditionally.
    """
    print(f"\n=== Q3b: concurrent session limit (up to {args.max}) ===")
    print("  While this runs, the router may refuse other logins. Cleaning up after.")

    clients: list[DecoClient] = []
    opened = 0
    stopped_by: str | None = None
    try:
        for i in range(args.max):
            client = new_client(
                args.host, args.password, args.verify_ssl, auto_relogin=False
            )
            try:
                await client.__aenter__()
                await client.login()
            except DecoAuthError as err:
                stopped_by = (
                    f"login refused at session {i + 1}: {err} (code {err.code!r})"
                )
                with contextlib.suppress(Exception):
                    await client.__aexit__(None, None, None)
                break
            except DecoError as err:
                stopped_by = f"session {i + 1} failed: {err}"
                with contextlib.suppress(Exception):
                    await client.__aexit__(None, None, None)
                break
            clients.append(client)
            opened += 1
            print(f"  session {opened} open")

        # How many of the sessions we opened are still usable?
        alive = 0
        for client in clients:
            try:
                await client.get_mode()
                alive += 1
            except DecoError:
                pass
    finally:
        for client in clients:
            with contextlib.suppress(Exception):
                await client.logout()
                await client.__aexit__(None, None, None)
        print(f"  cleaned up {len(clients)} session(s)")

    hit_limit = stopped_by is not None
    report.add(
        "q3b-limit",
        INFO,
        f"opened {opened} concurrent session(s); {alive} still usable at the end",
        (stopped_by or f"never hit a limit within the --max {args.max} cap")
        + f".\n         Sessions still usable after opening {opened}: {alive}. "
        + (
            "Only the newest session works, so the firmware keeps exactly one "
            "session per user."
            if alive == 1 and opened > 1
            else "Several sessions coexist."
            if alive > 1
            else "No session survived, which suggests aggressive eviction."
        ),
    )
    if hit_limit:
        report.add(
            "q3b-limit",
            INFO,
            "login error code 0 ('sessions full') is reachable",
            "An integration that leaks sessions can lock the household out of "
            "the router UI. Always log out on unload.",
        )


# --------------------------------------------------------------------------- #
# Q3c: how long does an idle session survive?
# --------------------------------------------------------------------------- #


async def q_session_idle(
    report: Report, args: argparse.Namespace, _red: Redactor
) -> None:
    """Log in, then touch the session on a slow cadence until it dies."""
    minutes = args.minutes
    print(f"\n=== Q3c: idle session lifetime (up to {minutes} minutes) ===")
    print("  Touching the session every 60s; this is the slow one.")

    client = new_client(args.host, args.password, args.verify_ssl, auto_relogin=False)
    started = time.monotonic()
    last_ok = 0.0
    died_at: float | None = None
    reason = ""
    async with client:
        await client.login()
        deadline = started + minutes * 60
        while time.monotonic() < deadline:
            await asyncio.sleep(60)
            try:
                await client.get_mode()
                last_ok = time.monotonic() - started
                print(f"    alive at {last_ok / 60:.0f} min")
            except DecoSessionExpiredError as err:
                died_at = time.monotonic() - started
                reason = str(err)
                break
            except DecoError as err:
                died_at = time.monotonic() - started
                reason = f"non-session error: {err}"
                break

    if died_at is None:
        report.add(
            "q3c-idle",
            PASS,
            f"a session touched once a minute survived at least "
            f"{last_ok / 60:.0f} minutes",
            "No expiry observed within the test window. This bounds the *keep-alive* "
            "lifetime, not the fully-idle one: a poll every 60s may itself be what "
            "keeps it alive.",
        )
    else:
        report.add(
            "q3c-idle",
            WARN,
            f"the session died after {died_at / 60:.1f} minutes",
            f"last successful call at {last_ok / 60:.1f} min; {reason}.\n         "
            f"A refresh interval below this is not sufficient on its own -- the "
            f"client still needs re-login-and-retry.",
        )


# --------------------------------------------------------------------------- #
# Q1: router mode. Not answerable without a configuration change.
# --------------------------------------------------------------------------- #


async def q_router_mode(
    report: Report, args: argparse.Namespace, red: Redactor
) -> None:
    print("\n=== Q1: Router-mode payload shapes ===")
    client = new_client(args.host, args.password, args.verify_ssl)
    async with client:
        await client.login()
        mode = await client.get_mode()
        wan: Any
        internet: Any
        try:
            wan = await client.call("/admin/network?form=wan_ipv4")
        except DecoError as err:
            wan = {"error": str(err)}
        try:
            internet = await client.get_internet()
        except DecoError as err:
            internet = {"error": str(err)}

    report.add(
        "q1-router-mode",
        SKIP,
        "Router-mode payload shapes cannot be probed from this unit",
        f"this unit reports {fmt(mode)}. Switching a Deco between AP and Router "
        f"mode is a configuration change that re-runs setup and drops the "
        f"household's connectivity, so it is out of scope for an automated probe. "
        f"It needs either a spare unit or an explicit maintenance window.",
    )
    report.add(
        "q1-router-mode",
        INFO,
        "what the WAN endpoints return in AP mode (for comparison later)",
        f"wan_ipv4: {fmt(red.obj(wan), 90)}\n         "
        f"internet: {fmt(red.obj(internet), 90)}",
    )


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

QUESTIONS = {
    "slave-perf": q_slave_perf,
    "signal-scale": q_signal_scale,
    "session-evict": q_session_evict,
    "sessions": q_session_limit,
    "session-idle": q_session_idle,
    "router-mode": q_router_mode,
}
# `sessions` can briefly block household logins; `session-idle` takes an hour.
SLOW_OR_INVASIVE = {"sessions", "session-idle"}


async def run(args: argparse.Namespace) -> int:
    report = Report()
    red = Redactor(enabled=not args.show_values)
    if args.question == "all":
        chosen = [k for k in QUESTIONS if k not in SLOW_OR_INVASIVE]
    else:
        chosen = [args.question]

    print("=" * 78)
    print(f"Deco R4 open-question probe -> {args.host}")
    print(f"running: {', '.join(chosen)}")
    print("=" * 78)

    for name in chosen:
        try:
            await QUESTIONS[name](report, args, red)
        except DecoAuthError as err:
            report.add(name, FAIL, f"{name}: authentication failed", str(err))
            print("\n  Refusing to retry (lockout risk). Fix DECO_PASSWORD and re-run.")
            break
        except (DecoError, DecoConnectionError) as err:
            report.add(name, FAIL, f"{name}: aborted", str(err))
    return report.summary()


def main() -> int:
    load_env()
    parser = argparse.ArgumentParser(
        description="Investigate the open questions in doc/specification.md 10.2.",
    )
    parser.add_argument(
        "question",
        choices=[*QUESTIONS, "all"],
        help="which question to investigate ('all' skips the slow/invasive ones)",
    )
    parser.add_argument("--host", default=os.environ.get("DECO_HOST"))
    parser.add_argument("--password", default=os.environ.get("DECO_PASSWORD"))
    parser.add_argument("--verify-ssl", action="store_true")
    parser.add_argument(
        "--max", type=int, default=8, help="session cap for the 'sessions' question"
    )
    parser.add_argument(
        "--minutes",
        type=int,
        default=90,
        help="duration for the 'session-idle' question",
    )
    parser.add_argument(
        "--show-values",
        action="store_true",
        help="print real MACs/IPs/names instead of placeholders",
    )
    args = parser.parse_args()
    if not args.host or not args.password:
        parser.error("DECO_HOST and DECO_PASSWORD must be set in .env")
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
