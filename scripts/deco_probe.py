"""
Live probe for the TP-Link Deco R4 web interface.

Exercises the protocol in `doc/specification.md` against real hardware and
reports, claim by claim, whether the specification holds. It is read-only: it
runs the login handshake, issues `operation: read` / `get` calls, and logs out.
It never writes, reboots or resets anything, and it never retries a rejected
password (that would burn login attempts toward the router's lockout).

Usage:
    uv run python scripts/deco_probe.py                    # full report, redacted
    uv run python scripts/deco_probe.py --check performance
    uv run python scripts/deco_probe.py --show-values      # reveal names/MACs/IPs
    uv run python scripts/deco_probe.py --dump             # raw JSON -> scripts/out/
    uv run python scripts/deco_probe.py --soak 40          # fixed-seq soak test

Credentials come from the repo-root `.env` (`DECO_HOST`, `DECO_USERNAME`,
`DECO_PASSWORD`); flags override it.

Output is redacted by default: MACs, IPs, device/client names and SSIDs are
replaced with stable placeholders so a report can be pasted into an issue. Pass
`--show-values` only when you need the real thing locally.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import math
import os
import re
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parent))

from deco_protocol import (
    ID_ENCODINGS,
    AesKey,
    DecoApiError,
    DecoAuthError,
    DecoClient,
    DecoConnectionError,
    DecoError,
    DecoSessionExpiredError,
    b64_decode_field,
    encode_session_id,
    md5_hex,
    probe_unauthenticated,
    su_encrypt,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "scripts" / "out"

MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}$")
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Field names whose values are personal or identifying and must be redacted.
SENSITIVE_KEYS = frozenset(
    {
        "mac",
        "mac_addr",
        "macaddr",
        "device_mac",
        "previous",
        "ip",
        "ipaddr",
        "device_ip",
        "gateway",
        "dns1",
        "dns2",
        "name",
        "nickname",
        "custom_nickname",
        "device_name",
        "ssid",
        "device_id",
        "master_device_id",
        "parent_device_id",
        "hw_id",
        "oem_id",
        "owner_id",
        "bssid_2g",
        "bssid_5g",
        "bssid_sta_2g",
        "bssid_sta_5g",
    }
)

# Values that carry protocol meaning rather than identity, so redacting them
# would destroy information without protecting anything.
NON_IDENTIFYING = frozenset(
    # S104 (binding to all interfaces) is a false positive: this is the router's
    # sentinel for "client has no lease", not a listen address.
    {"", "0.0.0.0", "default", "custom", "none"}  # noqa: S104
)
# Field names that must never be printed at all, redacted or not.
SECRET_KEYS = frozenset(
    {"password", "pwd", "acs_password", "stunpassword", "key", "iv"}
)


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #

PASS, FAIL, WARN, INFO, SKIP = "PASS", "FAIL", "WARN", "INFO", "SKIP"


class Report:
    """Collects claim verdicts and prints them as a table."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, str]] = []

    def add(self, section: str, verdict: str, claim: str, detail: str = "") -> None:
        self.rows.append((section, verdict, claim, detail))
        icon = {PASS: "PASS", FAIL: "FAIL", WARN: "WARN", INFO: "INFO", SKIP: "SKIP"}[
            verdict
        ]
        print(f"  [{icon}] {claim}" + (f"\n         {detail}" if detail else ""))

    def summary(self) -> int:
        counts = Counter(v for _, v, _, _ in self.rows)
        print("\n" + "=" * 78)
        print(
            "SUMMARY  "
            + "  ".join(
                f"{k}={counts.get(k, 0)}" for k in (PASS, FAIL, WARN, INFO, SKIP)
            )
        )
        failures = [(s, c, d) for s, v, c, d in self.rows if v == FAIL]
        if failures:
            print("\nSpecification claims that did NOT hold:")
            for section, claim, detail in failures:
                print(f"  - [{section}] {claim}" + (f" -- {detail}" if detail else ""))
        print("=" * 78)
        return 1 if failures else 0


class Redactor:
    """Assigns stable placeholders to identifying values."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._map: dict[str, str] = {}
        self._counts: Counter[str] = Counter()

    def value(self, raw: object, kind: str | None = None) -> object:
        if not self.enabled or not isinstance(raw, str):
            return raw
        if raw.lower() in NON_IDENTIFYING:
            return raw
        if raw in self._map:
            return self._map[raw]
        if kind is None:
            kind = "mac" if MAC_RE.match(raw) else "ip" if IP_RE.match(raw) else "name"
        self._counts[kind] += 1
        placeholder = f"<{kind}-{self._counts[kind]}>"
        self._map[raw] = placeholder
        return placeholder

    def obj(self, value: Any, key: str | None = None) -> Any:
        """Recursively redact a payload for printing."""
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                # Keys can themselves be identifying: the per-node client map is
                # keyed by node MAC. Redact the key as well as the value.
                safe_key = (
                    str(self.value(k)) if MAC_RE.match(k) or IP_RE.match(k) else k
                )
                if k.lower() in SECRET_KEYS:
                    out[safe_key] = "<withheld>"
                else:
                    out[safe_key] = self.obj(v, key=k)
            return out
        if isinstance(value, list):
            return [self.obj(v, key=key) for v in value]
        if key and key.lower() in SENSITIVE_KEYS:
            return self.value(value)
        return value


def fmt(value: object, width: int = 60) -> str:
    text = json.dumps(value, default=str)
    return text if len(text) <= width else text[: width - 3] + "..."


# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #


def load_env() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(REPO_ROOT / ".env")


def looks_base64(value: object) -> bool:
    if not isinstance(value, str) or len(value) < 4 or len(value) % 4:
        return False
    try:
        base64.b64decode(value, validate=True).decode("utf-8")
    except ValueError, UnicodeDecodeError:
        return False
    return True


# --------------------------------------------------------------------------- #
# Offline self-test of the crypto ports
# --------------------------------------------------------------------------- #


def check_crypto(report: Report) -> None:
    print("\n--- 0. Crypto self-test (offline) ---")

    aes = AesKey.generate()
    ok = (
        len(aes.key) == 16
        and aes.key.isdigit()
        and len(aes.iv) == 16
        and aes.iv.isdigit()
    )
    report.add(
        "crypto",
        PASS if ok else FAIL,
        "AES key/IV are 16-character ASCII decimal digit strings",
        f"key_string form: k=<16 digits>&i=<16 digits> (len {len(aes.key_string)})",
    )

    sample = '{"operation":"read"}'
    roundtrip = aes.decrypt(aes.encrypt(sample))
    report.add(
        "crypto",
        PASS if roundtrip == sample else FAIL,
        "AES-128-CBC/PKCS#7 round-trips",
    )

    # su_encrypt: 32-char salt + 32-char MD5 must yield 32 chars from the alphabet.
    alphabet = "".join(chr(c) for c in range(33, 108))
    derived = su_encrypt("x" * 32, md5_hex("sample"), alphabet)
    ok = len(derived) == 32 and all(c in alphabet for c in derived)
    report.add(
        "crypto",
        PASS if ok else FAIL,
        "su_encrypt(32-char salt, MD5 hex, dictionary) -> 32 chars from the dictionary",
    )

    # Session-id encoding must round-trip through both schemes.
    from urllib.parse import unquote

    tricky = "4W\x08}WN3H*u>Qs{j\x08BkL|[L\x08.NmJT^s4j"
    ok = all(unquote(encode_session_id(tricky, s)) == tricky for s in ID_ENCODINGS)
    report.add(
        "crypto",
        PASS if ok else FAIL,
        "both id encodings round-trip a control-character-bearing id",
    )


# --------------------------------------------------------------------------- #
# Live checks
# --------------------------------------------------------------------------- #


async def check_unauthenticated(report: Report, host: str, verify_ssl: bool) -> None:
    print("\n--- 1. Unauthenticated endpoints ---")
    try:
        result = await probe_unauthenticated(host, verify_ssl=verify_ssl)
    except DecoConnectionError as err:
        report.add("unauth", FAIL, "router is reachable", str(err))
        raise

    envar = result.get("envar", {})
    body = envar.get("body")
    ok = isinstance(body, dict) and body.get("error_code") == 0
    report.add(
        "unauth",
        PASS if ok else FAIL,
        "/system?form=envar returns plain JSON {error_code, result}",
        f"status={envar.get('status')} result={fmt((body or {}).get('result'))}",
    )

    fd = result.get("check_factory_default", {})
    body = fd.get("body")
    ok = isinstance(body, dict) and body.get("error_code") == 0
    report.add(
        "unauth",
        PASS if ok else FAIL,
        "/login?form=check_factory_default returns plain JSON",
        f"status={fd.get('status')} result={fmt((body or {}).get('result'))}",
    )


def check_handshake(report: Report, client: DecoClient) -> None:
    print("\n--- 2. Handshake facts ---")
    f = client.facts

    report.add(
        "handshake",
        PASS if f.tmp_key_status == 401 else FAIL,
        "?code=7&asyn=1 returns 401 with key material when unauthenticated",
        f"status={f.tmp_key_status}",
    )
    report.add(
        "handshake",
        PASS if f.salt_len == 32 else FAIL,
        "salt (line 3) is 32 characters",
        f"got {f.salt_len}",
    )
    report.add(
        "handshake",
        PASS if f.dictionary_len == 255 else FAIL,
        "dictionary (line 4) is 255 characters",
        f"got {f.dictionary_len}, {f.dictionary_distinct} distinct, "
        f"ordinal range {f.dictionary_ord_range}",
    )
    report.add(
        "handshake",
        WARN if f.dictionary_has_control_bytes else INFO,
        "dictionary may contain control bytes",
        "control bytes PRESENT this session -- percent-encoding the id is mandatory"
        if f.dictionary_has_control_bytes
        else "none this session (they have been observed before; still encode)",
    )
    report.add(
        "handshake",
        PASS if f.rsa_modulus_bits == 512 else WARN,
        "RSA modulus is 512-bit",
        f"got {f.rsa_modulus_bits} bits, exponent 0x{f.rsa_exponent_hex}",
    )
    report.add(
        "handshake",
        PASS if f.rsa_exponent_hex == "010001" else WARN,
        "RSA exponent is 010001 (65537)",
        f"got {f.rsa_exponent_hex}",
    )
    report.add(
        "handshake",
        INFO,
        "sequence number obtained from key exchange",
        f"{f.seq} digits={len(str(f.seq))}",
    )
    report.add(
        "handshake",
        PASS if f.session_id_len == 32 else FAIL,
        "derived session id is 32 characters",
        f"got {f.session_id_len}",
    )
    report.add(
        "handshake",
        INFO,
        "session id contains characters needing percent-encoding",
        f"{f.session_id_needs_encoding} "
        f"(encoding scheme in use: {f.session_id_encoding_used})",
    )
    report.add(
        "handshake",
        PASS if f.plaintext_responses_until_set_key else WARN,
        "responses stay plaintext until the AES key is uploaded",
    )
    if f.signature_blocks is None:
        report.add(
            "handshake", SKIP, "request signature width (no ?form= call issued yet)"
        )
    else:
        report.add(
            "handshake",
            PASS if f.signature_blocks == 1 else WARN,
            "request signature fits in one RSA block",
            f"sign is {f.signature_hex_len} hex chars = {f.signature_blocks} block(s)",
        )


async def check_mode(report: Report, client: DecoClient) -> dict[str, Any]:
    print("\n--- 3. Operation mode ---")
    mode = await client.get_mode()
    keys = sorted(mode)
    ok = "sysmode" in mode and "workmode" in mode
    report.add(
        "mode",
        PASS if ok else FAIL,
        "/admin/device?form=mode returns sysmode and workmode",
        f"keys={keys} values={fmt(mode)}",
    )
    report.add(
        "mode",
        INFO,
        "effective operation mode",
        f"sysmode={mode.get('sysmode')!r} workmode={mode.get('workmode')!r}"
        + (" -> range extender" if mode.get("workmode") == "RE" else ""),
    )
    return mode


async def check_device_list(
    report: Report, client: DecoClient, red: Redactor
) -> list[dict[str, Any]]:
    print("\n--- 4. Deco node list ---")
    nodes = await client.get_device_list()
    report.add(
        "device_list",
        PASS if nodes else FAIL,
        "/admin/device?form=device_list returns a non-empty device_list",
        f"{len(nodes)} node(s)",
    )
    if not nodes:
        return nodes

    observed = sorted({k for n in nodes for k in n})
    documented = {
        "mac",
        "nickname",
        "custom_nickname",
        "device_model",
        "device_ip",
        "device_id",
        "role",
        "previous",
        "group_status",
        "inet_status",
        "inet_error_msg",
        "hardware_ver",
        "software_ver",
        "version",
        "new_version",
        "need_to_upgrade",
        "hw_id",
        "oem_id",
        "oversized_firmware",
    }
    missing = sorted(documented - set(observed))
    extra = sorted(set(observed) - documented)
    report.add(
        "device_list",
        INFO,
        f"{len(observed)} field(s) present per node",
        f"documented-but-absent: {missing or 'none'}\n         "
        f"undocumented-but-present: {extra or 'none'}",
    )

    macs = [n.get("mac") for n in nodes if isinstance(n.get("mac"), str)]
    fmt_ok = all(MAC_RE.match(m) for m in macs)
    sep = {("-" if "-" in m else ":" if ":" in m else "?") for m in macs}
    case = {
        ("upper" if m.upper() == m else "lower" if m.lower() == m else "mixed")
        for m in macs
    }
    report.add(
        "device_list",
        PASS if fmt_ok else FAIL,
        "node MACs are well-formed",
        f"separator={sorted(sep)} case={sorted(case)} -> "
        f"spec claim 'uppercase AA-BB-CC-DD-EE-FF' is "
        f"{'CONFIRMED' if sep == {'-'} and case == {'upper'} else 'WRONG, see above'}",
    )

    nick_custom = [n for n in nodes if n.get("nickname") == "custom"]
    nick_b64 = [n for n in nodes if looks_base64(n.get("nickname"))]
    report.add(
        "device_list",
        INFO,
        "nickname encoding",
        f"{len(nick_custom)}/{len(nodes)} node(s) use the literal 'custom' "
        f"(real name then in base64 custom_nickname); "
        f"{len(nick_b64)} nickname value(s) look base64",
    )

    print("\n  Nodes:")
    for n in nodes:
        name = n.get("nickname")
        if name == "custom":
            name = b64_decode_field(n.get("custom_nickname"))
        online = _derive_online(n)
        print(
            f"    role={n.get('role')!s:8} model={n.get('device_model')!s:8} "
            f"online={online!s:5} mac={red.value(n.get('mac'), 'mac')} "
            f"ip={red.value(n.get('device_ip'), 'ip')} name={red.value(name, 'name')}"
        )
        print(
            f"      group_status={n.get('group_status')!r} "
            f"inet_status={n.get('inet_status')!r} "
            f"inet_error_msg={n.get('inet_error_msg')!r}"
        )
    return nodes


def _derive_online(node: dict[str, Any]) -> bool:
    """Derive online exactly as the router's own networkMap/controllers.js does."""
    group = str(node.get("group_status", "")).lower()
    inet = str(node.get("inet_status", "")).lower()
    err = str(node.get("inet_error_msg", "")).lower()
    return not (group == "disconnected" or (inet != "online" and err != "well"))


async def check_performance_liveness(
    report: Report, client: DecoClient, samples: int, load: bool
) -> None:
    """Check whether form=performance ever moves. On this firmware it does not.

    Sampled repeatedly, optionally while loading the router's own CPU with the
    heaviest read available (`client_list` over ~130 clients costs it an RSA
    verify, an AES decrypt, a large JSON build and an AES encrypt).
    """
    print(f"\n--- 5b. Is form=performance a live metric? ({samples} samples) ---")
    seen: set[tuple[str, str]] = set()
    for i in range(samples):
        perf = await client.get_performance()
        seen.add((str(perf.get("cpu_usage")), str(perf.get("mem_usage"))))
        if load and i % 2 == 0:
            await client.get_client_list()
        await asyncio.sleep(1.5)
    report.add(
        "performance",
        WARN if len(seen) == 1 else PASS,
        "form=performance is a STATIC value, not a live metric"
        if len(seen) == 1
        else "form=performance varies over time, so it is a live metric",
        f"{len(seen)} distinct (cpu, mem) pair(s) over {samples} samples"
        + (f" under load: {sorted(seen)}" if load else f": {sorted(seen)}")
        + (
            ".\n         Do not build CPU/memory sensors on this: they would be "
            "flat lines. See spec 7.5."
            if len(seen) == 1
            else ""
        ),
    )


async def check_performance(
    report: Report, client: DecoClient, nodes: list[dict[str, Any]]
) -> None:
    print("\n--- 5. Performance (does it accept device_mac?) ---")

    baseline = await client.get_performance()
    keys = sorted(baseline)
    ok = "cpu_usage" in baseline and "mem_usage" in baseline
    report.add(
        "performance",
        PASS if ok else FAIL,
        "form=performance with no params returns cpu_usage and mem_usage",
        f"keys={keys} values={fmt(baseline)}",
    )
    types = {k: type(baseline.get(k)).__name__ for k in ("cpu_usage", "mem_usage")}
    numeric_strings = all(isinstance(baseline.get(k), str) for k in types)
    in_range = True
    for k in types:
        try:
            in_range &= 0.0 <= float(baseline[k]) <= 1.0
        except TypeError, ValueError:
            in_range = False
    report.add(
        "performance",
        PASS if in_range else FAIL,
        "cpu_usage/mem_usage parse as fractions in 0..1 (x100 for percent)",
        f"raw={fmt(baseline)} json_types={types}",
    )
    report.add(
        "performance",
        WARN if numeric_strings else INFO,
        "cpu_usage/mem_usage JSON type",
        "they are STRINGS, not numbers -- a client must coerce with float() "
        "before arithmetic"
        if numeric_strings
        else f"native numbers: {types}",
    )

    # Does the form accept a device_mac at all?
    results: dict[str, Any] = {}
    try:
        results["default"] = await client.get_performance("default")
        accepts = True
    except DecoApiError as err:
        accepts = False
        report.add(
            "performance",
            INFO,
            "form=performance REJECTS a device_mac parameter",
            f"{err} -> CPU/memory are master-only; "
            f"do not create these sensors for slave nodes",
        )
    except DecoSessionExpiredError as err:
        accepts = False
        report.add(
            "performance",
            WARN,
            "form=performance killed the session when given device_mac",
            str(err),
        )

    if not accepts:
        return

    for node in nodes:
        mac = node.get("mac")
        if not isinstance(mac, str):
            continue
        try:
            results[mac] = await client.get_performance(mac)
        except DecoError as err:
            results[mac] = {"error": str(err)}

    # A bogus MAC separates "parameter parsed and honoured" from "parameter
    # accepted and silently discarded".
    try:
        bogus: Any = await client.get_performance("00-00-00-00-00-00")
    except DecoError as err:
        bogus = {"error": str(err)}
    bogus_same = json.dumps(bogus, sort_keys=True) == json.dumps(
        results.get("default"), sort_keys=True
    )
    report.add(
        "performance",
        INFO,
        "a bogus device_mac returns the SAME payload as a real one"
        if bogus_same
        else "a bogus device_mac is rejected (so the parameter IS parsed)",
        f"bogus-MAC response: {fmt(bogus, 48)}"
        + (
            "\n         -> the parameter is ignored entirely; this endpoint only "
            "ever reports the node being talked to"
            if bogus_same
            else ""
        ),
    )

    # Distinguish "accepted and honoured" from "accepted and ignored".
    signatures = {
        json.dumps(v, sort_keys=True)
        for k, v in results.items()
        if isinstance(v, dict) and "error" not in v
    }
    per_node = len(signatures) > 1
    detail_lines = []
    for k, v in results.items():
        label = "default" if k == "default" else f"node {k[-5:]}"
        detail_lines.append(f"{label}: {fmt(v, 48)}")
    report.add(
        "performance",
        PASS if per_node else INFO,
        "form=performance accepts device_mac AND returns per-node values"
        if per_node
        else "form=performance accepts device_mac but returns identical "
        "values (parameter ignored)",
        "\n         ".join(detail_lines)
        + (
            "\n         -> per-node CPU/memory sensors ARE possible"
            if per_node
            else "\n         -> values did not vary; likely master-only. Re-run under "
            "differing load to be certain, since idle nodes can coincide."
        ),
    )


async def check_clients(
    report: Report, client: DecoClient, nodes: list[dict[str, Any]], red: Redactor
) -> dict[str, Any]:
    print("\n--- 6. Client list and per-node filtering ---")

    all_clients = await client.get_client_list("default")
    report.add(
        "client_list",
        PASS if isinstance(all_clients, list) else FAIL,
        "form=client_list with device_mac=default returns client_list",
        f"{len(all_clients)} client(s)",
    )
    if not all_clients:
        report.add("client_list", SKIP, "no clients connected; field checks skipped")
        return {"default": all_clients, "by_node": {}}

    observed = sorted({k for c in all_clients for k in c})
    documented = {
        "name",
        "mac",
        "ip",
        "up_speed",
        "down_speed",
        "client_type",
        "connection_type",
        "online",
        "enable_priority",
        "remain_time",
        "interface",
        "wire_type",
        "owner_id",
        "enable_isolation",
        "link_priority",
        "linked_device_info",
        "client_mesh",
    }
    report.add(
        "client_list",
        INFO,
        f"{len(observed)} field(s) present per client",
        f"documented-but-absent: "
        f"{sorted(documented - set(observed)) or 'none'}\n         "
        f"undocumented-but-present: {sorted(set(observed) - documented) or 'none'}",
    )

    named = [c for c in all_clients if c.get("name")]
    names_b64 = sum(1 for c in named if looks_base64(c.get("name")))
    report.add(
        "client_list",
        PASS if names_b64 == len(named) else WARN,
        "client 'name' is always base64",
        f"{names_b64}/{len(named)} non-empty names decode as base64 UTF-8; "
        f"{len(all_clients) - len(named)} client(s) have no name at all",
    )

    conn_types = Counter(str(c.get("connection_type")) for c in all_clients)
    client_types = Counter(str(c.get("client_type")) for c in all_clients)
    known_conn = {"band2_4", "band5", "band5_2", "wired", "zigbee", "bluetooth"}
    unknown = sorted(set(conn_types) - known_conn)
    report.add(
        "client_list",
        PASS if not unknown else INFO,
        "connection_type values are all documented",
        f"observed={dict(conn_types)}"
        + (f"\n         UNDOCUMENTED: {unknown}" if unknown else ""),
    )
    report.add(
        "client_list", INFO, "client_type values observed", f"{dict(client_types)}"
    )

    speeds = [
        (c.get("up_speed"), c.get("down_speed"))
        for c in all_clients
        if isinstance(c.get("up_speed"), (int, float))
    ]
    if speeds:
        max_up = max(s[0] for s in speeds)
        max_down = max(s[1] for s in speeds)
        report.add(
            "client_list",
            INFO,
            "OPEN QUESTION 3: rate units (KB/s vs Kbit/s) need a live transfer",
            f"max up={max_up} down={max_down} raw units. If a client is "
            f"downloading at a known N Mbit/s, KB/s reads ~N*128 and "
            f"Kbit/s ~N*1000.",
        )

    # OPEN QUESTION: does per-node filtering actually work?
    online_nodes = [
        n for n in nodes if _derive_online(n) and isinstance(n.get("mac"), str)
    ]
    per_node: dict[str, list[dict[str, Any]]] = {}
    for node in online_nodes:
        mac = str(node["mac"])
        try:
            per_node[mac] = await client.get_client_list(mac)
        except DecoError as err:
            report.add(
                "client_list", FAIL, "per-node client_list failed for a node", str(err)
            )
            return {"default": all_clients, "by_node": per_node}

    total = sum(len(v) for v in per_node.values())
    macs_all = {c.get("mac") for c in all_clients}
    macs_split = {c.get("mac") for v in per_node.values() for c in v}
    filtered = total != len(all_clients) * max(len(per_node), 1) and total > 0
    report.add(
        "client_list",
        PASS if filtered else FAIL,
        "device_mac filters the client list per node",
        f"default={len(all_clients)} clients; per-node counts="
        f"{ {m[-5:]: len(v) for m, v in per_node.items()} }; union={len(macs_split)}",
    )
    overlap = [
        m
        for m in macs_split
        if sum(1 for v in per_node.values() if any(c.get("mac") == m for c in v)) > 1
    ]
    report.add(
        "client_list",
        PASS if not overlap else WARN,
        "each client appears under exactly one node (so attribution is unambiguous)",
        f"{len(overlap)} client(s) appeared under more than one node"
        if overlap
        else "no client appeared twice",
    )
    lost = macs_all - macs_split
    lost_clients = [c for c in all_clients if c.get("mac") in lost]
    lost_online = sum(1 for c in lost_clients if c.get("online"))
    report.add(
        "client_list",
        PASS if not lost else WARN,
        "every client from the 'default' list is attributable to a node",
        f"{len(lost)} of {len(all_clients)} client(s) appear in 'default' but under "
        f"no node; {lost_online} of those are online. The 'default' list is a "
        f"remembered-client inventory, the per-node lists are currently-attached."
        if lost
        else "all accounted for",
    )

    # Can one 'default' call replace N per-node calls? The per-node filter is the
    # ground truth here, so check the join against it.
    ids = {n.get("device_id"): n.get("mac") for n in nodes if n.get("device_id")}
    agree = disagree = unresolvable = 0
    for node_mac, clients in per_node.items():
        for c in clients:
            linked = (c.get("linked_device_info") or {}).get("device_id")
            if linked not in ids:
                unresolvable += 1
            elif ids[linked] == node_mac:
                agree += 1
            else:
                disagree += 1
    checked = agree + disagree + unresolvable
    report.add(
        "client_list",
        PASS if checked and agree == checked else FAIL if checked else SKIP,
        "client.linked_device_info.device_id identifies the attached node, so ONE "
        "'default' call replaces one call per node",
        f"of {checked} client(s) from per-node lists: {agree} agree with the "
        f"filter, {disagree} point at a different node, {unresolvable} carry a "
        f"device_id absent from device_list",
    )

    print("\n  Clients by node:")
    for mac, clients in per_node.items():
        print(f"    node {red.value(mac, 'mac')}: {len(clients)} client(s)")
        for c in clients:
            print(
                f"      {red.value(b64_decode_field(c.get('name')), 'name')!s:16} "
                f"mac={red.value(c.get('mac'), 'mac'):11} "
                f"ip={red.value(c.get('ip'), 'ip')!s:11} "
                f"conn={c.get('connection_type')!s:9} "
                f"type={c.get('client_type')!s:8} "
                f"up={c.get('up_speed')} down={c.get('down_speed')} "
                f"online={c.get('online')}"
            )
    return {"default": all_clients, "by_node": per_node}


async def check_lan_and_wlan(
    report: Report, client: DecoClient, nodes: list[dict[str, Any]], red: Redactor
) -> None:
    print("\n--- 7. LAN details and wireless ---")

    lan = await client.get_lan_ip("default")
    ok = "mac_addr" in lan and isinstance(lan.get("lan_ip"), dict)
    report.add(
        "lan_ip",
        PASS if ok else FAIL,
        "form=lan_ip returns mac_addr and lan_ip{ip, mask}",
        f"keys={sorted(lan)} lan_ip keys={sorted(lan.get('lan_ip') or {})}",
    )

    # Does device_mac actually select a different node here?
    variants: dict[str, str] = {}
    for node in nodes:
        mac = node.get("mac")
        if not isinstance(mac, str):
            continue
        try:
            r = await client.get_lan_ip(mac)
            variants[mac] = json.dumps(r, sort_keys=True)
        except DecoError as err:
            variants[mac] = f"error: {err}"
    distinct = len(set(variants.values()))
    report.add(
        "lan_ip",
        PASS if distinct > 1 or len(variants) <= 1 else WARN,
        "form=lan_ip honours device_mac (per-node results differ)",
        f"{len(variants)} node(s) queried, {distinct} distinct response(s)",
    )

    wlan = await client.get_wlan()
    bands = sorted(k for k in wlan if k.startswith("band"))
    has_shape = all(isinstance(wlan.get(b), dict) and "host" in wlan[b] for b in bands)
    report.add(
        "wlan",
        PASS if bands and has_shape else FAIL,
        "form=wlan returns per-band host/guest structures",
        f"bands={bands} (tri-band={'band5_2' in bands})",
    )
    host = (wlan.get("band2_4") or {}).get("host") or {}
    report.add(
        "wlan",
        PASS if looks_base64(host.get("ssid")) else FAIL,
        "band2_4.host.ssid is base64 encoded",
        f"host keys={sorted(host)} (ssid/password values withheld)",
    )

    try:
        internet = await client.get_internet()
        report.add(
            "internet",
            INFO,
            "form=internet reachable",
            f"{fmt(red.obj(internet))}",
        )
    except DecoError as err:
        report.add("internet", INFO, "form=internet not usable in this mode", str(err))


async def check_id_encodings(
    report: Report, host: str, password: str, verify_ssl: bool
) -> None:
    print("\n--- 8. OPEN QUESTION 2: session-id URL encoding ---")
    for scheme in ID_ENCODINGS:
        client = DecoClient(
            host=host, password=password, verify_ssl=verify_ssl, id_encoding=scheme
        )
        try:
            async with client:
                await client.login()
                await client.get_mode()
            report.add(
                "id_encoding",
                PASS,
                f"'{scheme}' percent-encoding of the id is accepted by the router",
            )
        except DecoAuthError as err:
            report.add(
                "id_encoding",
                FAIL,
                f"'{scheme}' encoding rejected at login -- stopping to avoid lockout",
                str(err),
            )
            return
        except DecoError as err:
            report.add("id_encoding", FAIL, f"'{scheme}' encoding failed", str(err))


async def check_seq_soak(report: Report, client: DecoClient, count: int) -> None:
    print(f"\n--- 9. OPEN QUESTION 5: fixed-seq soak ({count} calls) ---")
    start = time.monotonic()
    failed_at: int | None = None
    for i in range(count):
        try:
            await client.get_performance()
        except DecoError as err:
            failed_at = i + 1
            report.add(
                "seq",
                FAIL,
                "a fixed sequence number survives repeated calls",
                f"failed on call {failed_at}: {err}",
            )
            break
    else:
        elapsed = time.monotonic() - start
        report.add(
            "seq",
            PASS,
            "a fixed sequence number survives repeated calls",
            f"{count} calls in {elapsed:.1f}s with seq={client.facts.seq} unchanged. "
            f"Note: this proves reuse, not multi-hour session lifetime.",
        )


# A large public file, throttled locally to the target rate. Needs to sustain
# well above --rate-kbps or the measurement is meaningless, so a CDN is used.
# Alternatives if this host is blocked: https://proof.ovh.net/files/100Mb.dat,
# https://ash-speed.hetzner.com/100MB.bin. Override with --rate-url.
RATE_TEST_URL = "http://cachefly.cachefly.net/100mb.test"


async def _rate_limited_download(url: str, kb_per_sec: int, seconds: float) -> int:
    """Pull `url` at roughly `kb_per_sec`, for `seconds`. Returns bytes read.

    The pacing must be *smooth*, not bursty. Reading large chunks at line speed
    and then sleeping produces the right average but a much higher instantaneous
    rate, and the router samples the instantaneous rate: an early version of this
    check overshot by 50-80% for exactly that reason. Chunks are therefore sized
    to roughly 1/50th of a second of traffic so a sleep follows every small read.
    """
    target = kb_per_sec * 1024
    chunk_size = max(2048, target // 50)
    read = 0
    started = time.monotonic()
    timeout = aiohttp.ClientTimeout(total=seconds + 30)
    async with (
        aiohttp.ClientSession(timeout=timeout) as session,
        session.get(url) as resp,
    ):
        if resp.status != 200:
            raise DecoError(f"rate-test source returned HTTP {resp.status} for {url}")
        async for chunk in resp.content.iter_chunked(chunk_size):
            read += len(chunk)
            elapsed = time.monotonic() - started
            if elapsed >= seconds:
                break
            # Throttle by sleeping until the byte count matches the target rate.
            due = read / target
            if due > elapsed:
                await asyncio.sleep(due - elapsed)
    return read


async def check_rate_units(
    report: Report,
    client: DecoClient,
    kb_per_sec: int,
    seconds: float,
    url: str,
    red: Redactor,
) -> None:
    """Settle KB/s vs Kbit/s by driving a known rate and watching the counters.

    Opt-in: this deliberately consumes about `kb_per_sec * seconds` of the
    household's bandwidth and data allowance.

    Attribution is by *rise above baseline*, not absolute peak: other household
    traffic can easily out-rank this transfer in absolute terms, but only this
    machine's counter should jump by the driven rate.
    """
    print(
        f"\n--- 10. OPEN QUESTION 3: rate units "
        f"({kb_per_sec} KB/s for {seconds:.0f}s) ---"
    )
    mib = kb_per_sec * seconds / 1024
    print(f"  This will download about {mib:.0f} MiB over the household connection.")

    def downs(clients: list[dict[str, Any]]) -> dict[str, int]:
        return {
            c["mac"]: int(c["down_speed"])
            for c in clients
            if isinstance(c.get("mac"), str) and isinstance(c.get("down_speed"), int)
        }

    baseline = downs(await client.get_client_list())
    samples: dict[str, list[int]] = {}

    async def poll() -> None:
        deadline = time.monotonic() + seconds
        # Let the router's own averaging settle before sampling.
        await asyncio.sleep(min(4.0, seconds / 4))
        while time.monotonic() < deadline:
            try:
                for mac, down in downs(await client.get_client_list()).items():
                    samples.setdefault(mac, []).append(down)
            except DecoError:
                return
            await asyncio.sleep(1.5)

    download = asyncio.create_task(_rate_limited_download(url, kb_per_sec, seconds))
    await poll()
    try:
        got = await download
    except (aiohttp.ClientError, TimeoutError, DecoError) as err:
        report.add("rates", SKIP, "rate-unit test needs a working source", str(err))
        return

    actual_kbps = got / 1024 / seconds
    # If the source could not sustain the target, the arithmetic below is noise.
    if actual_kbps < kb_per_sec * 0.5:
        report.add(
            "rates",
            SKIP,
            "rate-unit test could not sustain the target rate",
            f"asked for {kb_per_sec} KB/s, achieved {actual_kbps:.0f} KB/s "
            f"({got} bytes). Try --rate-url with a faster source, or a lower "
            f"--rate-kbps.",
        )
        return
    if not samples:
        report.add("rates", SKIP, "no client rates sampled during the transfer")
        return

    # Median, not peak: the median tracks the sustained rate, while a peak also
    # catches TCP bursts and any unrelated household spike.
    rises = {
        mac: statistics.median(values) - baseline.get(mac, 0)
        for mac, values in samples.items()
        if values
    }
    top_mac = max(rises, key=lambda m: rises[m])
    rise = rises[top_mac]

    # The two hypotheses are 8x apart, so compare by ratio rather than by absolute
    # error. Unrelated traffic on the same client only ever inflates the rise, and
    # a tolerance of 2x absorbs that while still separating KB/s from Kbit/s.
    ratio_kbytes = rise / actual_kbps
    ratio_kbits = rise / (actual_kbps * 8)
    if abs(math.log(ratio_kbits)) <= abs(math.log(ratio_kbytes)):
        verdict, best, other = "Kbit/s", ratio_kbits, ratio_kbytes
    else:
        verdict, best, other = "KB/s", ratio_kbytes, ratio_kbits
    confident = 0.5 <= best <= 2.0 and not 0.5 <= other <= 2.0
    report.add(
        "rates",
        PASS if confident else WARN,
        f"down_speed is reported in {verdict}"
        if confident
        else "down_speed unit is still ambiguous",
        f"drove {actual_kbps:.0f} KB/s = {actual_kbps * 8:.0f} Kbit/s; the client "
        f"whose median down_speed rose most was {red.value(top_mac, 'mac')}, "
        f"+{rise:.0f} over a baseline of {baseline.get(top_mac, 0)} "
        f"({len(samples[top_mac])} samples).\n         "
        f"observed/driven = {ratio_kbits:.2f}x if Kbit/s, {ratio_kbytes:.2f}x if "
        f"KB/s (they differ by 8x, so only one can be near 1)."
        + (
            "\n         The residual excess is that client's own background "
            "traffic plus link-layer framing, which this payload byte count "
            "excludes. Drive a second, higher rate to cancel it: the slope, not "
            "the offset, is the unit."
            if confident
            else "\n         Neither fits. Other household traffic is probably "
            "masking it; re-run when the network is idle."
        ),
    )


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

# "encoding", "soak" and "rates" are opt-in: the first two log in again, and
# "rates" deliberately consumes household bandwidth.
DEFAULT_SKIPPED = frozenset({"encoding", "soak", "rates"})
CHECKS = (
    "crypto",
    "unauth",
    "handshake",
    "mode",
    "devices",
    "performance",
    "clients",
    "lan",
    "encoding",
    "soak",
    "rates",
    "liveness",
)


async def run(args: argparse.Namespace) -> int:
    report = Report()
    red = Redactor(enabled=not args.show_values)
    selected = set(args.check) if args.check else set(CHECKS) - DEFAULT_SKIPPED
    dump: dict[str, Any] = {}

    print("=" * 78)
    print(f"Deco R4 protocol probe -> {args.host}")
    print(
        f"verify_ssl={args.verify_ssl}  id_encoding={args.id_encoding}  "
        f"output={'REAL VALUES' if args.show_values else 'redacted'}"
    )
    print("=" * 78)

    if "crypto" in selected:
        check_crypto(report)

    if "unauth" in selected:
        await check_unauthenticated(report, args.host, args.verify_ssl)

    needs_session = selected & {
        "handshake",
        "mode",
        "devices",
        "performance",
        "clients",
        "lan",
        "soak",
        "rates",
        "liveness",
    }
    if needs_session:
        client = DecoClient(
            host=args.host,
            password=args.password,
            verify_ssl=args.verify_ssl,
            id_encoding=args.id_encoding,
            trace=args.trace,
        )
        async with client:
            print("\n--- Logging in ---")
            try:
                await client.login()
            except DecoAuthError as err:
                report.add("login", FAIL, "login succeeded", f"{err}")
                print(
                    "\n  Refusing to retry: the router locks the account after "
                    "~10 failed\n"
                    "  attempts. Fix DECO_PASSWORD in .env and re-run."
                )
                return report.summary() or 1
            print("  Logged in.")

            nodes: list[dict[str, Any]] = []
            if "mode" in selected:
                dump["mode"] = await check_mode(report, client)
            elif "handshake" in selected:
                # The request signature only exists once a ?form= call has been
                # enveloped, so issue the cheapest one before reporting on it.
                await client.get_mode()

            # Reported after the first ?form= call so signature facts are populated.
            if "handshake" in selected:
                check_handshake(report, client)

            if "devices" in selected:
                nodes = await check_device_list(report, client, red)
                dump["device_list"] = nodes
            elif selected & {"performance", "clients", "lan"}:
                nodes = await client.get_device_list()

            if "performance" in selected:
                await check_performance(report, client, nodes)
            if "liveness" in selected:
                await check_performance_liveness(
                    report, client, args.liveness_samples, load=True
                )
            if "clients" in selected:
                dump["clients"] = await check_clients(report, client, nodes, red)
            if "lan" in selected:
                await check_lan_and_wlan(report, client, nodes, red)
            if "soak" in selected:
                await check_seq_soak(report, client, args.soak)
            if "rates" in selected:
                await check_rate_units(
                    report,
                    client,
                    args.rate_kbps,
                    args.rate_seconds,
                    args.rate_url,
                    red,
                )

            print("\n--- Session durability ---")
            report.add(
                "session",
                PASS if client.relogin_count == 0 else WARN,
                "the session survived the whole cycle without re-login"
                if client.relogin_count == 0
                else "the session died mid-cycle and was transparently recovered",
                "no re-login needed"
                if client.relogin_count == 0
                else f"{client.relogin_count} re-login(s). This firmware evicts "
                f"sessions unpredictably (HTTP 403), so an integration MUST "
                f"re-login and retry rather than surfacing the failure.",
            )
            print(f"\n  Requests issued this session: {client.request_count}")
            print("  Logging out.")

    if "encoding" in selected:
        await check_id_encodings(report, args.host, args.password, args.verify_ssl)

    if args.dump and dump:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        path = OUT_DIR / "probe-dump.json"
        payload = dump if args.show_values else red.obj(dump)
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(
            f"\n  Raw payloads written to {path.relative_to(REPO_ROOT)} "
            f"({'REAL VALUES' if args.show_values else 'redacted'}); "
            f"this directory is gitignored."
        )

    return report.summary()


def main() -> int:
    load_env()
    parser = argparse.ArgumentParser(
        description="Read-only live probe of the TP-Link Deco R4 web interface.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--host", default=os.environ.get("DECO_HOST"), help="router host or URL"
    )
    parser.add_argument(
        "--password", default=os.environ.get("DECO_PASSWORD"), help="admin password"
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="verify the TLS certificate (fails on the router's self-signed cert)",
    )
    parser.add_argument(
        "--id-encoding",
        choices=ID_ENCODINGS,
        default="browser",
        help="percent-encoding scheme for the session id (default: browser)",
    )
    parser.add_argument(
        "--check",
        action="append",
        choices=CHECKS,
        help="run only these checks (repeatable). Default: all except "
        + "/".join(sorted(DEFAULT_SKIPPED))
        + ".",
    )
    parser.add_argument(
        "--soak", type=int, default=30, help="calls for the seq soak test"
    )
    parser.add_argument(
        "--rate-kbps",
        type=int,
        default=1024,
        help="target rate in KB/s for the 'rates' check (default 1024 = 1 MiB/s)",
    )
    parser.add_argument(
        "--rate-seconds",
        type=float,
        default=20.0,
        help="duration in seconds for the 'rates' check (default 20)",
    )
    parser.add_argument(
        "--liveness-samples",
        type=int,
        default=12,
        help="samples for the performance-liveness check (default 12)",
    )
    parser.add_argument(
        "--rate-url",
        default=RATE_TEST_URL,
        help="large-file URL used to drive the 'rates' check",
    )
    parser.add_argument(
        "--show-values",
        action="store_true",
        help="print real MACs/IPs/names/SSIDs instead of placeholders (local use only)",
    )
    parser.add_argument(
        "--dump", action="store_true", help="write raw payloads to scripts/out/"
    )
    parser.add_argument("--trace", action="store_true", help="log each HTTP request")
    args = parser.parse_args()

    if not args.host or not args.password:
        parser.error(
            "DECO_HOST and DECO_PASSWORD must be set in .env (copy .env.example) "
            "or passed as --host/--password"
        )

    try:
        return asyncio.run(run(args))
    except DecoConnectionError as err:
        print(f"\nERROR: {err}", file=sys.stderr)
        return 2
    except DecoError as err:
        print(f"\nERROR: {err}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
