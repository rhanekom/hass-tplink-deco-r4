# TODO

The project's official todo list: the source of truth for next actions and build
milestones. Keep it current as work lands.

## Next

- [x] Write `doc/specification.md`: the login/session protocol for the target
      firmware (endpoints, framing, crypto, error codes) and the monitoring
      endpoints the integration will poll.
- [x] Prove the login handshake end to end with a CLI probe under `scripts/`
      (`deco_protocol.py` + `deco_probe.py`), and close the spec's open
      questions against real hardware (`deco_open_questions.py`).
- [ ] **Decide what to do about CPU/memory.** `form=performance` returns a
      static value on this firmware (spec 7.5): unchanged under load, over time,
      and across all 7 nodes. Either drop those two sensors or ship them clearly
      marked unreliable. This is a scope decision, not a technical one.
- [ ] Port the proven logic into `custom_components/tplink_deco_r4/api.py` with
      tests. Non-obvious things to carry over from the spike:
    - The SSL context (spec 2.2) - a default client cannot handshake at all, so
      Home Assistant's shared session cannot be used.
    - Strict percent-encoding of the session id, with `yarl.URL(..., encoded=True)`.
    - Re-login-and-retry inside the client, per call (spec 6.2) - the firmware
      keeps one session and every login evicts it.
    - `float()` coercion of `cpu_usage`/`mem_usage`; they are JSON strings.
    - The `linked_device_info.device_id` join, so a refresh is 2 calls not 1+N.
- [ ] Config flow per `doc/specification.md` section 8 (host, verify SSL,
      username, password, refresh rate; validated on save).
- [ ] Entities: mesh nodes, connected clients, WAN/uplink state. Free extras
      `device_list` gives us: per-node `signal_level` (0-3) and per-node
      `software_ver` for firmware-drift visibility.
- [ ] README should warn that polling evicts anyone logged into the router's own
      web UI, and that this is a firmware constraint with no workaround.

## Open questions

Full detail in `doc/specification.md` section 10.2.

- [ ] Router-mode **payload content**. The menu trees for Router and AP mode are
      byte-identical, so the endpoint surface and field names should be
      unchanged; what is untested is whether `wan_ipv4`/`internet` carry real
      uplink data in Router mode. Needs a mode switch, which drops household
      connectivity, so it needs a spare unit or a maintenance window.
- [ ] RE-mode behaviour. `navigator.re.json` drops `networkMap` and
      `networkStatus`, so `client_list` and `device_list` may be unavailable in
      range-extender mode. No RE unit was available.
- [ ] Whether the TP-Link **cloud** mobile app shares the local single-session
      table (the local web UI definitely does).
- [ ] Whether the `?code=2` vxWorks block channel exposes real system stats,
      which would be an alternative source for CPU/memory.
- [ ] Which firmware/hardware revisions this interface covers. Confirmed so far:
      Deco E4R, firmware 1.3.1 Build 20260403 Rel. 8727, 7-node mesh, AP mode
      (`sysmode: AP`, `workmode: FAP`).
