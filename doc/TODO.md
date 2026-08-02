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
- [ ] Decide whether to expose **live WAN throughput**. `?code=2` block 22
      carries monotonic `inOctets`/`outOctets`/`inPkts`/`outPkts` plus per-port
      rates, and they are genuinely live (spec 9.5.2) - the only real telemetry
      found, given `performance` is static. Trade-off: it means depending on a
      firmware-internal block id rather than the `?form=` API, so it is less
      likely to survive a firmware change. Read the security note in 9.5.1
      first.
- [x] README warns that polling evicts anyone logged into the router's own web
      UI, that CPU/memory are not real, and that the admin password grants full
      device read, and states plainly that nothing works yet.
- [x] Add brand assets so the HACS `brands` check passes, including the dark-mode
      logo. Copied from home-assistant/brands `core_brands/tplink`; provenance
      and the trademark notice are recorded in `NOTICE`. No `dark_icon` is needed
      (the icon is all mid-tone; only the wordmark needs inverting). Verify on the next PR into `main` that
      `Validate` goes green - it has been failing on that check since 31 July.
      The longer-term fix is submitting `tplink_deco_r4` to
      home-assistant/brands once the integration actually does something.

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
- [ ] What block 22's `upTime` counts (system vs WAN-link uptime) and the units
      of its `inRates`/`outRates`. The tick rate is measured at ~64.5/s; the
      semantics are not.
- [ ] Which firmware/hardware revisions this interface covers. Confirmed so far:
      Deco E4R, firmware 1.3.1 Build 20260403 Rel. 8727, 7-node mesh, AP mode
      (`sysmode: AP`, `workmode: FAP`).
