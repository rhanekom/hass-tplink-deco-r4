# TODO

The project's official todo list: the source of truth for next actions and build
milestones. Keep it current as work lands.

## Next

- [ ] Write `doc/specification.md`: the login/session protocol for the target
      firmware (endpoints, framing, crypto, error codes) and the monitoring
      endpoints the integration will poll.
- [ ] Prove the login handshake end to end with a CLI probe under `scripts/`.
- [ ] Port the proven logic into `custom_components/tplink_deco_r4/api.py` with tests.
- [ ] Config flow (host + credentials, validated on save).
- [ ] Entities: mesh nodes, connected clients, WAN/uplink state.

## Open questions

- [ ] Which firmware/hardware revisions the new login flow covers. Confirmed so
      far: Deco E4R, firmware 1.3.1 Build 20260403 Rel. 8727.
