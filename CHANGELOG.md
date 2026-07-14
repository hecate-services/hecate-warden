# Changelog

## [0.2.0]

### Added
- **Self-registration** (`announce_presence` + `hecate_warden_facts:presence/0`):
  the warden announces itself on a `warden/presence` heartbeat (label, tenant,
  tarpit flag, and declared micro-degree coordinates from `HECATE_WARDEN_LAT_E6`
  / `HECATE_WARDEN_LNG_E6`), so the federation map builds its sensor roster LIVE
  instead of from a hard-coded box list. A box self-registers the moment it boots
  and drops off when its heartbeat goes stale. Coordinates are SELF-ASSERTED (an
  untrusted warden can claim any location); server-side geo-verification is the
  hardening path if that matters.

## [Unreleased]

### Added
- Initial hecate-warden: a storeless, producer-only hecate-om service.
- **Tarpit** (`tarpit_listener` + `tarpit_connection`): binds decoy ports, holds
  every connection open with an endless slow fake SSH banner, publishes
  `warden/ensnared` facts (source IP + how long held). Native Erlang gen_tcp;
  holds tens of thousands of idle connections cheaply.
- **Auth-log sensor** (`sense_auth_log`): tails the host auth log, counts
  credential-spray per source IP in a rolling window, publishes `warden/threats`
  facts past a threshold. Read-only; the warden never touches sshd and cannot
  block anyone.
