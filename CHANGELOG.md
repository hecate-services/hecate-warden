# Changelog

## [0.2.3]

### Fixed

- `capabilities/0` returned plain binaries (`[<<"warden.report_threat">>,
  <<"warden.ensnare">>]`); `hecate_om_service:capability()` has been
  `#{name := binary(), version := pos_integer(), ...}` since at least
  hecate_om 0.16.4. Never caught because 0.2.2's `identity_key_path` fix
  was needed just to REACH the code path that cares about the shape --
  with no keypair, `build_advertisement/6` was never called at all.
  Deploying 0.2.2 to the fleet crashed `hecate_om_capabilities`
  (`function_clause`) on the first advertisement attempt after every box
  rolled. Found live within a minute of the rollout, via `docker logs`.

## [0.2.2]

### Fixed

- `identity_key_path` was never set in `config/sys.config.src` -- without it,
  `hecate_om_identity:keypair/0` returns `{error, no_keypair}` forever and
  capability advertisement (`warden.report_threat`, `warden.ensnare`)
  silently no-ops on every republish tick. No crash, no error logged; the
  node just never actually reachable on the mesh. hecate_om >= 0.14.1
  self-heals a missing/corrupt keypair FILE at a configured path, but this
  service never had a path configured at all, so bumping to 0.15 (0.2.1,
  above) did not fix it on its own. Same bug class hecate-mail, hecate-tube,
  hecate-rag and hecate-embedder each independently hit -- confirmed via a
  live DHT sweep of all 7 fleet stations showing zero `warden.*` records
  anywhere. Points at the existing `/var/lib/hecate-warden` Containerfile
  volume (previously only holding `erl_crash.dump`) rather than a new one.

## [0.2.1]

### Fixed

- Bumped `hecate_om` dependency `~> 0.10` -> `~> 0.15` (resolves 0.15.1,
  transitively macula 10.0.0 -> 10.10.0). Had drifted well behind the
  fleet this senses attacks on, including the domain-filter fix that
  was silently dropping every `macula_diagnostics:event/2,3` call on
  any consumer. Full eunit suite clean at the new versions.

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
