# Changelog

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
