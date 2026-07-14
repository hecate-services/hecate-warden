# hecate-warden

A deceptive threshold guard you bolt onto a public-facing box. It watches the
intrusion attempts your server is *already* taking, turns the persistent ones
into a shared, provenanced indicator on a federated mesh, and — if you let it —
wastes attackers' time in a tarpit. It never blocks, never stores your logs, and
never sends anything but the indicator itself.

Drop it in as a sidecar, set a handful of environment variables, and your box
starts contributing to — and benefiting from — a **commons of threat
intelligence**. That is the whole idea: the same botnet is hammering everyone's
boxes; if each of us reports what we see, all of us see the campaign before it
reaches the next door.

> **Integrating on your own infrastructure?** Jump to the
> [Integration guide](docs/INTEGRATION.md) — it is the copy-paste drop-in.

---

## Why it exists

Every public box on the internet takes tens of thousands of credential-spray
attempts a day from a broad, distributed botnet. Individually that noise is
useless. Correlated across many boxes it is a map of who is attacking, from
where, with what — and it arrives with a head start: we have measured a median
of ~56 minutes between the same attacker hitting one box and reaching the next.

The warden's job is to make that correlation possible **without** the two things
that usually come with "threat intelligence": a central vendor hoovering up
everyone's logs, and a blocklist that just shoves the attacker at the next
victim. Instead:

- **Only the indicator leaves the box** — a source IP, an attempt count, the
  usernames tried. Your logs never leave. There is no aggregator, no single
  point of surveillance.
- **It never blocks.** A blocklist protects one box and passes the attacker on.
  A tarpit *costs the attacker time* and *teaches the federation who they are* —
  and every action is spent on our own resources; nothing ever reaches toward
  the attacker's machine.

## What it does

- **Senses.** Reads the host's auth log (mounted read-only) for real attacks on
  the box's real sshd. Counts attempts per source IP in a rolling window, and
  when one crosses a threshold (default: 5 failures / 5 min) publishes a
  `warden/threats` fact — the IP, the count, the usernames tried.
- **Ensnares** *(optional)*. Binds decoy ports and holds every connection open,
  dribbling an endless slow fake SSH banner. A scanner sits there for hours for
  the cost to you of a socket and a timer. Publishes `warden/ensnared` — who
  took the bait and how long you held them. This is endlessh, in the language
  built for it: the BEAM holds tens of thousands of idle sockets without
  breaking a sweat.

## What it deliberately does NOT do

The warden runs on the most-attacked machine you own, so it holds the *least*:

- **No log storage, no aggregation.** It reads the log, extracts the indicator,
  forgets the rest. The durable evidence chain is built elsewhere, on
  infrastructure that is not under attack.
- **No cognition, no LLM key, no credentials of value.** If the box is popped,
  the entire blast radius is a threat-reporter for one location.
- **No blocking, no reaching outward.** Its whole capability menu is "report" and
  "ensnare" — small and safe by construction.
- **No added attack surface by default.** In sensing-only mode (the default) it
  opens no listening ports at all; it only reads a log that is already being
  written.

## Two modes

| Mode | Ports opened | What you get | Risk added |
|---|---|---|---|
| **Sensing-only** (default) | none | Shared threat indicators from your real sshd firehose | **zero** — reads an existing log |
| **Tarpit** (opt-in) | decoy ports you open | The above, plus attacker-time wasted + `ensnared` facts | the decoy ports you choose to open |

Start sensing-only. Turn the tarpit on later by opening decoy ports in your
firewall and listing them in one env var. Never point the tarpit at your real
sshd port unless you have moved admin SSH to a high port first.

## Quick start (drop-in sidecar)

The distributable is a container. Add it beside your public service:

```yaml
# docker-compose.yml (excerpt — full example in deploy/docker-compose.yml)
services:
  hecate-warden:
    image: ghcr.io/hecate-services/hecate-warden:latest
    restart: unless-stopped
    network_mode: host
    environment:
      HECATE_WARDEN_TENANT_ID: acme-corp        # WHO you are (your org)
      HECATE_WARDEN_LABEL:     web-01            # WHERE this is (this box)
      HECATE_REALM:            "<64-hex realm>"  # the commons you join
      MACULA_STATION_SEEDS:    https://station-de-frankfurt.macula.io:4433
      HECATE_WARDEN_TARPIT_PORTS: "[]"           # sensing-only
      HECATE_WARDEN_AUTH_LOG:  /host/log/auth.log
    volumes:
      - /var/log/auth.log:/host/log/auth.log:ro  # read-only
```

That is the entire integration: your box now contributes to the commons and
opens nothing. Full walkthrough, all env vars, and the tarpit step are in the
[Integration guide](docs/INTEGRATION.md).

## Identity: `tenant_id` and `label`

Two fields ride on every fact, and they answer different questions:

- **`tenant_id`** — *who operates this warden.* Set it to your own id when you
  drop the sidecar into your stack. The commons uses it to **attribute** a
  sighting to its contributor and to let you filter to your own fleet.
- **`label`** — *where this warden runs.* A box or service name (`web-01`,
  `helsinki`), so a sighting says where it was seen without decoding a DID.

Crucially, **`tenant_id` never scopes correlation** — that stays global on
purpose. An attacker seen by *your* box and by *someone else's* is exactly the
cross-organisation campaign the commons exists to surface, and both of you see
it. tenant_id is for attribution and your own views, not for walling off your
intelligence.

Each warden also mints an ephemeral mesh identity (a DID) at boot, so every fact
carries cryptographic provenance of the reporter. See
[Integration → Trust & identity](docs/INTEGRATION.md#trust--identity) for how
attribution hardens from self-asserted to provisioned as the commons grows.

## Configuration

Everything is environment variables (see `config/sys.config.src`). The full
reference with defaults is in the
[Integration guide](docs/INTEGRATION.md#environment-reference). The ones you will
actually set:

| Variable | Meaning |
|---|---|
| `HECATE_WARDEN_TENANT_ID` | your org id (attribution) |
| `HECATE_WARDEN_LABEL` | this box/service name |
| `HECATE_REALM` | the 64-hex mesh realm (the commons you join) |
| `MACULA_STATION_SEEDS` | a station URL to reach the mesh |
| `HECATE_WARDEN_TARPIT_PORTS` | `[]` for sensing-only, else e.g. `[2222,2323]` |
| `HECATE_WARDEN_AUTH_LOG` | path to the auth log inside the container |

## The facts it publishes

Two topics, integration facts (not domain events — the warden holds no store):

- `warden/threats` — `{type, warden(DID), tenant_id, label, source_ip, attempts, window_s, usernames, at}`
- `warden/ensnared` — `{type, warden(DID), tenant_id, label, source_ip, held_ms, at}`

Downstream, `hecate-sentinel` correlates these across boxes and countries and
raises campaigns to the society; nothing about that consumer is your concern to
run. You publish; the commons reasons.

## Architecture (one screen)

```
   your box                             the commons (elsewhere)
 ┌───────────────────────┐           ┌──────────────────────────┐
 │ sshd  ──▶ auth.log     │           │ hecate-sentinel          │
 │           │ (ro mount) │  facts    │  correlate cross-box,    │
 │        hecate-warden ──┼──────────▶│  raise campaigns         │
 │        (sense/ensnare) │  (mesh)   │        │                 │
 │  opens nothing by      │           │  hecate-spartan society  │
 │  default; holds least  │           │  judge targeted vs noise │
 └───────────────────────┘           └──────────────────────────┘
   only the INDICATOR crosses — never your logs
```

The warden is the only part that runs on your infrastructure. The consumers
(`hecate-sentinel`, the `hecate-spartan` society) run on the commons side and are
not your concern to operate.

## Build & test

```bash
rebar3 compile
rebar3 eunit      # tarpit_tests
rebar3 lint
```

## Roadmap

- A sweet honeypot — a fake shell attackers can "log into," every keystroke
  recorded, deception tuned live.
- The abuse-report pipeline — assemble the immutable evidence and file it with
  the hosting provider and the national CERT.
- Provisioned per-tenant identity — attributable, revocable membership so the
  commons stays trustworthy at scale.

## License

See [LICENSE](LICENSE). Contributions welcome — this is a commons.
