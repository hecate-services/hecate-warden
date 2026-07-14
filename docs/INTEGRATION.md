# Integrating hecate-warden on your own infrastructure

This is the drop-in guide for a third party who wants to add a warden as a
sidecar to a public-facing service — and, in doing so, join a federated threat
commons. If you have not read the [README](../README.md), start there for the
"why."

The promise: **copy a compose file, set five environment variables, and your box
contributes to the commons while opening nothing.**

- [Prerequisites](#prerequisites)
- [Step 1 — Drop in the sidecar (sensing-only)](#step-1--drop-in-the-sidecar-sensing-only)
- [Step 2 — Verify it works](#step-2--verify-it-works)
- [Step 3 (optional) — Turn on the tarpit](#step-3-optional--turn-on-the-tarpit)
- [Environment reference](#environment-reference)
- [`tenant_id` vs `label`](#tenant_id-vs-label)
- [Trust & identity](#trust--identity)
- [Privacy: what leaves your box](#privacy-what-leaves-your-box)
- [FAQ](#faq)

---

## Prerequisites

- A public-facing Linux box that runs a real service under attack (typically
  `sshd` writing to `/var/log/auth.log`, or `/var/log/secure` on RHEL-family).
- A container runtime (Docker or Podman).
- **Public IPv6** on the box *if* you dial an IPv6-only station seed. The
  public Macula stations are IPv6-only; the warden reaches them over the host's
  IPv6, which is why it runs with `network_mode: host`. If your box is
  IPv4-only, ask for an IPv4-reachable seed.
- The commons you are joining will give you two values: a **realm** (a 64-hex
  string — the topic scope everyone shares) and a **station seed** (a URL to
  reach the mesh). These are not secrets.

## Step 1 — Drop in the sidecar (sensing-only)

Copy `deploy/docker-compose.yml` and `deploy/.env.example` from this repo. Fill
in `.env`:

```dotenv
# .env  — the five you actually set
HECATE_WARDEN_TENANT_ID=acme-corp
HECATE_WARDEN_LABEL=web-01
HECATE_REALM=074acb6cb190d8ef79fdbdd8e8e76d53f6292c181fd23f4d3998560f9a94e8e3
MACULA_STATION_SEEDS=https://station-de-frankfurt.macula.io:4433
HECATE_WARDEN_AUTH_LOG_HOST=/var/log/auth.log
```

Then:

```bash
docker compose up -d
docker compose logs -f hecate-warden
```

That is it. The warden is now:

- reading `/var/log/auth.log` (read-only) and reporting persistent attackers,
- opening **no ports** (`HECATE_WARDEN_TARPIT_PORTS` defaults to `[]`),
- publishing to the commons realm you joined.

If you prefer a single `docker run`:

```bash
docker run -d --name hecate-warden --restart unless-stopped --network host \
  -e HECATE_WARDEN_TENANT_ID=acme-corp \
  -e HECATE_WARDEN_LABEL=web-01 \
  -e HECATE_REALM=<64-hex realm> \
  -e MACULA_STATION_SEEDS=https://station-de-frankfurt.macula.io:4433 \
  -e HECATE_WARDEN_TARPIT_PORTS="[]" \
  -e HECATE_WARDEN_AUTH_LOG=/host/log/auth.log \
  -e HECATE_HEALTH_PORT=8460 \
  -v /var/log/auth.log:/host/log/auth.log:ro \
  ghcr.io/hecate-services/hecate-warden:latest
```

## Step 2 — Verify it works

1. **Health.** `curl -s localhost:8460/` should answer (the warden is up).
2. **It is reading the log.** `docker logs hecate-warden` shows startup and, as
   soon as a source IP crosses the threshold, lines like:
   `[warden] threat: 45.148.10.240 (7 attempts/300s) users=[...]`.
3. **It reached the mesh.** The logs show the macula pool attaching and a link
   to your station seed forming. Persistent-attacker facts flow from there; if
   the mesh is unreachable the warden keeps sensing and simply drops the facts
   (an unreachable commons never stops the guard from doing its job).

No attackers yet? On a fresh public box you usually wait minutes, not hours —
the botnet finds you fast.

## Step 3 (optional) — Turn on the tarpit

Sensing-only adds zero attack surface. The tarpit adds decoy ports that waste
attackers' time. Do it deliberately:

1. **Choose decoy ports** that are not your real services — e.g. `2222`, `2323`.
   (Port `23`/telnet is a classic magnet but needs root/`CAP_NET_BIND_SERVICE`.)
2. **Open them in your firewall.** The tarpit only helps if attackers can reach
   the decoy ports.
3. **List them** in the env var and restart:

   ```dotenv
   HECATE_WARDEN_TARPIT_PORTS=[2222,2323]
   ```

Every connection to a decoy port is held open with an endless slow fake SSH
banner; when the attacker gives up you get a `warden/ensnared` fact with how
long you held them.

> **Do not** point the tarpit at your real sshd port (`22`) unless you have first
> moved admin SSH to a high port. The warden cannot lock you out — but a tarpit
> on `22` will swallow your own logins too.

## Environment reference

| Variable | Default | Meaning |
|---|---|---|
| `HECATE_WARDEN_TENANT_ID` | *(unset → unattributed)* | WHO operates this warden — your org id. Carried on every fact. |
| `HECATE_WARDEN_LABEL` | *(unset → `undefined`)* | WHERE it runs — a box/service name. Carried on every fact. |
| `HECATE_REALM` | — | The 64-hex realm (the commons). **Required.** |
| `MACULA_STATION_SEEDS` | — | Station URL(s) to reach the mesh. **Required.** |
| `HECATE_WARDEN_TARPIT_PORTS` | `[]` | Decoy ports as an Erlang list literal, e.g. `[2222,2323]`. `[]` = sensing-only. |
| `HECATE_WARDEN_MAX_CONNS` | `65536` | Max concurrent tarpit connections held open. |
| `HECATE_WARDEN_LAT_E6` | *(unset → no marker)* | This box's latitude in **micro-degrees** (integer; the mesh drops raw floats). E.g. Helsinki `60170000`. Announced on the `warden/presence` heartbeat so the map self-populates. **Self-asserted** — a warden can claim any location; unset = listed online without a map marker. |
| `HECATE_WARDEN_LNG_E6` | *(unset → no marker)* | This box's longitude in micro-degrees. E.g. Helsinki `24940000`. |
| `HECATE_WARDEN_AUTH_LOG` | `/host/log/auth.log` | Path to the auth log **inside the container** (mount your host log here read-only). |
| `HECATE_HEALTH_PORT` | `8460` | Local health endpoint port. |
| `HECATE_NODE_NAME` | `hecate_warden` | Erlang node name (only matters if you run more than one on a host). |
| `HECATE_COOKIE` | `hecate_warden` | Erlang distribution cookie (loopback only). |

The sensing threshold (5 failures / 5 min) and report cooldown are compiled
defaults tuned to real botnet traffic; they are not env-configurable in v1.

## `tenant_id` vs `label`

They answer different questions and both ride on every fact:

- **`tenant_id` = who.** Your organisation. Set it once per deployment. The
  commons attributes sightings to you and lets you filter dashboards to your own
  fleet. Two different orgs running wardens are two tenants.
- **`label` = where.** A single box or service. `web-01`, `db-primary`,
  `helsinki`. One tenant typically runs many labels.

**Correlation is always global** — this is the entire point. An attacker that
hits `acme-corp/web-01` and also `othertenant/gw-3` is a cross-organisation
campaign, and the commons surfaces it to everyone. `tenant_id` is for
attribution and your own views; it never partitions the intelligence. If you
want private-only intelligence, run your own realm (below) — but then you lose
the commons benefit, which is the reason to be here.

## Trust & identity

Every warden mints its own Ed25519 keypair (a DID) at boot and asks the realm
for a capability (UCAN) scoped to `warden/*` publish and nothing else. So every
fact is signed and attributable to a reporter, and a warden's authority is the
smallest possible: it can report, and it can ensnare.

Attribution hardens in stages as a commons grows, and you can pick where you sit:

- **Self-asserted (default, easiest).** Ephemeral DID + a `tenant_id` you set.
  Good for getting value immediately; trust is reputational, and a consumer can
  weight or ignore a tenant that behaves badly.
- **Provisioned (hardened, roadmap).** A per-tenant service certificate issued by
  the realm, so `tenant_id` is cryptographically bound and revocable. Use this
  when the commons needs to guarantee that a "sighting" came from a real,
  accountable participant (and to keep bad actors from poisoning the pool).

Running your **own** realm instead of a shared one is a one-line change
(`HECATE_REALM`), and turns the warden into a private, single-tenant threat
sensor. It works — you just do not get anyone else's intelligence, and they do
not get yours.

## Privacy: what leaves your box

Only the **indicator** crosses the mesh:

- source IP, attempt count, the usernames tried, a timestamp, your `tenant_id`
  and `label`.

Your logs never leave. There is no aggregator storing them, no vendor, no
central surveillance point. The warden reads a line, extracts the indicator,
and forgets the rest — it holds no store at all. The usernames attackers *try*
(e.g. `root, admin, oracle, pi`) are the revealing part and are deliberately
shared, because "which credentials is this campaign spraying" is exactly the
intelligence that helps everyone; they are the attacker's guesses, not your
users.

## FAQ

**Does it need root?** Only to bind low decoy ports (< 1024) in tarpit mode.
Sensing-only needs no privileges beyond reading the mounted log.

**Will it slow my box down?** No. Sensing is a periodic tail of one file. The
tarpit's whole design is cheapness — idle sockets on the BEAM cost almost
nothing.

**Can it lock me out or block traffic?** No. It has no capability to block, drop,
or firewall anything. Its entire menu is "report" and "ensnare."

**What if the mesh is down?** The warden keeps sensing and drops the facts it
cannot publish. It never blocks the guard on a reachable commons.

**RHEL / Amazon Linux?** Point `HECATE_WARDEN_AUTH_LOG_HOST` at
`/var/log/secure` instead of `/var/log/auth.log`.

**Multiple boxes?** Run one warden per box, same `tenant_id`, a distinct
`label` each. That is how the commons sees your fleet as your fleet.

**How do I leave?** `docker compose down` (or `docker rm -f hecate-warden`). It
is a sidecar; removing it changes nothing else on the box.
