# hecate-warden

The deceptive threshold guard. A Layer-2 hecate-om service that runs as a
sidecar to `macula-station` on the **public** boxes — the ones taking tens of
thousands of intrusion attempts a day — and turns those attacks into wasted
attacker time and shared intelligence.

## Why it exists

The public boxes are the most-attacked machines in the fleet. So the warden
holds the *least*: **no event store, no cognition, no LLM key**, and a minimal
mesh identity that can only publish threat facts. If a box is popped, an attacker
gains a tarpit controller for one location — nothing more. The durable evidence
chain lives in `hecate-spartan`, on infrastructure that is not under attack.

## What it does (v1)

- **Senses.** Reads the host auth log for real attacks on the box's real sshd —
  every attacker, the volume, the material that correlates across countries.
  Publishes `warden/threats`.
- **Ensnares.** Binds decoy ports and holds every connection open, dribbling an
  endless slow fake SSH banner. A scanner sits there for hours for the cost to us
  of a socket and a timer. Publishes `warden/ensnared` (who took the bait, and
  how long we held them). This is endlessh, in the language built for it — BEAM
  holds tens of thousands of idle connections without breaking a sweat.

It does **not** block. A blocklist just sends the attacker to the next victim. A
tarpit wastes their time and teaches us who they are, and every action is
entirely our own resource — nothing reaches toward the attacker's machine.

## What's next (v2)

A sweet honeypot — a fake shell they can "log into", every keystroke recorded,
with the deception tuned live by the Spartan agents (a drone decides "this one's
interesting, promote them"). Plus the abuse-report pipeline: assemble the
immutable evidence and file it with the hosting provider and the national CERT.

## Deploy

Runs as a container beside `macula-station`. By default the tarpit binds decoy
ports (2222, 2323, 23) — NOT the box's real sshd. To catch the SSH firehose on
port 22, move real admin SSH to a high port first (per box, opt-in), then point
the tarpit at 22.
