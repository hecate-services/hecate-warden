#!/usr/bin/env bash
# Deploy a warden as a sidecar to macula-station on a PUBLIC box.
#
# SENSING-ONLY by default (SPARTAN_TARPIT_PORTS="[]"): the warden only reads the
# box's real auth log and publishes threat facts. It opens NO listening ports,
# adds NO attack surface, and touches nothing on the station. The real port-22
# firehose is already arriving; the warden just starts reading it. Turn on the
# tarpit later by passing decoy ports (and opening them in the box's firewall).
#
# It dials a LOCAL station on the box (a loopback hop) and publishes in the
# realm, so its facts reach the sentinel over the relay mesh. Storeless: the box
# holds no evidence — that lives in hecate-sentinel, off the attacked machine.
#
#   HECATE_REALM=<64-hex> ./scripts/deploy-warden.sh <ssh-host> <station-seed> [auth-log]
set -euo pipefail

IMAGE="${WARDEN_IMAGE:-ghcr.io/hecate-services/hecate-warden:latest}"
REALM="${HECATE_REALM:?set HECATE_REALM to the 64-hex realm tag}"
HOST="${1:?usage: deploy-warden.sh <ssh-host> <station-seed> [auth-log]}"
SEED="${2:?usage: deploy-warden.sh <ssh-host> <station-seed> [auth-log]}"
AUTHLOG="${3:-/var/log/auth.log}"
# Decoy ports for the tarpit. Empty = sensing only (no listeners). Set e.g.
# "[2222,2323,23]" once the box firewall opens them.
PORTS="${SPARTAN_TARPIT_PORTS:-[]}"
# The beam boxes log in as rl; the public Hetzner boxes as root. Override with
# SSH_USER=root (the ssh config already maps their IdentityFile by hostname).
SSH_USER="${SSH_USER:-rl}"

ssh -o BatchMode=yes "${SSH_USER}@${HOST}" \
    "IMAGE='${IMAGE}' REALM='${REALM}' SEED='${SEED}' AUTHLOG='${AUTHLOG}' PORTS='${PORTS}' bash -s" <<'REMOTE'
set -euo pipefail
which docker >/dev/null || sudo=sudo
${sudo:-} docker pull "$IMAGE" >/dev/null
${sudo:-} docker rm -f hecate-warden >/dev/null 2>&1 || true
${sudo:-} docker run -d --name hecate-warden --restart unless-stopped --network host \
  -e HECATE_REALM="$REALM" \
  -e MACULA_STATION_SEEDS="$SEED" \
  -e HECATE_NODE_NAME=hecate_warden \
  -e HECATE_NODE_HOST=127.0.0.1 \
  -e HECATE_COOKIE=hecate_warden \
  -e HECATE_HEALTH_PORT=8460 \
  -e HECATE_WARDEN_TARPIT_PORTS="$PORTS" \
  -e HECATE_WARDEN_MAX_CONNS=65536 \
  -e HECATE_WARDEN_AUTH_LOG=/host/log/auth.log \
  -v "${AUTHLOG}:/host/log/auth.log:ro" \
  "$IMAGE" >/dev/null
echo "  hecate-warden up on $(hostname) -> ${SEED} (tarpit ports: ${PORTS})"
REMOTE
