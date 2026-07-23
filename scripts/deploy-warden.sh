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
# A human name for this warden, carried on every fact. Defaults to the last
# dash-segment of the ssh host (relays-hetzner-helsinki -> helsinki); override
# with WARDEN_LABEL for boxes whose name is an IP or unclear.
_h="${HOST%%.*}"
LABEL="${WARDEN_LABEL:-${_h##*-}}"
# WHO operates this warden — our own tenant id, carried on every fact so the
# commons attributes our sightings to us. Third parties set their own.
TENANT_ID="${WARDEN_TENANT_ID:-hecate}"
# Self-asserted micro-degree coordinates (lat/lng x 1e6, integers — the mesh
# drops raw floats). Carried on the presence heartbeat so the /vigil map DRAWS a
# marker for this box. UNSET = the box is listed online but NOT placed on the
# map (this is the "no warden markers" symptom). Set per box.
LAT_E6="${HECATE_WARDEN_LAT_E6:-}"
LNG_E6="${HECATE_WARDEN_LNG_E6:-}"
# The beam boxes log in as rl; the public Hetzner boxes as root. Override with
# SSH_USER=root (the ssh config already maps their IdentityFile by hostname).
SSH_USER="${SSH_USER:-rl}"

ssh -o BatchMode=yes "${SSH_USER}@${HOST}" \
    "IMAGE='${IMAGE}' REALM='${REALM}' SEED='${SEED}' AUTHLOG='${AUTHLOG}' PORTS='${PORTS}' LABEL='${LABEL}' TENANT_ID='${TENANT_ID}' LAT_E6='${LAT_E6}' LNG_E6='${LNG_E6}' bash -s" <<'REMOTE'
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
  -e HECATE_WARDEN_TENANT_ID="$TENANT_ID" \
  -e HECATE_WARDEN_LABEL="$LABEL" \
  -e HECATE_WARDEN_LAT_E6="$LAT_E6" \
  -e HECATE_WARDEN_LNG_E6="$LNG_E6" \
  -v "${AUTHLOG}:/host/log/auth.log:ro" \
  "$IMAGE" >/dev/null
echo "  hecate-warden up as \"${TENANT_ID}/${LABEL}\" -> ${SEED} (tarpit ports: ${PORTS}; coords: ${LAT_E6:-unset}/${LNG_E6:-unset})"
REMOTE
