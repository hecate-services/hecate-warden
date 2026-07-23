#!/usr/bin/env bash
# Re-arm the warden across the whole public fleet in one pass.
#
# Wraps deploy-warden.sh (sibling script) for every public box we own. SENSING
# ONLY: no listening ports, no attack surface, no station changes. Reversible
# per box with `docker rm -f hecate-warden`.
#
# The 7 canonical boxes are the fleet that ran wardens before the 2026-07-18
# retirement (see infrastructure/WARDEN.md). The 2 Linode stub boxes are NEW
# coverage: they are Nanode 1GB, and a sensing-only warden fits comfortably
# (a full macula-station does NOT — do not add one without a plan bump).
#
# Usage:
#   HECATE_REALM=<64-hex> ./scripts/rearm-warden-fleet.sh          # all boxes
#   HECATE_REALM=<64-hex> ./scripts/rearm-warden-fleet.sh stations # subset (see GROUPS)
#   DRY_RUN=1 HECATE_REALM=<64-hex> ./scripts/rearm-warden-fleet.sh # print, don't ssh
#
# Never commit the realm hex. Pass it from the environment at run time.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
DEPLOY="${HERE}/deploy-warden.sh"
: "${HECATE_REALM:?set HECATE_REALM to the 64-hex realm tag}"
FRANKFURT="https://station-de-frankfurt.macula.io:4433"

# box = "ssh-host|station-seed|label-override(optional)". Blank label => derived
# from the host by deploy-warden.sh. Public boxes all log in as root.
STATIONS=(
  "relays-hetzner-helsinki.macula.io|https://station-fr-paris.macula.io:4433|"
  "relays-hetzner-nuremberg.macula.io|${FRANKFURT}|"
  "stations-hetzner-falkenstein.macula.io|https://station-be-brussels.macula.io:4433|"
  "macula.io|${FRANKFURT}|"
  "relays-linode-paris.macula.io|${FRANKFURT}|"
)
RELAYS=(
  "dist-hetzner-nuremberg.macula.io|${FRANKFURT}|"
  "159.69.210.171|${FRANKFURT}|reckon"
)
# NEW coverage (user request 2026-07-23): the two Linode stub Nanodes.
STUBS=(
  "172.232.219.239|${FRANKFURT}|milan"
  "172.234.124.60|${FRANKFURT}|stockholm"
)

group="${1:-all}"
case "$group" in
  stations) FLEET=("${STATIONS[@]}") ;;
  relays)   FLEET=("${RELAYS[@]}") ;;
  stubs)    FLEET=("${STUBS[@]}") ;;
  all)      FLEET=("${STATIONS[@]}" "${RELAYS[@]}" "${STUBS[@]}") ;;
  *) echo "unknown group '$group' (want: stations|relays|stubs|all)" >&2; exit 2 ;;
esac

echo "Re-arming ${#FLEET[@]} warden(s) in group '${group}' (realm ${HECATE_REALM:0:8}…)"
for box in "${FLEET[@]}"; do
  IFS='|' read -r host seed label <<<"$box"
  echo "── ${host} → ${seed}${label:+  (label: ${label})}"
  if [[ -n "${DRY_RUN:-}" ]]; then
    echo "   DRY_RUN: SSH_USER=root ${label:+WARDEN_LABEL=${label} }HECATE_REALM=… ${DEPLOY} ${host} ${seed}"
    continue
  fi
  if [[ -n "$label" ]]; then
    SSH_USER=root WARDEN_LABEL="$label" HECATE_REALM="$HECATE_REALM" "$DEPLOY" "$host" "$seed"
  else
    SSH_USER=root HECATE_REALM="$HECATE_REALM" "$DEPLOY" "$host" "$seed"
  fi
done
echo "Done. Verify facts flowing: the realm's /threats page fills as wardens report."
