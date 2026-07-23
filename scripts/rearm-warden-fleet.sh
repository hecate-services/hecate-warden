#!/usr/bin/env bash
# Re-arm the warden across the whole public fleet in one pass.
#
# Wraps deploy-warden.sh (sibling script) for every public box we own. SENSING
# ONLY: no listening ports, no attack surface, no station changes. Reversible
# per box with `docker rm -f hecate-warden`.
#
# 6 canonical boxes (the pre-2026-07-18 fleet minus dist-hetzner-nuremberg,
# phased out 2026-07). The 2 Linode stub boxes are NEW coverage: Nanode 1GB, a
# sensing-only warden fits comfortably (a full macula-station does NOT — do not
# add one without a plan bump). See infrastructure/WARDEN.md.
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

# box = "ssh-host|station-seed|label|lat_e6|lng_e6". Public boxes log in as root.
# lat/lng are the box's real-city micro-degrees (degrees x 1e6) — WITHOUT them
# the warden announces presence but the /vigil map draws NO marker for it. The
# 3 Nuremberg boxes carry small offsets so they render as a cluster, not a stack.
#
# ALL wardens seed station-de-frankfurt — the sentinel's own station — so every
# warden->sentinel hop is 1-hop (same station), which delivers reliably. The
# earlier design seeded the station-box wardens at their LOCAL station
# (helsinki->fr-paris, falkenstein->be-brussels) and relied on cross-relay
# interest propagation to reach the sentinel; that multi-hop path did not
# converge, so the fleet is collapsed onto the de-frankfurt hub (2026-07-23).
STATIONS=(
  "relays-hetzner-helsinki.macula.io|${FRANKFURT}|helsinki|60169900|24938400"
  "relays-hetzner-nuremberg.macula.io|${FRANKFURT}|nuremberg|49452100|11076700"
  "stations-hetzner-falkenstein.macula.io|${FRANKFURT}|falkenstein|50477900|12371300"
  "macula.io|${FRANKFURT}|frankfurt|50110900|8682100"
  "relays-linode-paris.macula.io|${FRANKFURT}|paris|48856600|2352200"
)
RELAYS=(
  "159.69.210.171|${FRANKFURT}|reckon-db|49435000|11060000"
)
# NEW coverage (user request 2026-07-23): the two Linode stub Nanodes.
STUBS=(
  "172.232.219.239|${FRANKFURT}|milan|45464200|9190000"
  "172.234.124.60|${FRANKFURT}|stockholm|59329300|18068600"
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
  IFS='|' read -r host seed label lat lng <<<"$box"
  echo "── ${host} → ${seed}  (${label} @ ${lat}/${lng})"
  if [[ -n "${DRY_RUN:-}" ]]; then
    echo "   DRY_RUN: SSH_USER=root WARDEN_LABEL=${label} HECATE_WARDEN_LAT_E6=${lat} HECATE_WARDEN_LNG_E6=${lng} HECATE_REALM=… ${DEPLOY} ${host} ${seed}"
    continue
  fi
  SSH_USER=root WARDEN_LABEL="$label" \
    HECATE_WARDEN_LAT_E6="$lat" HECATE_WARDEN_LNG_E6="$lng" \
    HECATE_REALM="$HECATE_REALM" "$DEPLOY" "$host" "$seed"
done
echo "Done. /threats fills as wardens report; /vigil draws a marker per box now that coords are set."
