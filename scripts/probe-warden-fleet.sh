#!/usr/bin/env bash
# Read-only fleet probe: is each warden still SEEING threats, and is the host
# auth log it reads still growing?
#
# The warden has two independent sensors. The tarpit (decoy ports) emits
# `warden/ensnared`; the auth-log tail (`sense_auth_log`) emits
# `warden/threats`. When the map goes quiet, the first question is which of the
# two stopped, and on how many boxes. This answers exactly that and changes
# nothing.
#
# Usage: ./scripts/probe-warden-fleet.sh
set -uo pipefail

CONTAINER="${WARDEN_CONTAINER:-hecate-warden}"
AUTH_LOG="${WARDEN_AUTH_LOG:-/var/log/auth.log}"
SSH_OPTS=(-o ConnectTimeout=10 -o BatchMode=yes)
TAIL_LINES="${WARDEN_TAIL_LINES:-4000}"

BOXES=(
  "relays-hetzner-helsinki.macula.io|helsinki"
  "relays-hetzner-nuremberg.macula.io|nuremberg"
  "stations-hetzner-falkenstein.macula.io|falkenstein"
  "macula.io|frankfurt"
  "relays-linode-paris.macula.io|paris"
  "159.69.210.171|reckon-db"
  "178.105.157.209|beamcampus"
  "172.232.219.239|milan"
  "172.234.124.60|stockholm"
)

# Runs on the box. `grep -B1` picks up the OTP "=INFO REPORT====" line that
# carries the timestamp, since the threat line itself has none.
remote_probe() {
  cat <<REMOTE
container="\$(docker ps --filter name=${CONTAINER} --format '{{.Status}}' 2>/dev/null | head -1)"
echo "container: \${container:-ABSENT}"
last_threat="\$(docker logs --tail ${TAIL_LINES} ${CONTAINER} 2>&1 | grep -B1 'warden\] threat:' | grep 'INFO REPORT' | tail -1)"
echo "last_threat: \${last_threat:-none in last ${TAIL_LINES} lines}"
count="\$(docker logs --tail ${TAIL_LINES} ${CONTAINER} 2>&1 | grep -c 'warden\] threat:')"
echo "threat_lines: \${count}"
if [ -r "${AUTH_LOG}" ]; then
  echo "authlog: \$(stat -c '%y size=%s' "${AUTH_LOG}")"
else
  echo "authlog: MISSING or unreadable at ${AUTH_LOG}"
fi
echo "authlog_dir: \$(ls -1 \$(dirname ${AUTH_LOG})/auth.log* 2>/dev/null | tr '\n' ' ')"
echo "mount: \$(docker inspect ${CONTAINER} --format '{{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}' 2>/dev/null)"
REMOTE
}

for entry in "${BOXES[@]}"; do
  IFS='|' read -r host label <<<"$entry"
  echo "########## ${label}  (${host}) ##########"
  remote_probe | ssh "${SSH_OPTS[@]}" "root@${host}" bash -s 2>&1 |
    grep -v "post-quantum\|store now\|openssh.com/pq\|may need to be upgraded"
  echo
done
