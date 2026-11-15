#!/bin/sh
# Bring up the inner dockerd and the simulated external host, then exec the test command.
set -eu

: "${HARBORSHIELD_E2E_LOG_DIR:?HARBORSHIELD_E2E_LOG_DIR must name a writable log directory}"
: "${HARBORSHIELD_E2E_IMAGES:?HARBORSHIELD_E2E_IMAGES must name the e2e images directory}"
# HARBORSHIELD_E2E_OWNER, as uid:gid, receives ownership of the logs when the run ends.
mkdir -p "$HARBORSHIELD_E2E_LOG_DIR"

dockerd >"$HARBORSHIELD_E2E_LOG_DIR/dockerd.log" 2>&1 &
dockerd_pid=$!

attempts=0
until docker info >/dev/null 2>&1; do
    if ! kill -0 "$dockerd_pid" 2>/dev/null; then
        echo "dockerd exited during startup:" >&2
        tail -n 50 "$HARBORSHIELD_E2E_LOG_DIR/dockerd.log" >&2
        exit 1
    fi
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 120 ]; then
        echo "dockerd was not ready after 60s:" >&2
        tail -n 50 "$HARBORSHIELD_E2E_LOG_DIR/dockerd.log" >&2
        exit 1
    fi
    sleep 0.5
done

# The image cache volume outlives runs; an interrupted run can leave labelled resources behind.
docker ps -aq --filter label=harborshield.e2e | xargs -r docker rm -f >/dev/null
docker network ls -q --filter label=harborshield.e2e | xargs -r docker network rm >/dev/null

docker build --quiet --tag harborshield-e2e-fixture \
    --file "$HARBORSHIELD_E2E_IMAGES/fixture.Dockerfile" "$HARBORSHIELD_E2E_IMAGES" >/dev/null

# Simulated external host: a namespace behind a veth with two source addresses, so
# allowlists can be tested with one permitted and one foreign source.
ip netns add hs-ext
ip link add hs-ext-host type veth peer name hs-ext-peer
ip link set hs-ext-peer netns hs-ext
ip addr add 198.18.0.1/24 dev hs-ext-host
ip link set hs-ext-host up
ip -n hs-ext addr add 198.18.0.2/24 dev hs-ext-peer
ip -n hs-ext addr add 198.18.0.3/24 dev hs-ext-peer
ip -n hs-ext link set lo up
ip -n hs-ext link set hs-ext-peer up
ip -n hs-ext route add default via 198.18.0.1

# Services on the external host, for output rules that target IPs outside Docker.
HS_NAME=external ip netns exec hs-ext hs-serve tcp:7000 tcp:7001 udp:7053 udp:7054 \
    >"$HARBORSHIELD_E2E_LOG_DIR/external-serve.log" 2>&1 &

attempts=0
until hs-probe tcp 198.18.0.2 7000 | grep -q '^CONNECTED '; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 40 ]; then
        echo "external host services were not listening after 20s:" >&2
        cat "$HARBORSHIELD_E2E_LOG_DIR/external-serve.log" >&2
        exit 1
    fi
    sleep 0.5
done

export HARBORSHIELD_E2E_HOST_ADDR=198.18.0.1
export HARBORSHIELD_E2E_EXT_NETNS=hs-ext
export HARBORSHIELD_E2E_EXT_ADDR=198.18.0.2
export HARBORSHIELD_E2E_EXT_FOREIGN_ADDR=198.18.0.3

# Run the tests as a child so the logs can be handed back to the invoking user afterwards;
# the sandbox runs as root and would otherwise leave root-owned files in their tree.
"$@" &
child=$!
trap 'kill -TERM "$child" 2>/dev/null' INT TERM
status=0
wait "$child" || status=$?
# A signal interrupts the first wait; wait again for the child's real exit status.
if kill -0 "$child" 2>/dev/null; then
    wait "$child" || status=$?
fi
if [ -n "${HARBORSHIELD_E2E_OWNER:-}" ]; then
    chown -R "$HARBORSHIELD_E2E_OWNER" "$HARBORSHIELD_E2E_LOG_DIR"
fi
exit "$status"
