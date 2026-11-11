#!/bin/bash
# The real Basics Station against examples/compose.yaml: the image, the file
# backend, and ChirpStack Gateway Bridge behind the gate. Passes when the
# bridge reports the gateway ONLINE over MQTT and the station gets the
# bridge's router_config back through the gate. Needs Docker and
# build/station/bin/station (scripts/build-station.sh). Tears the stack down.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STATION=${STATION_BIN:-$ROOT/build/station/bin/station}
EUI=0123456789abcdef
WORK=$(mktemp -d)
export GATEWAYS_DIR=$WORK/gateways
compose() { docker compose -f "$ROOT/examples/compose.yaml" "$@"; }

cleanup() {
    [[ -n ${STATION_PID:-} ]] && kill "$STATION_PID" 2>/dev/null || true
    compose down -v >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

[[ -s $ROOT/examples/signer_token ]] || openssl rand -hex 32 > "$ROOT/examples/signer_token"
mkdir -p "$GATEWAYS_DIR" "$WORK/home"
cp "$ROOT/examples/gateways/gateways.yaml" "$GATEWAYS_DIR/"
compose up -d --wait

compose exec -T signer basicstation-gate issue $EUI --out /state/bundles/$EUI \
    | sed -n '/^  /p' > "$WORK/entry"
{ grep -v '^gateways' "$ROOT/examples/gateways/gateways.yaml" | grep -v '^#'
  echo 'gateways:'; cat "$WORK/entry"; } > "$GATEWAYS_DIR/gateways.yaml.new"
mv "$GATEWAYS_DIR/gateways.yaml.new" "$GATEWAYS_DIR/gateways.yaml"
compose cp signer:/state/bundles/$EUI/. "$WORK/home"

cat > "$WORK/home/station.conf" <<EOF
{"SX1301_conf": {"lorawan_public": true, "clksrc": 1, "device": "spidev",
   "radio_0": {"type": "SX1257", "rssi_offset": -166.0, "tx_enable": true},
   "radio_1": {"type": "SX1257", "rssi_offset": -166.0, "tx_enable": false}},
 "station_conf": {"routerid": "123:4567:89ab:cdef", "log_file": "stderr", "log_level": "DEBUG"}}
EOF
(cd "$WORK/home" && exec "$STATION" --home . --temp "$WORK") > "$WORK/station.log" 2>&1 &
STATION_PID=$!

fail() {
    echo "FAIL: $1"
    grep -v -E '^ |^(cert|serial|issuer|subject|issued|expires|signed|EC key|basic) ' "$WORK/station.log" | tail -60
    compose logs --tail 30
    exit 1
}
compose exec -T mosquitto mosquitto_sub -t "gateway/$EUI/state/conn" -C 1 -W 30 \
    | tee "$WORK/conn" | grep -q ONLINE || fail "bridge did not report $EUI ONLINE"
for _ in $(seq 30); do
    grep -q 'Configuring for region' "$WORK/station.log" && break
    sleep 1
done
grep -q 'Configuring for region' "$WORK/station.log" || fail "station did not take the bridge's router_config"
echo "ok: $(cat "$WORK/conn")"
grep -m1 'Configuring for region' "$WORK/station.log"
