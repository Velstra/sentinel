#!/usr/bin/env bash
# Run the console's browser tests against a real appliance API.
#
#   tests/console/run.sh [path-to-sentinel-binary]
#
# Starts the API on a loopback port with a throwaway configuration and token,
# drives a headless browser against it, and tears everything down. `--no-apply`
# is what makes this safe to run on a workstation: the process edits its own
# temporary TOML and never touches the machine's network.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
bin=${1:-}

# Built, not merely found. Preferring an existing binary made this suite report
# on whatever was compiled last: two runs in a row said the console could not set
# a setting that had been added to it, because the page under test was the one
# from before the change. A cargo build that has nothing to do costs a second;
# a suite that quietly tests yesterday's binary costs an afternoon.
if [ -z "$bin" ]; then
  echo "building sentinel…" >&2
  (cd "$root" && cargo build -q)
  bin="$root/target/debug/sentinel"
fi

work=$(mktemp -d)
port=${CONSOLE_PORT:-18099}
trap 'kill "${api_pid:-0}" 2>/dev/null || true; rm -rf "$work"' EXIT

# A small but real configuration: the masks have to show something, and an
# empty appliance would let a broken reader pass for a clean one.
cat > "$work/config.toml" <<'TOML'
[system]
hostname = "console-test"
TOML
echo "consoletoken" > "$work/token"

# Output kept, and a refusal is fatal. One line the appliance will not take
# aborts the whole script — so a seed that silently failed left an appliance
# with nothing on it, and every test that reads something read an empty box.
SENTINEL_CONFIG="$work/config.toml" "$bin" configure \
  --config "$work/config.toml" --no-apply > "$work/seed.log" 2>&1 <<'CLI'
set interface eth0 zone lan
set interface eth1 zone wan
set interface eth0 address 10.0.0.1/24
set firewall zone lan default-action accept
set firewall zone wan default-action drop
set firewall rule web-in from wan
set firewall rule web-in to lan
set firewall rule web-in action accept
set firewall rule web-in proto tcp
set firewall rule web-in port 443
set protocols ospf interface eth0
set protocols ospf area 0.0.0.0
set protocols bgp local-as 65001
set interface wg0 type wireguard
set vpn wireguard wg0 listen-port 51820
set vpn wireguard wg0 private-key AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
set services ssh port 22
# One of every object whose form only exists once the object does: a route map
# and a prefix list have settings of their own, and a DHCP server and a router
# advertisement have a row that can be turned off. On an appliance without them
# those masks are correctly absent — and a walk over that appliance reports them
# as things the console cannot do.
set interface eth0 address6 fd00:a::1/64
set interface eth0 dhcp-server enable
set interface eth0 router-advert enable
set policy prefix-list customers rule 10 prefix 10.0.0.0/8
set policy route-map to-transit rule 10 action permit
# The management plane serves TLS by default, and the harness below drives the
# console over plain http on loopback. `enable` is what keeps the section alive
# through `save` — without it the whole `[services.web]` table is dropped and the
# API comes back up on HTTPS, where every request in this suite fails at connect.
set services web enable true
set services web tls false
commit
save
CLI
if ! grep -q "commit ok" "$work/seed.log"; then
  echo "the seed configuration was refused — the tests would run on an empty appliance:" >&2
  cat "$work/seed.log" >&2
  exit 1
fi

"$bin" api --listen "127.0.0.1:$port" --config "$work/config.toml" \
  --token-file "$work/token" --no-apply >"$work/api.log" 2>&1 &
api_pid=$!

for _ in $(seq 40); do
  if curl -fsS -o /dev/null "http://127.0.0.1:$port/api/v1/health" 2>/dev/null; then break; fi
  sleep 0.25
done

echo "console tests against http://127.0.0.1:$port"
# The API's own log is what explains a test that could not reach it, so a
# failure prints it rather than leaving the reader with "connection refused".
if ! CONSOLE_URL="http://127.0.0.1:$port/" \
     CONSOLE_TOKEN="consoletoken" \
     CONSOLE_CONFIG="$work/config.toml" \
     node "$here/console.test.mjs"; then
  echo "--- the appliance API said:" >&2
  tail -40 "$work/api.log" >&2 || true
  exit 1
fi
