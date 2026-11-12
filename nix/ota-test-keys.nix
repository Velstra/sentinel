# PUBLIC, disposable keys for isolated loopback VM tests only. Never import
# into an appliance module, release signer or deployed update channel.
{ pkgs }:
pkgs.runCommand "qa-ota-loopback-disposable-keys" { nativeBuildInputs = [ pkgs.openssl ]; } ''
  mkdir -p "$out"
  openssl genpkey -algorithm ed25519 -out "$out/release.key"
  openssl pkey -in "$out/release.key" -pubout -out "$out/release.pub"
  # Nix caches this derivation independently of fresh VM-run nonces. A 3-day
  # certificate makes subsequent weekly runs fail without a product regression.
  # Long validity is ONLY appropriate for these public, loopback test keys;
  # real TLS date, CA and IP validation remain enabled in the update client.
  openssl req -x509 -newkey rsa:2048 -nodes -days 36500 -subj /CN=qa-loopback \
    -addext 'subjectAltName=IP:127.0.0.1' -addext 'basicConstraints=critical,CA:TRUE' \
    -keyout "$out/tls.key" -out "$out/tls.crt"
  now=$(date +%s)
  week=$((now + 604800))
  decade=$((now + 315360000))
  for at in "$now" "$week" "$decade"; do
    openssl verify -CAfile "$out/tls.crt" -purpose sslserver -verify_ip 127.0.0.1 \
      -attime "$at" "$out/tls.crt"
  done
  # Reproduce the previous failure: the same verifier MUST reject an expired
  # 3-day control a week later. No -no_check_time or verification bypass exists.
  openssl req -x509 -key "$out/tls.key" -days 3 -subj /CN=expired-control \
    -addext 'subjectAltName=IP:127.0.0.1' -addext 'basicConstraints=critical,CA:TRUE' \
    -out "$TMPDIR/expired-control.crt"
  if openssl verify -CAfile "$TMPDIR/expired-control.crt" -verify_ip 127.0.0.1 \
      -attime "$week" "$TMPDIR/expired-control.crt" > "$TMPDIR/expired.log" 2>&1; then
    echo 'expired control unexpectedly verified' >&2
    exit 1
  fi
  grep -q 'certificate has expired' "$TMPDIR/expired.log"
  if openssl verify -CAfile "$out/tls.crt" -verify_ip 127.0.0.2 \
      -attime "$week" "$out/tls.crt" > "$TMPDIR/ip.log" 2>&1; then
    echo 'wrong-IP control unexpectedly verified' >&2
    exit 1
  fi
  grep -q 'IP address mismatch' "$TMPDIR/ip.log"
  printf '%s\n' 'current/week/decade TLS validation passed; expired and wrong-IP controls rejected' \
    > "$out/validity-proof.txt"
''
