# Build the real agent and its privileged maintenance integration test together.
# base must contain the reviewed maintenance implementation, not just the probe.
{ pkgs, base, testSource }:
base.overrideAttrs (old: {
  pname = "expiry-maintenance-probe";
  nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ pkgs.jq ];
  postPatch = (old.postPatch or "") + ''
    mkdir -p velstra-app/tests
    cp ${testSource} velstra-app/tests/expiry_maintenance.rs
  '';
  buildPhase = ''
    runHook preBuild
    cargo build --release --locked --offline --ignore-rust-version -p velstra --bin velstra
    # Native inventory tests need real /sys and iproute2: execute these exact
    # binaries inside the VM, not the build sandbox and not with tests skipped.
    cargo test --release --locked --offline --ignore-rust-version -p velstra --bin velstra --no-run --message-format=json > agent-tests.json
    cargo test --release --locked --offline --ignore-rust-version -p velstra --test expiry_maintenance --no-run
    cargo clippy --release --locked --offline --ignore-rust-version -p velstra --bin velstra --test expiry_maintenance -- -D warnings
    runHook postBuild
  '';
  installPhase = ''
    mkdir -p "$out/bin"
    mapfile -t unit_tests < <(jq -r 'select(.reason == "compiler-artifact" and .profile.test and .target.name == "velstra" and .executable != null) | .executable' agent-tests.json)
    test "''${#unit_tests[@]}" = 1
    cp "''${unit_tests[0]}" "$out/bin/velstra-unit-tests"
    count=0
    for probe in target/*/release/deps/expiry_maintenance-* target/release/deps/expiry_maintenance-*; do
      if test -f "$probe" && test -x "$probe"; then
        test "$count" = 0
        cp "$probe" "$out/bin/expiry-maintenance-probe"
        count=1
      fi
    done
    test "$count" = 1
    count=0
    for agent in target/*/release/velstra target/release/velstra; do
      if test -f "$agent" && test -x "$agent"; then
        test "$count" = 0
        cp "$agent" "$out/bin/velstra"
        count=1
      fi
    done
    test "$count" = 1
  '';
  postInstall = "";
  doCheck = false;
})
