# Storage contract only. Never install this harness as the appliance agent.
# The unchanged base object is checked by base.postPatch and is not attached.
{ pkgs, base, modelSource, libSource, testSource }:
base.overrideAttrs (old: {
  pname = "firewall-session-contract-probe";
  nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ pkgs.jq ];
  postPatch = (old.postPatch or "") + ''
    cp ${modelSource} velstra-common/src/firewall_session.rs
    cp ${libSource} velstra-common/src/lib.rs
    mkdir -p velstra-app/tests
    cp ${testSource} velstra-app/tests/firewall_session.rs
  '';
  buildPhase = ''
    runHook preBuild
    cargo test --release --locked --offline --ignore-rust-version -p velstra-common
    cargo test --release --locked --offline --ignore-rust-version -p velstra --test firewall_session --no-run --message-format=json-render-diagnostics > probe.json
    cargo clippy --release --locked --offline --ignore-rust-version -p velstra-common --all-targets -- -D warnings
    cargo clippy --release --locked --offline --ignore-rust-version -p velstra --test firewall_session -- -D warnings
    runHook postBuild
  '';
  installPhase = ''
    mkdir -p "$out/bin"
    mapfile -t tests < <(jq -r 'select(.reason == "compiler-artifact" and .profile.test and .target.name == "firewall_session" and .executable != null) | .executable' probe.json)
    test "''${#tests[@]}" = 1
    cp "''${tests[0]}" "$out/bin/firewall-session-probe"
  '';
  postInstall = "";
  doCheck = false;
})
