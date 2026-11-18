# Build the existing agent's separate privileged integration-test executable.
# Normal agent source/object stamp validation is retained. This harness loads
# only the explicitly supplied instrumented ELF; it never attaches to a NIC.
{ pkgs, base, testSource }:
base.overrideAttrs (old: {
  pname = "firewall-publication-kernel-probe";
  postPatch = (old.postPatch or "") + ''
    mkdir -p velstra-app/tests
    cp ${testSource} velstra-app/tests/firewall_publication.rs
  '';
  buildPhase = ''
    runHook preBuild
    cargo test --release --locked --offline --ignore-rust-version \
      -p velstra --test firewall_publication --no-run
    runHook postBuild
  '';
  installPhase = ''
    mkdir -p "$out/bin"
    # Cargo emits an executable plus a non-executable .d dependency file.
    found=0
    for probe in target/*/release/deps/firewall_publication-* target/release/deps/firewall_publication-*; do
      if test -f "$probe" && test -x "$probe"; then
        test "$found" = 0
        cp "$probe" "$out/bin/firewall-publication-probe"
        found=1
      fi
    done
    test "$found" = 1
  '';
  postInstall = "";
  doCheck = false;
})
