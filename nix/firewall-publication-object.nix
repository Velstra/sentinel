# Fault-injection object ONLY. Never use this derivation for an appliance.
# Actual packet writers are unchanged; an ordinary four-entry map makes their
# first/second update failure deterministic instead of evicting an old entry.
{ pkgs, base, outputHash }:
let
  oldLine = "static FW_FLOWS: LruHashMap<FirewallKey, FirewallState> = LruHashMap::with_max_entries(65536, 0);";
  newLine = "static FW_FLOWS: HashMap<FirewallKey, FirewallState> = HashMap::with_max_entries(4, 0);";
  source = pkgs.runCommand "fabric-firewall-publication-hash4-source" {} ''
    mkdir "$out"
    cp -R ${base.src}/. "$out/"
    chmod u+w "$out/velstra-ebpf/src/main.rs"
    test "$(grep -Fxc ${pkgs.lib.escapeShellArg oldLine} "$out/velstra-ebpf/src/main.rs")" = 1
    substituteInPlace "$out/velstra-ebpf/src/main.rs" \
      --replace-fail ${pkgs.lib.escapeShellArg oldLine} ${pkgs.lib.escapeShellArg newLine}
  '';
  originalIdentity = builtins.hashString "sha256" (toString base.src);
  instrumentedIdentity = builtins.hashString "sha256" (toString source);
in base.overrideAttrs (old:
assert pkgs.lib.hasInfix originalIdentity old.buildPhase;
{
  pname = "firewall-publication-fault-object";
  src = source;
  inherit outputHash;
  buildPhase = pkgs.lib.replaceStrings [ originalIdentity ] [ instrumentedIdentity ] old.buildPhase;
  passthru = (old.passthru or {}) // {
    publicationFaultOnly = true;
    baselineObject = base;
    baselineSource = base.src;
    baselineMainSha256 = builtins.hashFile "sha256" (base.src + "/velstra-ebpf/src/main.rs");
    inherit originalIdentity instrumentedIdentity;
    patchSha256 = builtins.hashString "sha256" (oldLine + "\n" + newLine);
  };
})
