# Keep evaluated NixOS module graphs out of long-lived flake check values.
# This changes evaluation lifetime only: hydraJob preserves the actual test
# derivation. Interactive/debugging and extension APIs reconstruct the same test
# on demand instead of retaining every evaluated node in the aggregate output.
_final: previous:
let
  inherit (previous) lib;
  compact = make:
    let
      essential = lib.hydraJob (make null);
      names = builtins.filter (name: !(builtins.hasAttr name essential))
        (builtins.attrNames (make null));
      result = essential // lib.genAttrs names (name:
        if name == "test" then result
        else if builtins.elem name [ "extend" "extendNixOS" "overrideTestDerivation" ] then
          argument: compact (_: (make null).${name} argument)
        else (make null).${name});
    # Do not leave the attribute-name list retaining the source test thunk.
    in builtins.deepSeq names result;
in {
  testers = previous.testers // {
    runNixOSTest = specification:
      compact (_: previous.testers.runNixOSTest specification);
  };
}
