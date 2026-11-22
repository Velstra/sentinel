# nixpkgs' replaceDirectDependencies (pkgs/build-support/
# replace-direct-dependencies.nix at the pin), rewriting store HASHES instead
# of whole base names. system.replaceDependencies calls it for every path it
# rewrites, through the overlay in flake.nix.
#
# The upstream rewrite replaces "<hash>-<name>" as one string. A compiler
# that expands a constant path into overlapping vector stores leaves the
# hash in .rodata followed by other bytes: GLib's _g_locale_get_charset_aliases
# builds "<glib>/lib/charset.alias" from 16-byte chunks, and the chunk
# "<hash>-glib-glib-2.88.3/lib" is not matched. The rewritten GLib then still
# refers to the original GLib, which keeps the replaced glibc in the closure
# (checks.image-security-floor caught it), and at run time it would compute
# the path of the original. A store hash is 32 base-32 characters and names
# exactly one path, which is also how Nix itself rewrites self-references,
# so rewriting the hash alone is exact.
#
# Everything else is upstream's. The overlay marks the package set with
# `replaceDirectDependencies.rewritesStoreHashes`, and security-backports.nix
# refuses to evaluate without it.
{
  lib,
  runCommandLocal,
  nix,
}:
{
  drv,
  replacements ? [ ],
}:
let
  inherit (lib)
    isStringLike
    substring
    stringLength
    optionalString
    escapeShellArgs
    concatMap
    ;

  isNonCaStorePath =
    x:
    if isStringLike x then
      let
        str = toString x;
      in
      builtins.substring 0 1 str == "/" && (dirOf str == builtins.storeDir)
    else
      false;
in
if replacements == [ ] then
  drv
else
  let
    drvName =
      if isNonCaStorePath drv then
        substring 33 (stringLength (baseNameOf drv)) (baseNameOf drv)
      else if drv ? drvAttrs.name then
        drv.drvAttrs.name
        + (
          let
            outputName = drv.outputName or "out";
          in
          optionalString (outputName != "out") "-${outputName}"
        )
      else
        throw "cannot reconstruct the derivation name from ${drv}";
  in
  runCommandLocal drvName { nativeBuildInputs = [ nix.out ]; } ''
    createRewriteScript() {
        while [ $# -ne 0 ]; do
            oldBasename="$(basename "$1")"
            newBasename="$(basename "$2")"
            shift 2
            if [ ''${#oldBasename} -ne ''${#newBasename} ]; then
                echo "cannot rewrite $oldBasename to $newBasename: length does not match" >&2
                exit 1
            fi
            echo "s|''${oldBasename:0:32}|''${newBasename:0:32}|g" >> rewrite.sed
        done
    }
    createRewriteScript ${
      escapeShellArgs (
        [
          drv
          (placeholder "out")
        ]
        ++ concatMap (
          { oldDependency, newDependency }:
          [
            oldDependency
            newDependency
          ]
        ) replacements
      )
    }
    nix-store --dump ${drv} | sed -f rewrite.sed | nix-store --restore $out
  ''
