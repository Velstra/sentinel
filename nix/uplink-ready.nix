# The import block for nix/uplink-ready.py, for a VM check's testScript. Put
# `''${import ./uplink-ready.nix { inherit pkgs; }}` on a line of its own at the
# script's base indentation; it binds `uplink_ready`.
{ pkgs }:
''
  import importlib.util as uplink_util
  uplink_spec = uplink_util.spec_from_file_location("uplink_ready", "${./uplink-ready.py}")
  assert uplink_spec is not None and uplink_spec.loader is not None
  uplink_ready = uplink_util.module_from_spec(uplink_spec)
  uplink_spec.loader.exec_module(uplink_ready)
  uplink_ready.use_bpftool("${pkgs.bpftools}/bin/bpftool")
''
