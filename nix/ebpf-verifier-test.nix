{ pkgs, self, kernelPackages, label }:
let
  packages = self.packages.x86_64-linux;
  programs = [
    "velstra_ha_exit" "velstra_ha_guard" "velstra" "velstra_main"
    "velstra_guest_delivery" "velstra_forward" "velstra_v4_state" "velstra_v6" "velstra_local"
    "velstra_v6_state" "velstra_egress" "velstra_egress_v4" "velstra_egress_v6"
    "velstra_egress_v6_state" "velstra_masquerade"
    "velstra_bum" "velstra_icmp_nat" "velstra_egress_icmp" "velstra_deferred_snat"
    "velstra_related" "velstra_related_egress" "velstra_related_egress_apply"
  ];
in pkgs.testers.runNixOSTest {
  name = "sentinel-ebpf-verifier-${label}";
  globalTimeout = 300;
  nodes.machine = {
    boot.kernelPackages = kernelPackages;
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ packages.velstra pkgs.coreutils ];
  };
  testScript = ''
    import json, os
    from pathlib import Path
    machine.start()
    machine.wait_for_unit("multi-user.target")
    status, verifier_output = machine.execute("velstra verify-ebpf ${packages.velstra-ebpf} 2>&1")
    expected = json.loads('${builtins.toJSON programs}')
    receipt = {
        "kernel": machine.succeed("uname -r").strip(),
        "object_sha256": machine.succeed("sha256sum ${packages.velstra-ebpf}").split()[0],
        "loader_path": "${packages.velstra}",
        "label": "${label}", "exit_code": status,
        "verified": [p for p in expected if "verified " + p + "\n" in verifier_output],
        "expected": expected, "verifier_output": verifier_output,
    }
    Path(os.environ["out"], "verifier.json").write_text(json.dumps(receipt, indent=2))
    # Print the receipt too: a rejected derivation must retain diagnostics via
    # nix log / CI artifacts, not depend on an unregistered failed $out.
    print("VERIFIER_RECEIPT=" + json.dumps(receipt))
    assert status == 0, verifier_output
    assert receipt["verified"] == expected, receipt
    assert "BTF couldn't be loaded" not in verifier_output, verifier_output
  '';
}
