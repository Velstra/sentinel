{ pkgs, kernelPackages ? pkgs.linuxPackages_6_12, label ? "6-12" }:
let
  attach = pkgs.rustPlatform.buildRustPackage {
    pname = "fragment-tcx-attach-fixture";
    version = "0.0.0";
    src = pkgs.lib.cleanSource ./fragment-tcx-attach;
    cargoLock = {
      lockFile = ./fragment-tcx-attach/Cargo.lock;
      outputHashes."aya-0.13.2" = "sha256-Py7WDRIjy9p6ntTdnjhahkClKI3wIJRNwwqnONFX7Kk=";
    };
    doCheck = true;
  };
  fixture = pkgs.runCommand "fragment-reassembly-tcx-bpf-fixture" {
    nativeBuildInputs = [ pkgs.llvmPackages.clang-unwrapped ];
  } ''
    clang -target bpf -O2 -g -Wall -Werror \
      -I${pkgs.linuxHeaders}/include -I${pkgs.libbpf}/include \
      -include ${./fragment-reassembly-combined-fixture.c} \
      -c ${./fragment-reassembly-tcx-fixture.c} -o "$out"
  '';
in pkgs.testers.runNixOSTest {
  name = "kernel-fragment-tcx-order-primitive-${label}";
  globalTimeout = 300;
  nodes.machine = {
    boot.kernelPackages = kernelPackages;
    boot.kernelModules = [
      "act_ct" "act_mirred" "cls_bpf" "cls_matchall" "cls_flower"
      "dummy" "nf_conntrack" "nf_defrag_ipv4" "sch_fq_codel"
    ];
    networking.firewall.enable = false;
    networking.dhcpcd.denyInterfaces = [
      "r-lan" "r-wan" "r-other" "frag-stage" "frag-stage2" "c0" "c-other" "s0"
    ];
    virtualisation.memorySize = 1024;
    environment.systemPackages = [
      pkgs.iproute2 pkgs.bpftools pkgs.conntrack-tools pkgs.python3
      pkgs.coreutils pkgs.procps attach
    ];
  };
  testScript = ''
    import json, os
    from pathlib import Path
    machine.start()
    machine.wait_for_unit("multi-user.target")
    code, output = machine.execute(
        "${pkgs.python3}/bin/python3 -B ${./fragment-reassembly-tcx-probe.py} "
        "--base-probe ${./fragment-reassembly-probe.py} "
        "--combined-probe ${./fragment-reassembly-combined-probe.py} "
        "--attach ${attach}/bin/fragment-tcx-attach --object ${fixture} "
        "--label ${label} --output /tmp/fragment-tcx.json 2>&1"
    )
    print(output)
    status, receipt = machine.execute("cat /tmp/fragment-tcx.json")
    if status == 0:
        Path(os.environ["out"], "fragment-tcx.json").write_text(receipt)
        print("FRAGMENT_TCX_RECEIPT=" + json.dumps(json.loads(receipt)))
    assert code == 0, output
    assert status == 0, receipt
  '';
}
