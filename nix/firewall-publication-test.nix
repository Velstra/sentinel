{ pkgs, probe, object, kernelPackages ? pkgs.linuxPackages_6_12 }:
assert object.publicationFaultOnly or false;
assert toString probe.src == toString object.baselineSource;
pkgs.testers.runNixOSTest {
  name = "sentinel-instrumented-firewall-publication";
  globalTimeout = 300;
  nodes.machine = {
    boot.kernelPackages = kernelPackages;
    virtualisation = { memorySize = 2048; cores = 1; };
    environment.systemPackages = [ pkgs.coreutils ];
  };
  testScript = ''
    import json, os
    from pathlib import Path
    machine.start()
    machine.wait_for_unit("multi-user.target")
    # A fixed-output cache is keyed by bytes, not the requested source. Refuse
    # an old measured ELF before calling it the current instrumented candidate.
    machine.succeed("${pkgs.llvm}/bin/llvm-objcopy --dump-section .velstra.source-id=/run/instrumented-source-id ${object} /run/instrumented-inspected.o")
    assert machine.succeed("cat /run/instrumented-source-id") == "${object.instrumentedIdentity}"
    machine.succeed("${pkgs.llvm}/bin/llvm-objcopy --dump-section .velstra.source-id=/run/baseline-source-id ${object.baselineObject} /run/baseline-inspected.o")
    assert machine.succeed("cat /run/baseline-source-id") == "${object.originalIdentity}"
    status, output = machine.execute(
        "VELSTRA_FW_PUBLICATION_OBJECT=${object} "
        "VELSTRA_FW_PUBLICATION_RECEIPT=/run/firewall-publication.json "
        "${probe}/bin/firewall-publication-probe "
        "kernel_publication_failures --ignored --exact --nocapture 2>&1"
    )
    print(output)
    Path(os.environ["out"], "test-output.txt").write_text(output)
    receipt_status, raw = machine.execute("cat /run/firewall-publication.json")
    if receipt_status == 0:
        receipt = json.loads(raw)
        receipt["kernel"] = machine.succeed("uname -r").strip()
        receipt["baseline_object_sha256"] = machine.succeed("sha256sum ${object.baselineObject}").split()[0]
        receipt["baseline_source_identity"] = "${object.originalIdentity}"
        receipt["instrumented_source_identity"] = "${object.instrumentedIdentity}"
        receipt["baseline_main_sha256"] = "${object.baselineMainSha256}"
        receipt["transformation_sha256"] = "${object.patchSha256}"
        Path(os.environ["out"], "firewall-publication.json").write_text(json.dumps(receipt, indent=2))
        print("FIREWALL_PUBLICATION_RECEIPT=" + json.dumps(receipt))
    assert status == 0, output
    assert receipt_status == 0, raw
    assert receipt["instrumented_not_release_object"] is True, receipt
    assert len(receipt["cases"]) == 18, receipt
    expected = {
        (program, occupied, None)
        for program in ("velstra_main", "velstra_egress_v4", "velstra_masquerade", "velstra_egress_icmp")
        for occupied in (2, 3, 4)
    } | {
        (program, None, case)
        for program in ("velstra_main", "velstra_egress_v4")
        for case in ("untracked_ack_no_publication", "stateless_syn_no_publication", "bidirectional_handshake_updates_full_map")
    }
    observed = {(case["path"], case.get("occupied_before"), case.get("case")) for case in receipt["cases"]}
    assert observed == expected, (observed, expected)
    assert receipt["object_sha256"] == machine.succeed("sha256sum ${object}").split()[0], receipt
  '';
}
