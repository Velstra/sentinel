# Real tiny-HASH kernel operations; deliberately not a live-traffic or HA gate.
{ pkgs, probe, object }:
assert object.publicationFaultOnly or false;
pkgs.testers.runNixOSTest {
  name = "sentinel-expiry-maintenance-kernel";
  globalTimeout = 300;
  nodes.machine = {
    boot.kernelPackages = pkgs.linuxPackages_6_12;
    virtualisation = { memorySize = 2048; cores = 1; };
    environment.systemPackages = [ pkgs.iproute2 ];
  };
  testScript = ''
    import json, os
    from pathlib import Path
    machine.start()
    machine.wait_for_unit("multi-user.target")
    status, output = machine.execute("${probe}/bin/velstra-unit-tests --nocapture 2>&1")
    print(output)
    Path(os.environ["out"], "agent-unit-tests.txt").write_text(output)
    assert status == 0, output
    status, output = machine.execute("${probe}/bin/expiry-maintenance-probe --nocapture 2>&1")
    print(output)
    Path(os.environ["out"], "maintenance-unit-tests.txt").write_text(output)
    assert status == 0, output
    status, output = machine.execute(
        "VELSTRA_EXPIRY_OBJECT=${object} "
        "VELSTRA_EXPIRY_RECEIPT=/run/expiry.json "
        "${probe}/bin/expiry-maintenance-probe kernel_expiry_maintenance --ignored --exact --nocapture 2>&1"
    )
    print(output)
    Path(os.environ["out"], "test-output.txt").write_text(output)
    receipt_status, raw = machine.execute("cat /run/expiry.json")
    if receipt_status == 0:
        receipt = json.loads(raw)
        receipt["kernel"] = machine.succeed("uname -r").strip()
        receipt["object_sha256"] = machine.succeed("sha256sum ${object}").split()[0]
        Path(os.environ["out"], "expiry.json").write_text(json.dumps(receipt, indent=2))
    assert status == 0, output
    assert receipt_status == 0, raw
    assert len(receipt["cycles"]) == 16, receipt
    assert receipt["map_type"] == "HASH" and receipt["map_capacity"] == 4
    for row in receipt["cycles"]:
        assert row["full"]["removed"] == 0
        assert row["reclaimed"]["removed"] == 1
        assert row["limited"]["examined"] == 1
        assert not row["limited"]["scan_complete"]
  '';
}
