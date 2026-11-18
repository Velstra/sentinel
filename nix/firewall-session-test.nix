# Does not replace the existing full stateful NAT traffic gate.
{ pkgs, probe, kernelPackages ? pkgs.linuxPackages_6_12, label ? "6_12" }:
pkgs.testers.runNixOSTest {
  name = "sentinel-firewall-session-storage-${label}";
  globalTimeout = 300;
  nodes.machine = {
    boot.kernelPackages = kernelPackages;
    virtualisation = { memorySize = 2048; cores = 4; };
  };
  testScript = ''
    import json, os
    from pathlib import Path
    machine.start()
    machine.wait_for_unit("multi-user.target")
    status, output = machine.execute(
        "VELSTRA_SESSION_RECEIPT=/run/session.json "
        "${probe}/bin/firewall-session-probe kernel_session_storage --ignored --exact --nocapture 2>&1"
    )
    print(output)
    Path(os.environ["out"], "test-output.txt").write_text(output)
    receipt_status, raw = machine.execute("cat /run/session.json")
    if receipt_status == 0:
        receipt = json.loads(raw)
        receipt["kernel"] = machine.succeed("uname -r").strip()
        receipt["probe_sha256"] = machine.succeed("sha256sum ${probe}/bin/firewall-session-probe").split()[0]
        Path(os.environ["out"], "session.json").write_text(json.dumps(receipt, indent=2))
    assert status == 0, output
    assert receipt_status == 0, raw
    capacity = receipt["capacity"]
    assert capacity["map_type"] == "HASH" and capacity["capacity"] == 65536
    assert [row["logical_flows"] for row in capacity["phases"]] == [1, 64, 12000, 15000, 16000, 17000, 20000, 32768]
    for row in capacity["phases"]:
        assert row["all_values_retained"]
        assert row["physical_records"] == row["logical_flows"] * 2
        assert row["directional_rows_verified"] == row["logical_flows"] * 4
    assert capacity["overflow_refused"] and capacity["existing_update_at_capacity"]
    assert capacity["noexist_preserved_owner"]
    assert receipt["claims"]["exactly_one_winner_per_key"]
    assert sum(receipt["claims"]["wins"]) == 2048
    assert receipt["claims"]["synchronized_claim_rounds"] == 2048
    assert receipt["whole_value"]["torn_observations"] == 0
    assert receipt["whole_value"]["reads"] >= 20000
    assert all(count > 0 for count in receipt["whole_value"]["version_reads"])
    assert receipt["whole_value"]["reads_while_writer_active"] > 0
  '';
}
