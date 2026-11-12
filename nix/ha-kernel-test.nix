{ pkgs, velstra-ha-tests }:
pkgs.testers.runNixOSTest {
  name = "sentinel-ha-kernel";
  nodes.machine = {
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ velstra-ha-tests ];
  };
  testScript = ''
    import re
    start_all()
    machine.wait_for_unit("multi-user.target")
    prefix = "conntrack_sync::secure::tests::"
    expected = {
        prefix + name for name in [
            "kernel_batches_replication_deletion_and_local_ownership",
            "kernel_synproxy_snapshot_splice_deletion_and_local_ownership",
            "kernel_ha_successor_replaces_former_master_locals_without_resetting_counters",
            "kernel_snapshot_keeps_flows_refreshed_during_batch_dumps",
            "kernel_ha_owner_reexports_unchanged_imported_splices_in_every_snapshot",
            "kernel_ha_preserves_node_local_control_connections_while_replacing_data",
            "kernel_authenticated_transport_applies_deltas_and_fences_policy_changes",
        ]
    }
    listing = machine.succeed("velstra-ha-tests --list --ignored conntrack_sync::secure::tests::kernel_")
    listed = re.findall(r"^([^\r\n]+): test$", listing, re.MULTILINE)
    assert len(listed) == len(expected) and set(listed) == expected, listing
    output = machine.succeed("velstra-ha-tests --ignored conntrack_sync::secure::tests::kernel_ --nocapture")
    machine.log(output)
    passed = re.findall(r"^test ([^\r\n]+) \.\.\. ok$", output, re.MULTILINE)
    assert len(passed) == len(expected) and set(passed) == expected, output
    assert re.search(r"test result: ok\. 7 passed; 0 failed; 0 ignored;", output), output
  '';
}
