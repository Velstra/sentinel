"""Readiness for VM checks that send traffic through masquerade.

The agent brings a zoned uplink up only after its hooks are attached; networkd
then configures the address, and the agent learns it on its next host-inventory
poll (up to about 2 s). Until then the uplink's MASQUERADE entry is unaddressed
and DP-04 refuses every packet that needs translating, so nothing leaks and
nothing is delivered either. The kernel showing the address (`ip addr`) is not
enough: the data plane may not hold it yet.

A check imports this module and calls `wait_uplink_addressed` before the first
masqueraded packet. An uplink with a fixed `to` address does not depend on the
poll, and waiting for it is harmless.
"""

import json
import time

BPFTOOL = "bpftool"


def use_bpftool(path):
    """The bpftool to run inside the VM (a store path in the check)."""
    global BPFTOOL
    BPFTOOL = path


def _bytes(raw):
    if not isinstance(raw, list):
        return None
    return [int(b, 0) if isinstance(b, str) else int(b) for b in raw]


def masquerade_entries(machine):
    """The MASQUERADE map as {ifindex: [a, b, c, d]}."""
    entries = json.loads(machine.succeed(BPFTOOL + " -j map dump name MASQUERADE"))
    table = {}
    for entry in entries:
        key, value = _bytes(entry.get("key")), _bytes(entry.get("value"))
        if key is None or value is None or len(key) != 4:
            continue
        table[int.from_bytes(bytes(key), "little")] = value
    return table


def wait_uplink_addressed(machine, interface, address, timeout=30.0):
    """Block until the data plane masquerades `interface` from `address`."""
    want = [int(part) for part in address.split(".")]
    ifindex = int(machine.succeed("cat /sys/class/net/" + interface + "/ifindex").strip())
    deadline = time.monotonic() + timeout
    while True:
        table = masquerade_entries(machine)
        if table.get(ifindex) == want:
            return
        if time.monotonic() > deadline:
            raise AssertionError(
                interface + " (ifindex " + str(ifindex) + ") is not masqueraded from "
                + address + " after " + str(timeout) + " s: MASQUERADE holds " + repr(table))
        time.sleep(0.25)
