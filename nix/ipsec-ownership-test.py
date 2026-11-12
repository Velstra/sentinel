"""Actual table ownership, configuration lifecycle and reboot recovery.

Adversarial mutations are deliberate negative controls in disposable VMs.
The driver never repairs an attacked product table: only a normal reboot
recreates volatile kernel/runtime state from the saved configuration.
"""
import hashlib
import json
import os
import shlex
from pathlib import Path

NFT = "__NFT__"
TABLE = "inet sentinel_ipsec_shunt"
REFUSAL_EXIT_CODES = []


def table(name=TABLE):
    return fw.succeed(NFT + " -s -nn list table " + name)


def saved_hash():
    return fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]


def configure(lines, refused=False):
    suffix = ["commit", "exit"] if refused else ["commit", "save", "exit"]
    payload = "\n".join(lines + suffix) + "\n"
    status, output = fw.execute("printf %s " + shlex.quote(payload) + " | sentinel configure 2>&1")
    if refused:
        assert status != 0 and "refusing mutation" in output and "commit ok" not in output, (status, output)
        REFUSAL_EXIT_CODES.append(status)
    else:
        assert status == 0 and "commit ok" in output and "error:" not in output.lower(), output
    return output


def add(name, subnet="198.19.210.0/24"):
    return ["set vpn ipsec " + name + " " + option for option in (
        "local 198.18.10.100", "remote 198.18.10.254",
        "local-subnet 198.18.20.0/24", "remote-subnet " + subnet,
        "psk public-ephemeral-ipsec-failclosed-fixture", "start-action none")]


def ready():
    fw.wait_for_unit("sentinel-boot-late.service")
    fw.wait_for_unit("strongswan-swanctl.service")
    assert fw.succeed("readlink -f /run/current-system/sw/bin/sentinel").strip() == "__SENTINEL__"


# The pinned driver otherwise starts QEMU with -no-reboot. `reboot()` is an
# asynchronous Ctrl+Alt+Delete, not an implicit restart of an exited QEMU.
fw.start(allow_reboot=True)
start_all()
ready()
fw.succeed(NFT + " add table inet qa_independent_shunt_owner")
independent = table("inet qa_independent_shunt_owner")
initial = table()
for _ in range(2):
    configure(["set vpn ipsec qa-site psk public-ephemeral-ipsec-failclosed-fixture"])
    assert table() == initial, "idempotent commit changed the stateless shunts"
configure(add("qa-second", "198.19.211.0/24"))
assert len(json.loads(fw.succeed("cat /run/sentinel/ipsec-guards.json"))["guards"]) == 6
assert table().count("counter drop") == 8
configure(["set vpn ipsec qa-second remote-subnet 198.19.212.0/24"])
assert "198.19.211.0/24" not in table() and "198.19.212.0/24" in table()
assert len(json.loads(fw.succeed("cat /run/sentinel/ipsec-guards.json"))["guards"]) == 6
configure(["delete vpn ipsec qa-second"])
assert table() == initial
configure(["delete vpn ipsec qa-site"])
fw.fail(NFT + " list table " + TABLE)
fw.fail("test -e /run/sentinel/ipsec-guards.json")
fw.fail("test -e /run/sentinel/ipsec-routes")
assert table("inet qa_independent_shunt_owner") == independent

# A coincidentally named table without the product journal must not be adopted
# or deleted, even when configuration would otherwise create product guards.
fw.succeed(NFT + " add table " + TABLE)
foreign = table()
before = saved_hash()
configure(add("qa-site"), refused=True)
assert saved_hash() == before and table() == foreign
fw.fail("test -e /run/sentinel/ipsec-guards.json")
assert table("inet qa_independent_shunt_owner") == independent
fw.reboot()
ready()
fw.fail(NFT + " list table " + TABLE)
configure(add("qa-site"))
owned = table()
before = saved_hash()

# A harmless counter-only foreign edit still invalidates complete ownership.
# No injected ACCEPT rule weakens confidentiality during this negative control.
fw.succeed(NFT + " add rule " + TABLE + " input counter")
tampered = table()
assert tampered != owned
configure(["set vpn ipsec qa-site start-action none"], refused=True)
assert saved_hash() == before and table() == tampered
fw.reboot()
ready()
assert table() == owned
state = json.loads(fw.succeed("cat /run/sentinel/ipsec-guards.json"))
assert len(state["guards"]) == 3 and state["snapshot"]
observation = {
    "idempotent_commits": 2,
    "add_change_remove_selectors": True,
    "independent_table_preserved_until_normal_reboot": True,
    "foreign_unjournalled_table_refused_without_mutation": True,
    "tampered_owned_table_refused_without_mutation": True,
    "no_failed_commit_saved": True,
    "recovery_only_through_normal_reboot": True,
    "recreated_stateless_table_SHA256": hashlib.sha256(owned.encode()).hexdigest(),
    "actual_journal_schema": state["schema"],
    "actual_refused_CLI_exit_codes": REFUSAL_EXIT_CODES,
}
Path(os.environ["out"], "ipsec-failclosed.json").write_text(json.dumps(observation, indent=2))
