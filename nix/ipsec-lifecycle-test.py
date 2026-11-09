"""Actual established-SA revocation and preservation, never a global SA flush."""
import json
import os
import re
import shlex
from pathlib import Path


def configure(lines):
    command = "printf %s " + shlex.quote("\n".join(lines + ["commit", "save", "exit"]) + "\n") + " | sentinel configure 2>&1"
    output = fw.succeed(command)
    assert "commit ok" in output and "error:" not in output.lower(), output


def sas(name):
    return fw.succeed("swanctl --list-sas --ike conn-" + name)


def ike_id(name):
    match = re.search(r"^conn-" + re.escape(name) + r": #(\d+),", sas(name), re.M)
    assert match is not None, "required owned IKE SA is absent"
    return match.group(1)


def counts():
    text = fw.succeed("ip xfrm state count")
    match = re.search(r"SAD count\s+(\d+)", text)
    assert match is not None, text
    return int(match.group(1))


def initiate(name):
    fw.succeed("swanctl --initiate --child " + name + " --timeout 30")
    fw.wait_until_succeeds("swanctl --list-sas --ike conn-" + name + " | grep -q INSTALLED", timeout=30)


def http(address, port):
    response = json.loads(client.succeed("curl --fail --silent --show-error --max-time 5 http://" + address + ":" + str(port) + "/"))
    assert response["peer"] == "198.18.20.50", response
    return response


start_all()
fw.wait_for_unit("sentinel-boot-late.service")
peer.wait_for_unit("strongswan-swanctl.service")
peer.wait_for_unit("qa-target.service")
peer.wait_for_unit("qa-keep-target.service")
assert fw.succeed("readlink -f /run/current-system/sw/bin/sentinel").strip() == "__SENTINEL__"
configure(["set vpn ipsec qa-site start-action none"] + ["set vpn ipsec qa-keep " + setting for setting in [
    "local 198.18.10.100", "remote 198.18.10.254", "local-subnet 198.18.20.0/24",
    "remote-subnet 198.19.211.0/24", "local-id fw-keep.example", "remote-id peer-keep.example",
    "psk public-ephemeral-IPsec-keep-fixture", "start-action none"]])
initiate("qa-site")
initiate("qa-keep")
assert counts() == 4
original = {name: ike_id(name) for name in ("qa-site", "qa-keep")}
observation = {"initial_IKE_ids": original, "actual_primary_HTTP": http("198.19.210.9", 9102),
               "actual_unchanged_tunnel_HTTP": http("198.19.211.9", 9105)}

with subtest("idempotent and unrelated commits preserve both established IKE identities"):
    configure(["set vpn ipsec qa-site start-action none"])
    assert {name: ike_id(name) for name in original} == original
    configure(["set protocols static 198.19.212.0/24 via 198.18.10.254"])
    assert {name: ike_id(name) for name in original} == original
    http("198.19.210.9", 9102)
    http("198.19.211.9", 9105)
    observation["unchanged_and_unrelated_commits_preserve_both_SAs"] = True

with subtest("changing an established connection key revokes old authentication without touching another tunnel"):
    configure(["set vpn ipsec qa-site psk public-WRONG-ipsec-failclosed-fixture"])
    assert not sas("qa-site").strip(), "old authenticated IKE SA survived a changed key"
    assert counts() == 2 and ike_id("qa-keep") == original["qa-keep"]
    code, error = fw.execute("swanctl --initiate --child qa-site --timeout 30 2>&1")
    assert code != 0 and "AUTHENTICATION_FAILED" in error, error
    assert not sas("qa-site").strip() and counts() == 2
    client.fail("curl --fail --silent --show-error --max-time 3 http://198.19.210.9:9102/")
    http("198.19.211.9", 9105)
    observation["changed_key_revoked_existing_authentication"] = True
    observation["wrong_key_fresh_authentication_refused"] = True

with subtest("normal correct-key recovery and active deletion keep the unrelated SA and traffic"):
    configure(["set vpn ipsec qa-site psk public-ephemeral-ipsec-failclosed-fixture"])
    initiate("qa-site")
    http("198.19.210.9", 9102)
    assert counts() == 4 and ike_id("qa-keep") == original["qa-keep"]
    configure(["delete vpn ipsec qa-site"])
    assert not sas("qa-site").strip() and counts() == 2, "removed tunnel retained kernel SAs"
    assert ike_id("qa-keep") == original["qa-keep"]
    assert "conn-qa-site" not in fw.succeed("swanctl --list-conns")
    http("198.19.211.9", 9105)
    observation["active_deletion_preserves_other_original_IKE_and_real_traffic"] = True

with subtest("deleting the final established responder leaves no loaded config or kernel SA"):
    configure(["delete vpn ipsec qa-keep"])
    assert counts() == 0 and not fw.succeed("swanctl --list-sas").strip()
    assert not fw.succeed("swanctl --list-conns").strip()
    fw.fail("test -e /run/sentinel/ipsec-guards.json")
    observation["last_established_tunnel_removed_without_global_SA_flush"] = True

Path(os.environ["out"], "ipsec-lifecycle.json").write_text(json.dumps(observation, indent=2))
