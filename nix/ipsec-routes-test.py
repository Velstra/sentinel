"""Real same-prefix static/IPsec coexistence, removal and foreign ownership."""
import json
import os
import shlex
from pathlib import Path

REFUSAL_EXIT_CODES = []


def routes():
    return json.loads(fw.succeed("ip -j -4 route show table main exact 198.19.210.0/24"))


def configure(lines, refuse=False):
    tail = ["commit", "exit"] if refuse else ["commit", "save", "exit"]
    status, output = fw.execute("printf %s " + shlex.quote("\n".join(lines + tail) + "\n") + " | sentinel configure 2>&1")
    if refuse:
        assert status != 0 and "refusing replacement" in output and "commit ok" not in output, (status, output)
        REFUSAL_EXIT_CODES.append(status)
    else:
        assert status == 0 and "commit ok" in output and "error:" not in output.lower(), output
    return output


def primary():
    return ["set vpn ipsec qa-site " + item for item in (
        "local 198.18.10.100", "remote 198.18.10.254",
        "local-subnet 198.18.20.0/24", "remote-subnet 198.19.210.0/24",
        "psk public-ephemeral-ipsec-failclosed-fixture", "start-action none")]


def static_route(rows):
    return [r for r in rows if r.get("protocol") in (4, "static") and r.get("metric", 0) == 0]


start_all()
fw.wait_for_unit("sentinel-boot-late.service")
peer.wait_for_unit("qa-target.service")
assert fw.succeed("readlink -f /run/current-system/sw/bin/sentinel").strip() == "__SENTINEL__"
configure(["set protocols static 198.19.210.0/24 via 198.18.10.254"])
coexisting = routes()
print("IPSEC_STATIC_ROUTE_COEXISTENCE " + json.dumps(coexisting), flush=True)
operator = static_route(coexisting)
assert len(operator) == 1, "IPsec route reconciliation overwrote the operator's same-prefix static route"
auxiliary = [r for r in coexisting if r.get("protocol") in (201, "201") and r.get("metric") == 42760]
assert len(auxiliary) == 1 and auxiliary[0]["prefsrc"] == "198.18.20.1", coexisting
configure(["delete vpn ipsec qa-site"])
after_removal = routes()
assert static_route(after_removal) == operator and len(after_removal) == 1, after_removal
actual = json.loads(fw.succeed("curl --fail --silent --show-error --max-time 5 --interface 198.18.10.100 http://198.19.210.9:9102/"))
assert actual["peer"] == "198.18.10.100", actual
configure(primary())
assert static_route(routes()) == operator
configure(["delete vpn ipsec qa-site"])

# An independently owned route deliberately occupying the private metric must
# be refused, not overwritten, even if it shares the same gateway and prefix.
fw.succeed("ip route add 198.19.210.0/24 via 198.18.10.254 proto static metric 42760")
foreign = routes()
saved = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
configure(primary(), refuse=True)
assert routes() == foreign
assert fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == saved
fw.fail("test -e /run/sentinel/ipsec-guards.json")
observation = {
    "real_Wren_static_and_IPsec_coexistence": coexisting,
    "operator_static_preserved_on_IPsec_removal": after_removal,
    "real_static_routed_HTTP_after_explicit_tunnel_removal": actual,
    "repeated_remove_and_readd_preserves_operator_route": True,
    "foreign_reserved_metric_refused_without_overwrite": True,
    "refused_commit_not_saved": True,
    "normal_failure_rollback_removes_new_shunts": True,
    "actual_refused_CLI_exit_codes": REFUSAL_EXIT_CODES,
}
Path(os.environ["out"], "ipsec-failclosed.json").write_text(json.dumps(observation, indent=2))
