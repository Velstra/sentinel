"""Real remote-default selector transport and confidentiality regression.

The topology boots with narrow selectors first. Expanding them is a genuine
product CLI transaction, not an nft/XFRM policy repair by the test driver.
"""
import json
import os
import shlex
from pathlib import Path

start_all()
fw.wait_for_unit("sentinel-boot-late.service")
fw.wait_for_unit("strongswan-swanctl.service")
peer.wait_for_unit("strongswan-swanctl.service")
peer.wait_for_unit("qa-target.service")
client.wait_for_unit("qa-client-target.service")
assert fw.succeed("readlink -f /run/current-system/sw/bin/sentinel").strip() == "__SENTINEL__"
fw.execute("swanctl --terminate --ike conn-qa-site --timeout 15")
peer.execute("swanctl --terminate --ike reference-peer --timeout 15")
before = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
before_shunts = fw.succeed("__NFT__ -s -nn list table inet sentinel_ipsec_shunt")
invalid = "\n".join([
    "set vpn ipsec qa-site local-subnet 0.0.0.0/0",
    "set vpn ipsec qa-site remote-subnet 0.0.0.0/0",
    "commit", "discard", "exit", "",
])
status, error = fw.execute("printf %s " + shlex.quote(invalid) + " | sentinel configure 2>&1")
assert status != 0 and "/0 on both sides" in error and "`vti`" in error, error
assert before == fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
assert before_shunts == fw.succeed("__NFT__ -s -nn list table inet sentinel_ipsec_shunt")
fw.succeed(
    "printf '%s\\n' "
    "'set protocols static 198.19.210.9/32 via 198.18.10.254' "
    "'set vpn ipsec qa-site local-subnet 198.18.0.0/16' "
    "'set vpn ipsec qa-site remote-subnet 0.0.0.0/0' "
    "commit save exit | sentinel configure"
)
# `route get` also runs XFRM lookup and may legitimately return unreachable
# before a full-selector SA exists. Inspect the actual FIB for this prerequisite.
fw.wait_until_succeeds("ip -4 route show exact 198.19.210.9/32 | grep -q 'via 198.18.10.254'", timeout=15)
peer.succeed(
    "systemd-run --unit=qa-fullselectors-wire --property=RuntimeMaxSec=90 "
    "__TCPDUMP__ --immediate-mode -U -ni eth1 -w /run/fullselectors.pcap "
    "'esp or udp port 500 or udp port 4500 or tcp port 9102'"
)
peer.wait_until_succeeds(
    "journalctl -u qa-fullselectors-wire --no-pager | grep -q 'listening on eth1'", timeout=5
)
status, initiation = fw.execute("swanctl --initiate --child qa-site --timeout 30 2>&1")
sa = fw.succeed("swanctl --list-sas")
installed = any(line.strip().startswith("qa-site:") and ", INSTALLED," in line for line in sa.splitlines())
if not installed:
    print("IPSEC_FULL_SELECTORS_TRANSPORT_FAILURE " + json.dumps({
        "initiate_exit": status,
        "initiate": initiation,
        "SAs_without_keys": sa,
        "shunts": fw.succeed("__NFT__ -j list table inet sentinel_ipsec_shunt"),
        "charon_log": fw.succeed("journalctl -u strongswan-swanctl.service -n 60 --no-pager"),
    }), flush=True)
assert installed, "full policy selectors must not block their own authenticated IKE transport"
url = "curl --fail --silent --show-error --max-time 8 http://198.19.210.9:9102/"
response_code, response_output = client.execute(url)
peer.succeed("systemctl kill --signal=SIGUSR2 qa-fullselectors-wire.service")
peer.succeed("systemctl stop qa-fullselectors-wire.service")
wire = peer.succeed("__TCPDUMP__ -nn -r /run/fullselectors.pcap 2>/dev/null")
esp = peer.succeed("__TCPDUMP__ -nn -r /run/fullselectors.pcap esp 2>/dev/null")
plain = peer.succeed(
    "__TCPDUMP__ -nn -r /run/fullselectors.pcap 'src host 198.18.10.100 and dst host 198.19.210.9 and tcp dst port 9102' 2>/dev/null"
)
if response_code:
    print("IPSEC_FULL_SELECTORS_PACKET_FAILURE " + json.dumps({
        "exit": response_code, "output": response_output, "independent_NIC_wire": wire,
        "fw_shunts": fw.succeed("__NFT__ -j list table inet sentinel_ipsec_shunt"),
        "fw_policies": fw.succeed("ip -s xfrm policy"),
        "peer_policies": peer.succeed("ip -s xfrm policy"),
        "fw_routes": fw.succeed("ip -4 route show table all"),
        "peer_routes": peer.succeed("ip -4 route show table all"),
        "peer_listener": peer.succeed("ss -lntp"),
        "peer_server_log": peer.succeed("journalctl -u qa-target.service --no-pager"),
    }), flush=True)
assert response_code == 0, "a full-selector CHILD must actually carry the protected request"
response = json.loads(response_output)
assert response["peer"] == "198.18.20.50", response
assert esp and not plain, (esp, plain)
fw.execute("swanctl --terminate --ike conn-qa-site --timeout 15")
peer.execute("swanctl --terminate --ike reference-peer --timeout 15")
fw.succeed(
    "printf '%s\\n' 'set vpn ipsec qa-site start-action none' "
    "'set vpn ipsec qa-site psk public-WRONG-ipsec-failclosed-fixture' "
    "commit save exit | sentinel configure"
)
refused, error = fw.execute("swanctl --initiate --child qa-site --timeout 30 2>&1")
assert refused != 0 and "AUTHENTICATION_FAILED" in error, error
for node in (fw, peer):
    # Emit no key/state contents. There must be no leftover SA covering the test.
    node.wait_until_succeeds("test -z \"$(ip xfrm state)\"", timeout=15)
peer.succeed(
    "systemd-run --unit=qa-fullselectors-no-sa --property=RuntimeMaxSec=40 "
    "__TCPDUMP__ --immediate-mode -U -ni eth1 -w /run/fullselectors-no-sa.pcap "
    "'udp port 500 or udp port 4500 or tcp port 9102'"
)
peer.wait_until_succeeds(
    "journalctl -u qa-fullselectors-no-sa --no-pager | grep -q 'listening on eth1'", timeout=5
)
udp = """import socket
for source in (500,4500):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.bind(('198.18.20.50',source))
        for destination in (500,4500):
            s.sendto(b'sentinel-qa-full-selectors-FORWARD-PLAINTEXT',('198.18.10.254',destination))
"""
client.succeed("__PYTHON__ -c " + shlex.quote(udp))
code, output = client.execute(url)
assert code != 0, "full-selector traffic must not fall back to plaintext without a CHILD SA"
fw.succeed("systemctl stop strongswan-swanctl.service")
unprivileged = """import errno,json,os,socket
assert os.getuid()!=0
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.bind(('198.18.10.100',4500))
    try:
        s.sendto(b'sentinel-qa-full-selectors-UNPRIVILEGED-PLAINTEXT',('198.18.10.254',4500))
    except OSError as e:
        assert e.errno in (errno.EPERM,errno.EACCES),e
        print(json.dumps({'uid':os.getuid(),'denied_errno':e.errno}))
    else:
        raise AssertionError('unprivileged IKE-port socket bypassed confidentiality shunts')
"""
uid_refusal = json.loads(fw.succeed("sudo -n -u nobody __PYTHON__ -c " + shlex.quote(unprivileged)))
peer.succeed("systemctl kill --signal=SIGUSR2 qa-fullselectors-no-sa.service")
peer.succeed("systemctl stop qa-fullselectors-no-sa.service")
unprotected = peer.succeed("__TCPDUMP__ -A -nn -r /run/fullselectors-no-sa.pcap 2>/dev/null")
no_sa_plain = peer.succeed("__TCPDUMP__ -nn -r /run/fullselectors-no-sa.pcap 'dst host 198.19.210.9 and tcp dst port 9102' 2>/dev/null")
assert not no_sa_plain, "without a kernel SA, every matching NIC frame would be plaintext"
assert "sentinel-qa-full-selectors-FORWARD-PLAINTEXT" not in unprotected
assert "sentinel-qa-full-selectors-UNPRIVILEGED-PLAINTEXT" not in unprotected
observation = {
    "full_remote_policy_selectors": "198.18.0.0/16 === 0.0.0.0/0",
    "both_default_policy_rejected_before_apply": True,
    "authenticated_response": response,
    "independent_NIC_capture": wire,
    "encrypted_wire_present": bool(esp),
    "client_request_not_SNATed_on_reference_NIC": not plain,
    "no_SA_protected_plaintext_absent": not no_sa_plain,
    "wrong_PSK_authentication_refused": True,
    "no_SA_request_exit": code,
    "no_SA_response": output,
    "forwarded_UDP_500_and_4500_not_exempted": True,
    "non_root_host_IKE_port_socket_refused": uid_refusal,
    "independent_no_SA_wire": unprotected,
}
Path(os.environ["out"], "ipsec-failclosed.json").write_text(json.dumps(observation, indent=2))
