"""Identical native-socket traffic for Sentinel and a netfilter oracle.

No Sentinel modules or packet parser are imported. Run on isolated test hosts,
never against an operator's production network. Stdlib only.
"""

import argparse
import asyncio
import errno
import hashlib
import json
import socket
import struct
import subprocess

TIMEOUT = 3
TCP_PORT = 18080
UDP_PORT = 18081


def payload(size):
    return (bytes(range(256)) * ((size + 255) // 256))[:size]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def metadata(data, peer):
    return {"bytes": len(data), "sha256": digest(data), "peer": peer}


async def tcp_peer(reader, writer):
    try:
        size = struct.unpack("!I", await reader.readexactly(4))[0]
        if size > 8 * 1024 * 1024:
            return
        data = await asyncio.wait_for(reader.readexactly(size), 10)
        meta = json.dumps(metadata(data, writer.get_extra_info("peername")[0])).encode()
        writer.write(struct.pack("!I", len(meta)) + meta + data)
        await writer.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


class UdpPeer(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(json.dumps(metadata(data, addr[0])).encode(), addr)


async def serve(addresses):
    loop = asyncio.get_running_loop()
    servers, transports = [], []
    for address in addresses:
        servers.append(await asyncio.start_server(tcp_peer, address, TCP_PORT))
        transport, _ = await loop.create_datagram_endpoint(UdpPeer, local_addr=(address, UDP_PORT))
        transports.append(transport)
    await asyncio.Event().wait()


def family(address):
    return socket.AF_INET6 if ":" in address else socket.AF_INET


def read_exact(connection, size):
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise ConnectionError("truncated echo")
        data.extend(part)
    return bytes(data)


def tcp(address, port, size=1024):
    data = payload(size)
    with socket.socket(family(address), socket.SOCK_STREAM) as connection:
        connection.settimeout(TIMEOUT)
        connection.connect((address, port))
        connection.sendall(struct.pack("!I", size) + data)
        count = struct.unpack("!I", read_exact(connection, 4))[0]
        if count > 4096:
            raise ValueError("oversized peer metadata")
        observed = json.loads(read_exact(connection, count))
        echoed = read_exact(connection, size)
        observed["echo_sha256"] = digest(echoed)
        return observed


def udp(address, port, size):
    with socket.socket(family(address), socket.SOCK_DGRAM) as connection:
        connection.settimeout(TIMEOUT)
        connection.connect((address, port))
        connection.send(payload(size))
        return json.loads(connection.recv(4096))


def pmtu():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(TIMEOUT)
        # Linux IP_MTU_DISCOVER=10, IP_PMTUDISC_DO=2, IP_RECVERR=11.
        connection.setsockopt(socket.IPPROTO_IP, 10, 2)
        connection.setsockopt(socket.IPPROTO_IP, 11, 1)
        connection.connect(("198.18.10.254", UDP_PORT))
        try:
            connection.send(payload(1400))
            connection.recv(4096)
        except OSError as error:
            if error.errno == errno.EMSGSIZE:
                return {"error": "message-too-large", "mtu": connection.getsockopt(socket.IPPROTO_IP, 14)}
            raise
        return {"error": "missing-pmtu-error"}


PMTU6_CLIENT_PORT = 18300
PMTU6_SERVER = "2001:db8:10::fe"


def pmtu6_client(result_path, ready_path, wait=10.0):
    """Hold a connected UDP flow open, then report the path MTU the kernel learnt.

    The flow is real traffic (one echoed datagram), so both firewalls track it
    before a Packet Too Big quoting it is injected from the WAN side. The PMTU is
    only updated for a live socket, so this stays connected until it sees the
    change or gives up.
    """
    import os
    import time
    def signal_ready():
        with open(ready_path, "w") as ready:
            ready.write("ready\n")

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as connection:
        connection.settimeout(TIMEOUT)
        try:
            connection.bind(("2001:db8:20::50", PMTU6_CLIENT_PORT))
            connection.connect((PMTU6_SERVER, UDP_PORT))
            connection.send(payload(64))
            connection.recv(4096)
        except OSError as error:
            # No tracked flow, so no PMTU case to run: report it as the case's
            # result instead of leaving the harness waiting.
            observed = error_result(error)
            signal_ready()
        else:
            signal_ready()
            deadline = time.monotonic() + wait
            mtu = connection.getsockopt(socket.IPPROTO_IPV6, 24)  # IPV6_MTU
            while mtu != 1280 and time.monotonic() < deadline:
                time.sleep(0.1)
                mtu = connection.getsockopt(socket.IPPROTO_IPV6, 24)
            observed = {"mtu": mtu}
    tmp = result_path + ".tmp"
    with open(tmp, "w") as result:
        json.dump(observed, result)
    os.rename(tmp, result_path)


def ptb6(client, client_port, server, server_port, mtu):
    """Send a Packet Too Big to `client`, quoting its UDP datagram to `server`.

    The WAN-side host plays the narrower router a real path would have. The
    kernel fills in the ICMPv6 checksum of a raw ICMPv6 socket.
    """
    datagram = struct.pack("!HHHH", client_port, server_port, 8 + 1352, 0) + payload(1352)
    quoted = struct.pack("!IHBB", 0x60000000, len(datagram), 17, 64)
    quoted += socket.inet_pton(socket.AF_INET6, client) + socket.inet_pton(socket.AF_INET6, server)
    message = struct.pack("!BBHI", 2, 0, 0, mtu) + (quoted + datagram)[:1280 - 48]
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as raw:
        raw.sendto(message, (client, 0))


def pmtu6_result(result_path="/tmp/pmtu6.json"):
    with open(result_path) as result:
        return json.load(result)


def ping(address, size):
    result = subprocess.run(
        ["ping", "-n", "-c", "1", "-W", "2", "-s", str(size), address],
        text=True, capture_output=True, timeout=5, check=False,
    )
    return {"delivered": result.returncode == 0}


def error_result(error):
    if isinstance(error, TimeoutError):
        return {"error": "timeout"}
    if isinstance(error, ConnectionRefusedError):
        return {"error": "refused"}
    return {"error": type(error).__name__, "errno": getattr(error, "errno", None)}


def cases(side):
    def expected(size, peer, echoed=False):
        result = metadata(payload(size), peer)
        if echoed:
            result["echo_sha256"] = result["sha256"]
        return result

    if side == "lan":
        return [
            ("ipv4-tcp-snat", lambda: tcp("198.18.10.254", TCP_PORT), expected(1024, "198.18.10.100", True)),
            ("ipv4-tcp-bulk-roundtrip", lambda: tcp("198.18.10.254", TCP_PORT, 4 * 1024**2), expected(4 * 1024**2, "198.18.10.100", True)),
            ("ipv4-udp-snat", lambda: udp("198.18.10.254", UDP_PORT, 512), expected(512, "198.18.10.100")),
            ("ipv4-udp-fragment-snat", lambda: udp("198.18.10.254", UDP_PORT, 4000), expected(4000, "198.18.10.100")),
            ("ipv4-icmp-echo-snat", lambda: ping("198.18.10.254", 56), {"delivered": True}),
            ("ipv4-icmp-fragment-snat", lambda: ping("198.18.10.254", 3000), {"delivered": True}),
            ("ipv4-related-port-unreachable", lambda: udp("198.18.10.254", 18199, 64), {"error": "refused"}),
            ("ipv6-tcp-forward", lambda: tcp("2001:db8:10::fe", TCP_PORT), expected(1024, "2001:db8:20::50", True)),
            ("ipv6-udp-forward", lambda: udp("2001:db8:10::fe", UDP_PORT, 512), expected(512, "2001:db8:20::50")),
        ]
    if side == "wan":
        return [
            ("ipv4-tcp-dnat", lambda: tcp("198.18.10.100", TCP_PORT), expected(1024, "198.18.10.254", True)),
            ("ipv4-udp-dnat", lambda: udp("198.18.10.100", UDP_PORT, 512), expected(512, "198.18.10.254")),
            ("ipv4-unsolicited-tcp-drop", lambda: tcp("198.18.20.50", TCP_PORT), {"error": "timeout"}),
            ("ipv4-unsolicited-udp-drop", lambda: udp("198.18.20.50", UDP_PORT, 64), {"error": "timeout"}),
            ("ipv4-tcp-reject", lambda: tcp("198.18.10.100", 18082), {"error": "refused"}),
            ("ipv6-unsolicited-tcp-drop", lambda: tcp("2001:db8:20::50", TCP_PORT), {"error": "timeout"}),
            ("ipv6-tcp-reject", lambda: tcp("2001:db8:10::100", 18082), {"error": "refused"}),
        ]
    if side == "pmtu":
        return [("ipv4-pmtu-feedback", pmtu, {"error": "message-too-large", "mtu": 1280})]
    # Firewall-policy sides (checks.firewall-policy-conformance): a WAN zone
    # that denies by default AND sets block-icmp, with no ICMPv6 rule of any kind,
    # an IPv4 bogon rule and an MSS clamp. Each case names the audit finding it
    # pins.
    if side == "policy-lan":
        return [
            # DP-09: forwarded SYN, full checksum from the sender, clamped.
            ("ipv4-tcp-mss-clamped-forward", lambda: tcp("198.18.10.254", TCP_PORT), expected(1024, "198.18.10.100", True)),
            # DP-C07: block-icmp neither stops the ping leaving nor its answer.
            ("ipv4-icmp-echo-under-block-icmp", lambda: ping("198.18.10.254", 56), {"delivered": True}),
            ("ipv4-related-unreachable-under-block-icmp", lambda: udp("198.18.10.254", 18199, 64), {"error": "refused"}),
            # DP-10: neighbour discovery on a default-drop, block-icmp WAN.
            ("ipv6-tcp-forward-default-drop-wan", lambda: tcp("2001:db8:10::fe", TCP_PORT), expected(1024, "2001:db8:20::50", True)),
            ("ipv6-icmp-echo-under-block-icmp", lambda: ping("2001:db8:10::fe", 56), {"delivered": True}),
            # DP-21: an ICMPv6 error about a tracked flow is RELATED.
            ("ipv6-related-unreachable-under-block-icmp", lambda: udp("2001:db8:10::fe", 18199, 64), {"error": "refused"}),
        ]
    if side == "policy-wan":
        return [
            # EDGE-02: the RST must be one the receiver accepts.
            ("ipv4-tcp-reject-valid-rst", lambda: tcp("198.18.10.100", 18082), {"error": "refused"}),
            # DP-11: a v4 0.0.0.0/8 drop on the same port must not touch IPv6...
            ("ipv6-tcp-reject-despite-v4-bogon-rule", lambda: tcp("2001:db8:10::100", 18082), {"error": "refused"}),
            # ...and a v4 0.0.0.0/1 accept must not open IPv6.
            ("ipv6-v4-prefix-rule-does-not-open", lambda: tcp("2001:db8:20::50", 18083), {"error": "timeout"}),
            # DP-35: a UDP reject answers with port-unreachable in both families.
            ("ipv4-udp-reject", lambda: udp("198.18.10.100", 18082, 64), {"error": "refused"}),
            ("ipv6-udp-reject", lambda: udp("2001:db8:10::100", 18082, 64), {"error": "refused"}),
            # block-icmp still refuses a new ping, over an explicit ICMP accept.
            ("ipv4-wan-ping-box-blocked", lambda: ping("198.18.10.100", 56), {"delivered": False}),
            ("ipv6-wan-ping-box-blocked", lambda: ping("2001:db8:10::100", 56), {"delivered": False}),
        ]
    if side == "pmtu6":
        return [("ipv6-pmtu-feedback-related", pmtu6_result, {"mtu": 1280})]
    raise ValueError("unknown traffic side: " + str(side))


def run(side):
    results = []
    for name, invoke, expected in cases(side):
        try:
            observed = invoke()
        except (OSError, ValueError, ConnectionError) as error:
            observed = error_result(error)
        results.append({"case": name, "expected": expected, "observed": observed})
    return results


def compare(oracle, subject, sides=("lan", "wan", "pmtu")):
    """No xfail/ignore list: even a known mismatch fails qualification."""
    for records in (oracle, subject):
        if not isinstance(records, list) or any(
            not isinstance(record, dict)
            or set(record) != {"case", "expected", "observed"}
            or not isinstance(record["case"], str)
            or not isinstance(record["expected"], dict)
            or not isinstance(record["observed"], dict)
            for record in records
        ):
            raise ValueError("malformed traffic results")
    oracle_by_id = {case["case"]: case for case in oracle}
    subject_by_id = {case["case"]: case for case in subject}
    if len(oracle_by_id) != len(oracle) or len(subject_by_id) != len(subject):
        raise ValueError("duplicate case identifier")
    if oracle_by_id.keys() != subject_by_id.keys():
        raise ValueError("different traffic inventories")
    required = {name: expected for side in sides
                for name, _, expected in cases(side)}
    if oracle_by_id.keys() != required.keys():
        raise ValueError("incomplete or unknown traffic inventory")
    result = []
    for name, ref in oracle_by_id.items():
        dut = subject_by_id[name]
        # Neither endpoint gets to redefine success. Two stale/misconfigured
        # probes agreeing that packet loss is expected must still fail closed.
        expected = json.dumps(required[name], sort_keys=True, allow_nan=False)
        for record in (ref, dut):
            if json.dumps(record["expected"], sort_keys=True, allow_nan=False) != expected:
                raise ValueError("noncanonical policy/expectation for " + name)
        oracle_valid = json.dumps(ref["observed"], sort_keys=True, allow_nan=False) == expected
        result.append({
            "case": name, "oracle_valid": oracle_valid,
            "passed": oracle_valid and json.dumps(
                dut["observed"], sort_keys=True, allow_nan=False) == expected,
            "expected": required[name], "netfilter": ref["observed"],
            "sentinel": dut["observed"],
        })
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("server")
    server.add_argument("address", nargs="+")
    client = commands.add_parser("client")
    client.add_argument("side", choices=("lan", "wan", "pmtu", "policy-lan", "policy-wan", "pmtu6"))
    hold = commands.add_parser("pmtu6-client")
    hold.add_argument("result")
    hold.add_argument("ready")
    inject = commands.add_parser("ptb6")
    inject.add_argument("client")
    inject.add_argument("client_port", type=int)
    inject.add_argument("server")
    inject.add_argument("server_port", type=int)
    inject.add_argument("mtu", type=int)
    args = parser.parse_args()
    if args.command == "server":
        asyncio.run(serve(args.address))
    elif args.command == "pmtu6-client":
        pmtu6_client(args.result, args.ready)
    elif args.command == "ptb6":
        ptb6(args.client, args.client_port, args.server, args.server_port, args.mtu)
    else:
        print(json.dumps(run(args.side)))
