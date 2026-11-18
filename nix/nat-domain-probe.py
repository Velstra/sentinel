"""Strict transport oracle for one real 65-port CGNAT block, not a NAT model."""

import ipaddress

SOURCE = "198.18.20.50"
TARGET = "198.18.10.254"
PUBLIC = "198.18.10.100"
PORT = 9000
BASE = 40000
SIZE = 65
SOURCE_PORTS = list(range(20000, 20066))
PHASES = (1, 65, 66)


def block():
    blocks = (65536 - BASE) // SIZE
    index = ((int(ipaddress.IPv4Address(SOURCE)) * 2654435761) & 0xffffffff) % blocks
    first = BASE + index * SIZE
    return first, first + SIZE - 1


def transport_result(manifest, echoes, count, previous=None):
    """Require complete identity-bearing evidence, including the refused socket.

    The common endpoint probe checks exact nonce/flow/round bytes on every held
    socket. A failed 66th handshake is expected only after all 65 permitted
    public ports were observed and the original 65 sockets still echo.
    """
    if type(count) is not int or count not in PHASES:
        raise ValueError("unexpected CGNAT phase")
    held = min(count, SIZE)
    attempts, rows = manifest.get("attempts"), echoes.get("rows")
    nonce = manifest.get("nonce")
    if (manifest.get("requested") != count or manifest.get("held") != held
            or not isinstance(attempts, list) or len(attempts) != count
            or not isinstance(rows, list) or len(rows) != held
            or type(echoes.get("round")) is not int
            or echoes["round"] != PHASES.index(count) + 1
            or not isinstance(nonce, str) or len(nonce) != 32
            or any(char not in "0123456789abcdef" for char in nonce)):
        raise ValueError("incomplete CGNAT transport evidence")
    first, last = block()
    public_ports = []
    for index, attempt in enumerate(attempts):
        if (type(attempt.get("id")) is not int or attempt["id"] != index
                or attempt.get("source") != [SOURCE, SOURCE_PORTS[index]]
                or attempt.get("target") != [TARGET, PORT]):
            raise ValueError("wrong or duplicate connection identity")
        if index == SIZE:
            failure = attempt.get("failure", {})
            if (attempt.get("initial_echo") is not False or "wire_peer" in attempt
                    or failure.get("stage") != "connect" or failure.get("kind") != "timeout"):
                raise ValueError("66th flow was admitted or failed outside the NAT admission path")
            continue
        row, wire = rows[index], attempt.get("wire_peer")
        if (type(row.get("id")) is not int or row["id"] != index
                or row.get("verified") is not True or "failure" in row
                or attempt.get("initial_echo") is not True or "failure" in attempt
                or not isinstance(wire, list) or len(wire) != 2
                or wire[0] != PUBLIC or type(wire[1]) is not int
                or not first <= wire[1] <= last):
            raise ValueError("missing echo, foreign public address or out-of-block port")
        public_ports.append(wire[1])
    if len(set(public_ports)) != held:
        raise ValueError("public tuple alias")
    if held == SIZE and set(public_ports) != set(range(first, last + 1)):
        raise ValueError("incomplete public port domain")
    if previous is not None and (
            previous.get("nonce") != nonce
            or attempts[:len(previous["attempts"])] != previous["attempts"]):
        raise ValueError("an existing socket identity changed across phases")
    return {"requested": count, "verified_held_echoes": held,
                "refused": count - held, "assigned_block": [first, last],
                "wire_ports_observed": public_ports, "passed": True}
