"""Endpoint-only pressure control; never a Sentinel map/admission qualification."""

PHASES = (1, 64, 12000, 15000, 16000, 17000, 20000)
SOURCE = "198.18.20.50"
PUBLIC = "198.18.10.100"
TARGETS = ("198.18.10.253", "198.18.10.254")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def endpoint(value, address, first=1, last=65535):
    return (isinstance(value, list) and len(value) == 2 and value[0] == address
            and type(value[1]) is int and first <= value[1] <= last)


def failure(value):
    return (isinstance(value, dict)
            and all(isinstance(value.get(key), str) and value[key] for key in ("stage", "kind"))
            and isinstance(value.get("detail"), str))


def analyse(manifest, echoes, count, revision, previous=None):
    """Validate immutable socket identities, then report (not hide) failed traffic.

    The unchanged common client validates nonce/flow/round bytes on each original
    socket. Receipts attest those checks; this oracle additionally rejects stale
    rounds, identity substitutions, incomplete rows and public tuple aliases.
    """
    need(type(count) is int and count in PHASES, "unexpected pressure phase")
    need(isinstance(manifest, dict) and isinstance(echoes, dict), "malformed receipts")
    need(all(type(value.get("version")) is int and value["version"] == 1
             and value.get("probe_revision") == revision for value in (manifest, echoes)),
         "probe version/revision mismatch")
    nonce = manifest.get("nonce")
    need(isinstance(nonce, str) and len(nonce) == 32
         and all(char in "0123456789abcdef" for char in nonce), "invalid nonce")
    attempts, rows = manifest.get("attempts"), echoes.get("rows")
    need(type(manifest.get("requested")) is int and manifest["requested"] == count
         and isinstance(attempts, list) and len(attempts) == count
         and isinstance(rows, list), "incomplete pressure receipts")
    need(type(echoes.get("round")) is int and echoes["round"] == PHASES.index(count) + 1,
         "stale or incorrect probe round")
    if count == PHASES[0]:
        need(previous is None, "unexpected previous phase")
    else:
        need(isinstance(previous, dict) and previous.get("requested") == PHASES[PHASES.index(count) - 1]
             and previous.get("nonce") == nonce
             and attempts[:previous["requested"]] == previous.get("attempts"),
             "previous held socket identities changed or phase missing")
    successful, opening, public, private = [], [], set(), set()
    aliases = 0
    for index, attempt in enumerate(attempts):
        need(isinstance(attempt, dict) and type(attempt.get("id")) is int
             and attempt["id"] == index
             and attempt.get("target") == [TARGETS[index % 2], 9000]
             and type(attempt.get("initial_echo")) is bool, "malformed flow identity")
        if attempt["initial_echo"]:
            need("failure" not in attempt and endpoint(attempt.get("source"), SOURCE, 1024)
                 and endpoint(attempt.get("wire_peer"), PUBLIC, 32768, 65535),
                 "invalid successful flow source/public tuple")
            key = (tuple(attempt["target"]), tuple(attempt["source"]))
            need(key not in private, "duplicate original socket identity")
            private.add(key)
            key = (tuple(attempt["target"]), tuple(attempt["wire_peer"]))
            aliases += int(key in public)
            public.add(key)
            successful.append(index)
        else:
            need(failure(attempt.get("failure")), "missing opening failure evidence")
            opening.append({"id": index, "failure": attempt["failure"]})
    need(type(manifest.get("held")) is int and manifest["held"] == len(successful)
         and len(rows) == len(successful), "held flow coverage incomplete")
    failed, verified = [], 0
    for index, row in zip(successful, rows, strict=True):
        need(isinstance(row, dict) and type(row.get("id")) is int and row["id"] == index
             and type(row.get("verified")) is bool, "malformed or duplicate held echo identity")
        if row["verified"]:
            need("failure" not in row, "contradictory successful echo")
            verified += 1
        else:
            need(failure(row.get("failure")), "missing held echo failure evidence")
            failed.append(row)
    return {"requested": count, "initial_nonce_echoes": len(successful),
            "verified_held_echoes": verified, "opening_failures": opening,
            "held_echo_failures": failed, "external_tuple_aliases": aliases,
            "passed": not opening and not failed and aliases == 0,
            "scope": "nftables reference endpoint evidence only; no Sentinel qualification"}
