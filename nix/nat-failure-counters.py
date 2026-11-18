"""Strict parsing of the agent's live NAT failure counters for packet tests.

These count packet attempts, not flows. Reads are not atomic across CPUs or
counter indexes; a no-candidate event is not evidence that a map is full.
"""

NAMES = frozenset(("egress_dropped", "egress_masqueraded",
                   "egress_nat_no_candidate", "egress_nat_claim_failed"))


def snapshot(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] in NAMES:
            if (len(fields) != 2 or fields[0] in result
                    or not fields[1].isascii() or not fields[1].isdigit()
                    or int(fields[1]) >= 2**64):
                raise ValueError("malformed or duplicate NAT counter")
            result[fields[0]] = int(fields[1])
    if result.keys() != NAMES:
        raise ValueError("live agent did not report all NAT failure counters")
    return result


def delta(before, after):
    if before.keys() != NAMES or after.keys() != NAMES:
        raise ValueError("incomplete NAT counter sample")
    if any(type(sample[key]) is not int or not 0 <= sample[key] < 2**64
           for sample in (before, after) for key in NAMES):
        raise ValueError("invalid NAT counter sample")
    if any(after[key] < before[key] for key in NAMES):
        raise ValueError("NAT counters reset during observation")
    return {key: after[key] - before[key] for key in sorted(NAMES)}
