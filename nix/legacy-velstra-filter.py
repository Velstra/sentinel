"""Hand an OLDER velstra agent the current compiler's velstra.toml (test only).

Only the mixed-version HA fixture pairs the current Sentinel compiler with an
older agent; on a real box both ship in one image. The older agent refuses
unknown keys, so this rewrites exactly the constructs that postdate it:

* top-level tables named on the command line (e.g. ``[state]``) are dropped;
* a ``dst-local = true`` port rule (DP-16: "this host", resolved by the new
  agent from its live addresses) is rewritten into the form the older agent
  understood: one rule per address this host holds, ``dst = "<addr>/<len>"``.
  Deleting only the key would turn the rule into "any destination", so that
  is never done; a host with no address of the rule's family gets no rule,
  which is narrower than written, never wider.
* ``blocklist_ingress_only = true`` (DP-15: the blocklist names sources only)
  is dropped: the older agent then also matches the blocklist against
  destinations at egress and refuses listed addresses' answers — what it always
  did, and stricter than written, never wider.
* ``[[synproxy]]`` entries scoped by ``policy`` (DP-31) lose the key and are
  folded into one entry per port: the older agent proxies a port on every
  zone, a superset of the zones written, and refuses a port listed twice.

Anything else the older agent rejects still crash-loops it and fails the
check: the list of rewrites is explicit on purpose.

usage: legacy-velstra-filter.py SOURCE TARGET IP_JSON_FILE|- TABLE...
IP_JSON_FILE is ``ip -j address show`` output ("-" runs nothing: no addresses).
"""

import ipaddress
import json
import sys
import tomllib

DST_LOCAL = "dst-local = true"
INGRESS_ONLY = "blocklist_ingress_only = true"


def host_addresses(ip_json):
    """Unicast addresses, both families, loopback/multicast/unspecified left out."""
    out = []
    for link in ip_json:
        for info in link.get("addr_info", []):
            addr = ipaddress.ip_address(info["local"])
            if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
                continue
            out.append(addr)
    return sorted(set(out), key=lambda a: (a.version, int(a)))


def blocks(text):
    """Split TOML text into (header, lines) blocks; the first header is None."""
    current, lines = None, []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("["):
            yield current, lines
            current, lines = stripped, []
        lines.append(line)
    yield current, lines


def expand_local(lines, addresses):
    """One concrete copy of a dst-local rule block per matching host address."""
    body = "".join(lines[1:])
    family = tomllib.loads(body).get("family")
    out = []
    for addr in addresses:
        if family == "ipv4" and addr.version != 4 or family == "ipv6" and addr.version != 6:
            continue
        prefix = 32 if addr.version == 4 else 128
        out.append(lines[0])
        for line in lines[1:]:
            if line.strip() == DST_LOCAL:
                line = f'dst = "{addr}/{prefix}"\n'
            out.append(line)
    return out


def unscoped_synproxy(lines, seen_ports):
    """A ``[[synproxy]]`` block without its ``policy``, or nothing when an
    entry for the same port was already kept."""
    port = tomllib.loads("".join(lines[1:]))["port"]
    if port in seen_ports:
        return []
    seen_ports.add(port)
    return [l for l in lines if not l.strip().startswith("policy =")]


def rewrite(text, names, addresses):
    kept, stripped, expanded, synproxy_ports = [], [], 0, set()
    for header, lines in blocks(text):
        lines = [l for l in lines if l.strip() != INGRESS_ONLY]
        if header is not None and not header.startswith("[["):
            if header.strip("[]").strip() in names:
                stripped.append(header)
                continue
        if header == "[[synproxy]]":
            kept.extend(unscoped_synproxy(lines, synproxy_ports))
            continue
        if header and header.startswith("[[") and any(l.strip() == DST_LOCAL for l in lines):
            kept.extend(expand_local(lines, addresses))
            expanded += 1
            continue
        kept.extend(lines)
    out = "".join(kept)
    parsed = tomllib.loads(out)
    assert not names & parsed.keys(), f"named tables survived the filter: {names & parsed.keys()}"
    assert "blocklist_ingress_only" not in parsed, "blocklist_ingress_only survived the filter"
    for policy in parsed.get("policy", []):
        assert "blocklist_ingress_only" not in policy, f"survived the filter: {policy}"
        for rule in policy.get("port_rule", []):
            assert "dst-local" not in rule, f"a dst-local rule survived the filter: {rule}"
    for entry in parsed.get("synproxy", []):
        assert "policy" not in entry, f"a scoped synproxy entry survived the filter: {entry}"
    return out, stripped, expanded


def main(argv):
    source, target, ip_file, names = argv[1], argv[2], argv[3], set(argv[4:])
    ip_json = [] if ip_file == "-" else json.load(open(ip_file))
    text, stripped, expanded = rewrite(open(source).read(), names, host_addresses(ip_json))
    open(target, "w").write(text)
    print(
        f"legacy agent config: stripped {stripped or 'nothing'}, "
        f"expanded {expanded} dst-local rule(s)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main(sys.argv)
