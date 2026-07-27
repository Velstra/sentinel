"""Turn a DB-IP country database into one CIDR list per country.

Run at **image build time**, not on the appliance: a firewall that only blocks a
country when it can reach a geolocation service is not a firewall you can put on
an isolated network. The result is plain text on purpose — an operator who wants
to know whether their own address is in a list can read it.

Usage: geoip-extract.py <database.mmdb> <output-dir>

Writes `<CC>.v4` and `<CC>.v6` per ISO country code, one CIDR per line, plus a
`COUNTRIES` index naming every code that has data.
"""

import collections
import ipaddress
import os
import sys

import maxminddb


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, dst = sys.argv[1], sys.argv[2]

    nets = collections.defaultdict(list)
    with maxminddb.open_database(src) as db:
        for net, record in db:
            country = (record.get("country") or {}).get("iso_code")
            if country:
                nets[country].append(net)

    os.makedirs(dst, exist_ok=True)
    written = []
    for country in sorted(nets):
        for version, suffix in ((4, "v4"), (6, "v6")):
            selected = [n for n in nets[country] if n.version == version]
            if not selected:
                continue
            # The database is range-derived, so neighbouring blocks of the same
            # country are common; collapsing them costs nothing here and saves an
            # LPM node on the appliance for every pair that merges.
            merged = ipaddress.collapse_addresses(selected)
            path = os.path.join(dst, f"{country}.{suffix}")
            with open(path, "w") as f:
                for network in merged:
                    f.write(f"{network}\n")
        written.append(country)

    # An index, so the appliance can tell "no such country" from "that country has
    # no addresses" without listing a directory of 500 files.
    with open(os.path.join(dst, "COUNTRIES"), "w") as f:
        for country in written:
            f.write(f"{country}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
