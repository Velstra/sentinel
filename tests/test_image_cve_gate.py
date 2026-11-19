"""Regression tests for the image CVE release gate (IMG-05).

The 1.0.0 audit found the gate blind: syft's Nix cataloger emits vendor=product
CPEs, so grype matched nothing for glibc/openssh/curl/suricata. These tests pin
the corrected mapping, the fail-closed rules and the waiver policy.
"""
from datetime import date
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "image_cve_gate.py"
TODAY = date(2026, 11, 19)
H = "/nix/store/" + "a" * 32 + "-"


def load():
    sys.path.insert(0, str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("image_cve_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load()
TABLE = gate.load_table(ROOT / "scripts" / "nix_cpe_map.json")


def nix_artifact(name, version, output=None):
    query = f"?output={output}&outputhash=x" if output else "?outputhash=x"
    return {"id": f"{name}-{version}-{output}", "name": name, "version": version, "type": "nix",
            "foundBy": "nix-cataloger", "purl": f"pkg:nix/{name}@{version}{query}",
            "cpes": [{"cpe": f"cpe:2.3:a:{name}:{name}:{version}:*:*:*:*:*:*:*", "source": "syft-generated"}],
            "locations": [{"path": f"{H}{name}-{version}" + (f"-{output}" if output else "")}]}


def kernel_artifact(version="6.12.117"):
    return {"id": "kernel", "name": "linux-kernel", "version": version, "type": "linux-kernel",
            "foundBy": "linux-kernel-cataloger", "purl": f"pkg:generic/linux-kernel@{version}",
            "cpes": [{"cpe": f"cpe:2.3:o:linux:linux_kernel:{version}:*:*:*:*:*:*:*", "source": "syft-generated"}]}


def full_sbom():
    artifacts = [kernel_artifact()]
    for name, version in [("glibc", "2.42-100"), ("openssh", "10.6p2"), ("openssl", "3.6.5"),
                          ("curl", "8.23.0"), ("systemd", "260.5"), ("sudo", "1.9.17p2"),
                          ("dnsmasq", "2.93"), ("strongswan", "6.1.0")]:
        artifacts.append(nix_artifact(name, version))
    return {"artifacts": artifacts, "source": {"type": "directory"}, "descriptor": {"name": "syft"}}


def full_closure():
    return [H + p for p in ("glibc-2.42-100", "openssh-10.6p2", "openssl-3.6.5", "curl-8.23.0-bin",
                            "systemd-260.5", "sudo-1.9.17p2", "dnsmasq-2.93", "strongswan-6.1.0",
                            "linux-6.12.117")]


def grype_match(cve, name, version, severity="High", fixed=("9.9",), state="fixed", kind="nix",
                constraint="< 9.9 (unknown)"):
    return {"vulnerability": {"id": cve, "severity": severity,
                              "fix": {"versions": list(fixed), "state": state}},
            "matchDetails": [{"found": {"versionConstraint": constraint}}],
            "artifact": {"name": name, "version": version, "type": kind}}


def waiver(cve, **extra):
    entry = {"id": cve, "reason": "reviewed: not reachable", "reviewed-by": "release-review",
             "reviewed": "2026-11-01", "expires": "2027-01-15"}
    entry.update(extra)
    return entry


class Table(unittest.TestCase):
    def test_schema_and_critical_set(self):
        self.assertEqual(TABLE["schema"], "velstra-nix-cpe-map/1")
        self.assertEqual(set(TABLE["critical"]), {"linux-kernel", "glibc", "openssh", "openssl", "curl",
                                                  "systemd", "sudo", "dnsmasq", "strongswan"})

    def test_every_critical_userspace_package_has_a_cpe(self):
        for name in TABLE["critical"]:
            if name == "linux-kernel":
                continue
            entry = TABLE["packages"][name]
            self.assertTrue(entry["vendor"] and entry["product"], name)

    def test_covers_the_audit_rewrites(self):
        # Everything the audit's fixcpe.py corrected must stay corrected.
        for name in ("glibc", "openssh", "curl", "suricata", "unbound", "python3", "util-linux",
                     "gnutls", "krb5", "expat", "binutils", "mongoc", "zlib", "net-snmp", "sqlite",
                     "libcap", "perl", "xz", "haproxy", "lego"):
            self.assertIn(name, TABLE["packages"], name)

    def test_aliases_point_at_packages(self):
        for alias, target in TABLE["aliases"].items():
            self.assertIn(target, TABLE["packages"], alias)

    def test_invalid_table_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "t.json"
            path.write_text(json.dumps({"schema": "velstra-nix-cpe-map/1", "critical": ["curl"],
                                        "packages": {}, "aliases": {}, "first-party": []}))
            with self.assertRaises(ValueError):
                gate.load_table(path)


class Versions(unittest.TestCase):
    def test_glibc_release_branch_suffix_is_stripped(self):
        self.assertEqual(gate.cpe_for(TABLE, "glibc", "2.42-100"), "cpe:2.3:a:gnu:glibc:2.42:*:*:*:*:*:*:*")

    def test_openssh_keeps_portable_suffix(self):
        self.assertEqual(gate.cpe_for(TABLE, "openssh", "10.5p1"),
                         "cpe:2.3:a:openbsd:openssh:10.5p1:*:*:*:*:*:*:*")

    def test_alias_resolves(self):
        self.assertEqual(gate.cpe_for(TABLE, "systemd-minimal", "260.5"),
                         "cpe:2.3:a:systemd_project:systemd:260.5:*:*:*:*:*:*:*")

    def test_unknown_package_has_no_mapping(self):
        self.assertIsNone(gate.cpe_for(TABLE, "not-a-real-package", "1.0"))


class Rewrite(unittest.TestCase):
    def test_vendor_equals_product_cpes_are_replaced(self):
        sbom, report = gate.rewrite(full_sbom(), TABLE)
        curl = [a for a in sbom["artifacts"] if a["name"] == "curl"][0]
        self.assertEqual([c["cpe"] for c in curl["cpes"]], ["cpe:2.3:a:haxx:curl:8.23.0:*:*:*:*:*:*:*"])
        self.assertGreaterEqual(report["rewritten"], 8)

    def test_kernel_cataloger_entry_is_kept(self):
        sbom, _ = gate.rewrite(full_sbom(), TABLE)
        kernel = [a for a in sbom["artifacts"] if a["type"] == "linux-kernel"]
        self.assertEqual(kernel[0]["cpes"][0]["cpe"], "cpe:2.3:o:linux:linux_kernel:6.12.117:*:*:*:*:*:*:*")

    def test_first_party_guess_cpes_are_dropped(self):
        # The audit's grype run matched an unrelated product called "wren".
        source = full_sbom()
        source["artifacts"].append(nix_artifact("wren", "0.4.0"))
        sbom, report = gate.rewrite(source, TABLE)
        wren = [a for a in sbom["artifacts"] if a["name"] == "wren"][0]
        self.assertEqual(wren["cpes"], [])
        self.assertIn("wren", report["first_party"])

    def test_input_is_not_mutated(self):
        source = full_sbom()
        before = json.dumps(source, sort_keys=True)
        gate.rewrite(source, TABLE)
        self.assertEqual(json.dumps(source, sort_keys=True), before)


class Coverage(unittest.TestCase):
    def test_complete_sbom_has_no_coverage_errors(self):
        sbom, _ = gate.rewrite(full_sbom(), TABLE)
        self.assertEqual(gate.critical_coverage(sbom, full_closure(), TABLE), [])

    def test_missing_kernel_cataloger_fails(self):
        source = full_sbom()
        source["artifacts"] = [a for a in source["artifacts"] if a["type"] != "linux-kernel"]
        sbom, _ = gate.rewrite(source, TABLE)
        errors = gate.critical_coverage(sbom, full_closure(), TABLE)
        self.assertTrue(any("linux-kernel" in e for e in errors), errors)

    def test_critical_in_closure_but_absent_from_sbom_fails(self):
        source = full_sbom()
        source["artifacts"] = [a for a in source["artifacts"] if a["name"] != "openssh"]
        sbom, _ = gate.rewrite(source, TABLE)
        errors = gate.critical_coverage(sbom, full_closure(), TABLE)
        self.assertTrue(any("openssh" in e for e in errors), errors)

    def test_unrewritten_sbom_fails(self):
        # The audit's exact failure: vendor=product CPEs that grype cannot match.
        errors = gate.critical_coverage(full_sbom(), full_closure(), TABLE)
        self.assertTrue(any("glibc" in e for e in errors), errors)

    def test_critical_absent_from_closure_is_not_required(self):
        source = full_sbom()
        source["artifacts"] = [a for a in source["artifacts"] if a["name"] != "strongswan"]
        closure = [p for p in full_closure() if "strongswan" not in p]
        sbom, _ = gate.rewrite(source, TABLE)
        self.assertEqual(gate.critical_coverage(sbom, closure, TABLE), [])


class Waivers(unittest.TestCase):
    def validate(self, entries, findings=None, kernel=None):
        findings = findings if findings is not None else [gate.Finding("CVE-2026-1", "curl", "8.22.0", "High")]
        return gate.validate_waivers({"schema": "velstra-cve-waivers/1", "waivers": entries,
                                      **({"kernel-baseline": kernel} if kernel else {})},
                                     findings, TODAY)

    def test_valid_waiver(self):
        self.assertEqual(self.validate([waiver("CVE-2026-1")]), [])

    def test_expired_waiver_fails(self):
        errors = self.validate([waiver("CVE-2026-1", reviewed="2026-09-01", expires="2026-11-01")])
        self.assertTrue(any("expired" in e for e in errors), errors)

    def test_missing_fields_fail(self):
        for field in ("reason", "reviewed-by", "reviewed", "expires"):
            entry = waiver("CVE-2026-1")
            del entry[field]
            self.assertTrue(self.validate([entry]), field)

    def test_too_long_waiver_fails(self):
        errors = self.validate([waiver("CVE-2026-1", reviewed="2026-11-01", expires="2027-03-01")])
        self.assertTrue(any("90 days" in e for e in errors), errors)

    def test_stale_waiver_fails(self):
        errors = self.validate([waiver("CVE-2026-9999")])
        self.assertTrue(any("matches no finding" in e for e in errors), errors)

    def test_package_scoped_waiver_must_match_package(self):
        errors = self.validate([waiver("CVE-2026-1", package="glibc")])
        self.assertTrue(any("matches no finding" in e for e in errors), errors)
        self.assertEqual(self.validate([waiver("CVE-2026-1", package="curl")]), [])

    def test_blanket_wildcards_are_refused(self):
        self.assertTrue(self.validate([waiver("*")]))
        self.assertTrue(self.validate([waiver("CVE-2026-*")]))

    def test_kernel_baseline_must_name_installed_version(self):
        baseline = {"kernel-version": "6.12.113", "max-unresolved": 10, "reason": "r",
                    "reviewed-by": "x", "reviewed": "2026-11-01", "expires": "2026-12-01"}
        findings = [gate.Finding("CVE-2026-2", "linux-kernel", "6.12.117", "High", kind="linux-kernel")]
        errors = self.validate([], findings, baseline)
        self.assertTrue(any("kernel" in e for e in errors), errors)


class Policy(unittest.TestCase):
    def evaluate(self, matches, vulnix=(), waivers=(), patched=None, kernel=None, closure=None, sbom=None):
        rewritten, _ = gate.rewrite(sbom or full_sbom(), TABLE)
        doc = {"schema": "velstra-cve-waivers/1", "waivers": list(waivers)}
        if kernel:
            doc["kernel-baseline"] = kernel
        return gate.evaluate(grype={"matches": list(matches)}, vulnix=list(vulnix), waivers=doc,
                             patched=patched or {}, sbom=rewritten,
                             closure=closure if closure is not None else full_closure(),
                             table=TABLE, today=TODAY, severity="High")

    def test_clean_passes(self):
        self.assertTrue(self.evaluate([])["pass"])

    def test_fixable_high_fails(self):
        verdict = self.evaluate([grype_match("CVE-2026-1", "curl", "8.22.0")])
        self.assertFalse(verdict["pass"])
        self.assertEqual(verdict["blocking"][0]["id"], "CVE-2026-1")

    def test_medium_does_not_block(self):
        self.assertTrue(self.evaluate([grype_match("CVE-2026-1", "curl", "8.22.0", severity="Medium")])["pass"])

    def test_no_fix_does_not_block(self):
        verdict = self.evaluate([grype_match("CVE-2026-1", "curl", "8.22.0", fixed=(), state="")])
        self.assertTrue(verdict["pass"])
        self.assertEqual(verdict["summary"]["no-fix"], 1)

    def test_fix_only_on_older_branches_does_not_block(self):
        # grype says "fixed" for libpq 18.6 although every fixed version is older.
        verdict = self.evaluate([grype_match("CVE-2026-116304", "libpq", "18.6",
                                             fixed=("14.25", "15.20", "16.16", "17.12"))])
        self.assertTrue(verdict["pass"], verdict["blocking"])
        self.assertEqual(verdict["summary"]["no-fix"], 1)

    def test_fix_compares_the_nvd_version(self):
        # glibc 2.42-100 is the 2.42 branch; a 2.42.1 fix is newer than it.
        verdict = self.evaluate([grype_match("CVE-2026-8", "glibc", "2.42-100", fixed=("2.42.1",))])
        self.assertFalse(verdict["pass"])

    def test_nix_patched_is_subtracted(self):
        verdict = self.evaluate([grype_match("CVE-2026-1", "curl", "8.22.0")],
                                patched={"curl": ["CVE-2026-1"]})
        self.assertTrue(verdict["pass"])
        self.assertEqual(verdict["summary"]["nix-patched"], 1)

    def test_patched_for_other_package_does_not_hide(self):
        verdict = self.evaluate([grype_match("CVE-2026-1", "curl", "8.22.0")],
                                patched={"glibc": ["CVE-2026-1"]})
        self.assertFalse(verdict["pass"])

    def test_waiver_unblocks(self):
        verdict = self.evaluate([grype_match("CVE-2026-1", "curl", "8.22.0")], waivers=[waiver("CVE-2026-1")])
        self.assertTrue(verdict["pass"])
        self.assertEqual(verdict["summary"]["waived"], 1)

    def test_duplicate_outputs_count_once(self):
        matches = [grype_match("CVE-2026-1", "curl", "8.22.0"),
                   grype_match("CVE-2026-1", "curl", "8.22.0", kind="binary"),
                   grype_match("CVE-2026-1", "curl", "8.22.0")]
        verdict = self.evaluate(matches)
        self.assertEqual(len(verdict["blocking"]), 1)

    def test_vulnix_only_high_blocks(self):
        vulnix = [{"pname": "openssh", "version": "10.5p1", "affected_by": ["CVE-2026-7"],
                   "cvssv3_basescore": {"CVE-2026-7": 8.1}}]
        verdict = self.evaluate([], vulnix=vulnix)
        self.assertFalse(verdict["pass"])
        self.assertEqual(verdict["blocking"][0]["sources"], ["vulnix"])
        self.assertEqual(verdict["summary"]["vulnix-only"], 1)

    def test_vulnix_and_grype_merge(self):
        vulnix = [{"pname": "curl", "version": "8.22.0", "affected_by": ["CVE-2026-1"],
                   "cvssv3_basescore": {"CVE-2026-1": 7.5}}]
        verdict = self.evaluate([grype_match("CVE-2026-1", "curl", "8.22.0")], vulnix=vulnix)
        self.assertEqual(len(verdict["blocking"]), 1)
        self.assertEqual(verdict["blocking"][0]["sources"], ["grype", "vulnix"])
        self.assertEqual(verdict["summary"]["both"], 1)

    def test_vulnix_alias_merges(self):
        vulnix = [{"pname": "systemd-minimal", "version": "260.5", "affected_by": ["CVE-2026-3"],
                   "cvssv3_basescore": {"CVE-2026-3": 5.0}}]
        verdict = self.evaluate([grype_match("CVE-2026-3", "systemd", "260.5", severity="Medium")], vulnix=vulnix)
        self.assertEqual(verdict["summary"]["both"], 1)

    def test_vulnix_low_does_not_block(self):
        vulnix = [{"pname": "curl", "version": "8.22.0", "affected_by": ["CVE-2026-1"],
                   "cvssv3_basescore": {"CVE-2026-1": 3.1}}]
        self.assertTrue(self.evaluate([], vulnix=vulnix)["pass"])

    def test_coverage_failure_blocks(self):
        source = full_sbom()
        source["artifacts"] = [a for a in source["artifacts"] if a["type"] != "linux-kernel"]
        verdict = self.evaluate([], sbom=source)
        self.assertFalse(verdict["pass"])
        self.assertTrue(verdict["coverage-errors"])

    def test_invalid_waiver_blocks_even_without_findings(self):
        verdict = self.evaluate([], waivers=[waiver("CVE-2026-1")])
        self.assertFalse(verdict["pass"])

    def test_kernel_same_branch_fix_blocks(self):
        match = grype_match("CVE-2026-5", "linux-kernel", "6.12.113", kind="linux-kernel",
                            fixed=("6.1.191", "6.12.114", "6.18.40"))
        sbom = full_sbom()
        sbom["artifacts"][0] = kernel_artifact("6.12.113")
        verdict = self.evaluate([match], sbom=sbom)
        self.assertFalse(verdict["pass"])
        self.assertEqual(verdict["blocking"][0]["kernel"], "same-branch-fix")

    def test_kernel_other_branch_fix_needs_baseline(self):
        match = grype_match("CVE-2026-6", "linux-kernel", "6.12.117", kind="linux-kernel",
                            fixed=("6.18.33", "7.0.10"))
        verdict = self.evaluate([match])
        self.assertFalse(verdict["pass"])
        self.assertTrue(any("kernel" in e for e in verdict["policy-errors"]), verdict)

    def test_kernel_baseline_ceiling(self):
        matches = [grype_match(f"CVE-2026-6{i}", "linux-kernel", "6.12.117", kind="linux-kernel",
                               fixed=("6.18.33",)) for i in range(3)]
        baseline = {"kernel-version": "6.12.117", "max-unresolved": 3, "reason": "reviewed backports",
                    "reviewed-by": "release-review", "reviewed": "2026-11-15", "expires": "2026-12-15"}
        self.assertTrue(self.evaluate(matches, kernel=baseline)["pass"])
        baseline["max-unresolved"] = 2
        verdict = self.evaluate(matches, kernel=baseline)
        self.assertFalse(verdict["pass"])

    def test_summary_counts_per_package(self):
        verdict = self.evaluate([grype_match("CVE-2026-1", "curl", "8.22.0", severity="Critical"),
                                 grype_match("CVE-2026-2", "curl", "8.22.0", severity="Low")])
        self.assertEqual(verdict["packages"]["curl"]["Critical"], 1)
        self.assertEqual(verdict["packages"]["curl"]["Low"], 1)


class Patched(unittest.TestCase):
    def test_extracts_patch_cves_per_package(self):
        derivations = {"derivations": {
            "/nix/store/x-sudo-1.9.17p2.drv": {"name": "sudo-1.9.17p2", "env": {
                "pname": "sudo", "version": "1.9.17p2",
                "patches": "/nix/store/i5g-CVE-2026-96512_1.patch /nix/store/nim-cve-2026-96512_2.patch"}},
            "/nix/store/y-zlib-1.3.2.drv": {"name": "zlib-1.3.2", "structuredAttrs": {
                "pname": "zlib", "version": "1.3.2", "patches": ["/nix/store/q-cve-2026-85091.patch"]}},
            "/nix/store/z-hello-1.drv": {"name": "hello-1", "env": {"pname": "hello", "patches": ""}},
        }}
        result = gate.patched_cves(derivations)
        self.assertEqual(result, {"sudo": ["CVE-2026-96512"], "zlib": ["CVE-2026-85091"]})

    def test_legacy_top_level_map(self):
        derivations = {"/nix/store/y-zlib-1.3.2.drv": {"name": "zlib-1.3.2", "env": {
            "patches": "/nix/store/q-CVE-2026-85091.patch"}}}
        self.assertEqual(gate.patched_cves(derivations), {"zlib": ["CVE-2026-85091"]})


class Waive(unittest.TestCase):
    def test_waive_generates_per_cve_entries(self):
        verdict = {"blocking": [{"id": "CVE-2026-1", "package": "curl"}, {"id": "CVE-2026-2", "package": "glibc"}]}
        entries = gate.waive(verdict, ["CVE-2026-1"], reason="not reachable: no HTTP/3",
                             reviewer="release-review", today=TODAY, days=30)
        self.assertEqual(entries, [{"id": "CVE-2026-1", "package": "curl", "reason": "not reachable: no HTTP/3",
                                    "reviewed-by": "release-review", "reviewed": "2026-11-19",
                                    "expires": "2026-12-19"}])

    def test_waive_refuses_unknown_cve_and_long_expiry(self):
        verdict = {"blocking": [{"id": "CVE-2026-1", "package": "curl"}]}
        with self.assertRaises(ValueError):
            gate.waive(verdict, ["CVE-2026-9"], reason="r", reviewer="x", today=TODAY, days=30)
        with self.assertRaises(ValueError):
            gate.waive(verdict, ["CVE-2026-1"], reason="r", reviewer="x", today=TODAY, days=120)
        with self.assertRaises(ValueError):
            gate.waive(verdict, ["CVE-2026-1"], reason=" ", reviewer="x", today=TODAY, days=30)


class Cli(unittest.TestCase):
    def test_evaluate_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            sbom, _ = gate.rewrite(full_sbom(), TABLE)
            (tmp / "sbom.json").write_text(json.dumps(sbom))
            (tmp / "grype.json").write_text(json.dumps({"matches": [grype_match("CVE-2026-1", "curl", "8.22.0")]}))
            (tmp / "vulnix.json").write_text("[]")
            (tmp / "closure.txt").write_text("\n".join(full_closure()) + "\n")
            (tmp / "waivers.json").write_text(json.dumps({"schema": "velstra-cve-waivers/1", "waivers": []}))
            command = [sys.executable, "-B", str(SCRIPT), "evaluate", "--sbom", str(tmp / "sbom.json"),
                       "--grype", str(tmp / "grype.json"), "--vulnix", str(tmp / "vulnix.json"),
                       "--closure", str(tmp / "closure.txt"), "--waivers", str(tmp / "waivers.json"),
                       "--today", "2026-11-19", "--output", str(tmp / "verdict.json")]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("CVE-2026-1", result.stdout)
            self.assertFalse(json.loads((tmp / "verdict.json").read_text())["pass"])

    def test_committed_waivers_file_is_valid_schema(self):
        doc = json.loads((ROOT / "scripts" / "cve-waivers.json").read_text())
        self.assertEqual(doc["schema"], "velstra-cve-waivers/1")
        self.assertIsInstance(doc["waivers"], list)


if __name__ == "__main__":
    unittest.main()
