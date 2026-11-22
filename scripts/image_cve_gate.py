#!/usr/bin/env python3
"""Release CVE gate for the built appliance image (audit 8b6181, IMG-05).

syft's Nix cataloger emits `cpe:2.3:a:<name>:<name>` for every Nix package, so
grype matched nothing for glibc, openssh, curl, suricata … and the old gate
reported a clean image. This gate:

* rewrites Nix CPEs from a maintained table (`nix_cpe_map.json`, shared with
  the enterprise pipeline) and keeps syft's linux-kernel cataloger entry;
* fails closed when a critical package that ships has no CPE grype can match;
* merges grype with vulnix as an independent second source;
* subtracts only CVEs a nixpkgs patch names for that very package, and
  reviewed, expiring, per-CVE waivers — never a blanket ignore.

Subcommands: rewrite, evaluate, patched, waive, run. Stdlib only.
"""
import argparse
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import date, timedelta
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_image_closure import parse_store_name  # noqa: E402

TABLE_SCHEMA = "velstra-nix-cpe-map/1"
WAIVER_SCHEMA = "velstra-cve-waivers/1"
DEFAULT_TABLE = Path(__file__).resolve().parent / "nix_cpe_map.json"
DEFAULT_WAIVERS = Path(__file__).resolve().parent / "cve-waivers.json"
KERNEL = "linux-kernel"
KERNEL_CPE = "cpe:2.3:o:linux:linux_kernel:"
CPE_SOURCE = "velstra-nix-cpe-map"
SEVERITY = {"Unknown": 0, "Negligible": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
MAX_WAIVER_DAYS = 90
WAIVER_ID = re.compile(r"^(CVE-\d{4}-\d+|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|GO-\d{4}-\d{4,})$")
PATCH_CVE = re.compile(r"cve-\d{4}-\d{4,}", re.IGNORECASE)
VERSION_RULES = {"as-is", "strip-nix-revision"}
REQUIRED_WAIVER = ("reason", "reviewed-by", "reviewed", "expires")


# --- the CPE table --------------------------------------------------------

def load_table(path=DEFAULT_TABLE):
    table = json.loads(Path(path).read_text())
    if table.get("schema") != TABLE_SCHEMA:
        raise ValueError(f"CPE table schema is not {TABLE_SCHEMA}")
    packages, aliases = table.get("packages"), table.get("aliases", {})
    critical, first_party = table.get("critical"), table.get("first-party", [])
    if not isinstance(packages, dict) or not isinstance(aliases, dict) or not isinstance(critical, list):
        raise ValueError("CPE table needs packages, aliases and critical")
    for name, entry in packages.items():
        if not (isinstance(entry, dict) and entry.get("vendor") and entry.get("product")):
            raise ValueError(f"CPE table entry {name!r} lacks vendor/product")
        if entry.get("version", "as-is") not in VERSION_RULES:
            raise ValueError(f"CPE table entry {name!r} has an unknown version rule")
    for alias, target in aliases.items():
        if target not in packages:
            raise ValueError(f"alias {alias!r} points at unmapped {target!r}")
    for name in critical:
        if name != KERNEL and name not in packages:
            raise ValueError(f"critical package {name!r} has no CPE mapping")
    if KERNEL not in critical:
        raise ValueError("the kernel must be a critical package")
    if not isinstance(first_party, list):
        raise ValueError("first-party must be a list")
    if not isinstance(table.get("generated", []), list):
        raise ValueError("generated must be a list")
    return table


def generated(table, name, version, path=""):
    """A store path NixOS generates (a config dir, a PAM file) whose name only
    looks like `<package>-<version>`: `dbus-1` and `polkit-1.pam` were matched
    as dbus 1 and polkit 1, i.e. against advisories for releases from 2019.
    syft drops the `.pam` suffix from the version, so the store path's own
    name is checked as well as name-version."""
    names = set(table.get("generated", []))
    stored = STORE_NAME.match(Path(path).name) if path else None
    return f"{name}-{version}" in names or bool(stored and stored.group(1) in names)


STORE_NAME = re.compile(r"^[0-9a-df-np-sv-z]{32}-(.+)$")


def artifact_path(artifact):
    metadata = artifact.get("metadata") if isinstance(artifact.get("metadata"), dict) else {}
    locations = artifact.get("locations") or [{}]
    return metadata.get("path") or locations[0].get("path", "")


def canonical(table, name):
    return table["aliases"].get(name, name)


def nvd_version(rule, version):
    if rule == "strip-nix-revision":
        return re.sub(r"-\d+$", "", version)
    return version


def cpe_for(table, name, version):
    entry = table["packages"].get(canonical(table, name))
    if entry is None or not version:
        return None
    value = nvd_version(entry.get("version", "as-is"), version)
    return f"cpe:2.3:a:{entry['vendor']}:{entry['product']}:{value}:*:*:*:*:*:*:*"


def rewrite(sbom, table):
    """Return a corrected copy of a syft JSON document and a short report."""
    result = deepcopy(sbom)
    report = {"rewritten": 0, "first_party": [], "unmapped": []}
    first_party = set(table.get("first-party", []))
    for artifact in result.get("artifacts", []):
        if artifact.get("type") != "nix":
            continue
        name = artifact.get("name", "")
        if name in first_party:
            artifact["cpes"] = []
            report["first_party"].append(name)
            continue
        if generated(table, name, artifact.get("version", ""), artifact_path(artifact)):
            artifact["cpes"] = []
            report.setdefault("generated", []).append(f"{name}-{artifact.get('version', '')}")
            continue
        cpe = cpe_for(table, name, artifact.get("version", ""))
        if cpe is None:
            report["unmapped"].append(name)
            continue
        artifact["cpes"] = [{"cpe": cpe, "source": CPE_SOURCE}]
        report["rewritten"] += 1
    report["first_party"] = sorted(set(report["first_party"]))
    report["unmapped"] = sorted(set(report["unmapped"]))
    return result, report


# --- coverage of the critical set -----------------------------------------

def closure_names(table, closure):
    names = set()
    for path in closure:
        pname, version, _output = parse_store_name(path)
        if pname == "linux" and version and version[0].isdigit():
            names.add(KERNEL)
        names.add(canonical(table, pname))
    return names


def matchable(artifact, prefix):
    for cpe in artifact.get("cpes", []):
        value = cpe.get("cpe", "")
        if value.startswith(prefix):
            version = value[len(prefix):].split(":", 1)[0]
            if version not in ("", "*", "-", "UNKNOWN"):
                return True
    return False


def critical_coverage(sbom, closure, table):
    """Errors for critical packages that ship but that grype could not match."""
    if not closure:
        return ["the closure listing is empty; coverage cannot be judged"]
    shipped = closure_names(table, closure)
    artifacts = sbom.get("artifacts", [])
    errors = []
    for name in table["critical"]:
        if name not in shipped:
            continue
        if name == KERNEL:
            ok = any(a.get("type") == KERNEL and matchable(a, KERNEL_CPE) for a in artifacts)
            if not ok:
                errors.append("linux-kernel ships but syft's linux-kernel cataloger produced no "
                              "matchable cpe:2.3:o:linux:linux_kernel entry")
            continue
        entry = table["packages"][name]
        prefix = f"cpe:2.3:a:{entry['vendor']}:{entry['product']}:"
        candidates = [a for a in artifacts if canonical(table, a.get("name", "")) == name
                      and a.get("type") in ("nix", "binary")]
        if not candidates:
            errors.append(f"{name} ships but is absent from the SBOM")
        elif not any(matchable(a, prefix) for a in candidates):
            errors.append(f"{name} ships but has no CPE grype can match (expected {prefix}<version>)")
    return errors


# --- findings ---------------------------------------------------------------

@dataclass
class Finding:
    id: str
    package: str
    version: str
    severity: str
    kind: str = "nix"
    fixed: tuple = ()
    fix_state: str = ""
    sources: set = field(default_factory=set)


def severity_from_cvss(score):
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low" if score > 0 else "Unknown"


def package_of(table, artifact):
    kind = artifact.get("type", "")
    if kind == KERNEL:
        return KERNEL
    if kind in ("nix", "binary"):
        return canonical(table, artifact.get("name", ""))
    return artifact.get("name", "")


def merge(findings, item):
    key = (item.id, item.package)
    existing = findings.get(key)
    if existing is None:
        findings[key] = item
        return
    if SEVERITY.get(item.severity, 0) > SEVERITY.get(existing.severity, 0):
        existing.severity = item.severity
    existing.fixed = tuple(sorted(set(existing.fixed) | set(item.fixed)))
    if item.fix_state == "fixed":
        existing.fix_state = "fixed"
    if existing.kind != KERNEL and item.kind == KERNEL:
        existing.kind = KERNEL
    existing.sources |= item.sources


def collect(grype, vulnix, table):
    findings = {}
    first_party = set(table.get("first-party", []))
    for match in grype.get("matches", []):
        vulnerability, artifact = match["vulnerability"], match["artifact"]
        fix = vulnerability.get("fix") or {}
        merge(findings, Finding(vulnerability["id"].upper(), package_of(table, artifact),
                                artifact.get("version", ""), vulnerability.get("severity") or "Unknown",
                                artifact.get("type", ""), tuple(fix.get("versions") or ()),
                                fix.get("state") or "", {"grype"}))
    for entry in vulnix:
        package = canonical(table, entry.get("pname", ""))
        if package in first_party or generated(table, entry.get("pname", ""), entry.get("version", "")):
            continue
        scores = entry.get("cvssv3_basescore") or {}
        for cve in entry.get("affected_by", []):
            merge(findings, Finding(cve.upper(), package, entry.get("version", ""),
                                    severity_from_cvss(scores.get(cve)), "nix", (), "", {"vulnix"}))
    return list(findings.values())


def version_tuple(text):
    return tuple(int(part) for part in re.findall(r"\d+", text))


def same_branch_fix(installed, fixed):
    branch = version_tuple(installed)[:2]
    return any(version_tuple(v)[:2] == branch and version_tuple(v) > version_tuple(installed)
               for v in (f.lstrip("*") for f in fixed))


# --- waivers ----------------------------------------------------------------

def parse_day(value, label):
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label}: not an ISO date: {value!r}") from None


def review_errors(entry, label, today):
    errors = []
    for key in REQUIRED_WAIVER:
        if not isinstance(entry.get(key), str) or not entry[key].strip():
            errors.append(f"{label}: missing {key}")
    if errors:
        return errors
    try:
        reviewed, expires = parse_day(entry["reviewed"], label), parse_day(entry["expires"], label)
    except ValueError as error:
        return [str(error)]
    if reviewed > today:
        errors.append(f"{label}: reviewed in the future")
    if expires < today:
        errors.append(f"{label}: expired on {expires}")
    if expires - reviewed > timedelta(days=MAX_WAIVER_DAYS):
        errors.append(f"{label}: valid for more than {MAX_WAIVER_DAYS} days after its review")
    return errors


def waiver_matches(waiver, finding, table):
    if waiver["id"].upper() != finding.id:
        return False
    package = waiver.get("package")
    return package is None or canonical(table, package) == finding.package


def validate_waivers(doc, findings, today, kernel_version=None, table=None):
    table = table or {"aliases": {}}
    if doc.get("schema") != WAIVER_SCHEMA or not isinstance(doc.get("waivers"), list):
        return [f"waiver file schema is not {WAIVER_SCHEMA}"]
    errors, seen = [], set()
    for index, waiver in enumerate(doc["waivers"]):
        label = f"waiver {waiver.get('id', index)!s}"
        if not isinstance(waiver.get("id"), str) or not WAIVER_ID.match(waiver["id"].upper()):
            errors.append(f"{label}: id must be one exact CVE/GHSA/GO identifier, never a pattern")
            continue
        key = (waiver["id"].upper(), waiver.get("package"))
        if key in seen:
            errors.append(f"{label}: duplicate")
        seen.add(key)
        errors += review_errors(waiver, label, today)
        if not any(waiver_matches(waiver, f, table) for f in findings):
            errors.append(f"{label}: matches no finding (stale; remove it)")
    baseline = doc.get("kernel-baseline")
    if baseline is not None:
        errors += review_errors(baseline, "kernel-baseline", today)
        installed = kernel_version or next((f.version for f in findings if f.kind == KERNEL), None)
        if "max-unresolved" in baseline:
            errors.append("kernel-baseline: a count ceiling (max-unresolved) accepts CVEs nobody reviewed; "
                          "list the reviewed CVE ids in reviewed-cves instead")
        errors += baseline_list_errors(baseline)
        if installed and baseline.get("kernel-version") != installed:
            errors.append(f"kernel-baseline reviewed {baseline.get('kernel-version')} but the image ships "
                          f"kernel {installed}; re-review the unresolved kernel matches")
    return errors


# --- verdict ----------------------------------------------------------------

def baseline_list_errors(baseline):
    """reviewed-cves: {disposition: [CVE id, ...]}, every id exact and listed once."""
    groups = baseline.get("reviewed-cves")
    if not isinstance(groups, dict) or not groups:
        return ["kernel-baseline: reviewed-cves must map each triage disposition to its CVE ids"]
    errors, seen = [], set()
    for disposition, ids in groups.items():
        if not isinstance(ids, list) or not ids:
            errors.append(f"kernel-baseline: {disposition} must be a non-empty list of CVE ids")
            continue
        for cve in ids:
            if not isinstance(cve, str) or not WAIVER_ID.match(cve.upper()):
                errors.append(f"kernel-baseline: {cve!r} in {disposition} is not one exact CVE id")
            elif cve.upper() in seen:
                errors.append(f"kernel-baseline: {cve} is listed twice")
            else:
                seen.add(cve.upper())
    return errors


def baseline_cves(baseline):
    groups = baseline.get("reviewed-cves") if isinstance(baseline, dict) else None
    if not isinstance(groups, dict):
        return set()
    return {cve.upper() for ids in groups.values() if isinstance(ids, list)
            for cve in ids if isinstance(cve, str)}


def kernel_version_of(sbom):
    for artifact in sbom.get("artifacts", []):
        if artifact.get("type") == KERNEL:
            return artifact.get("version")
    return None


def newer_fix(finding, table):
    """A fix is available only when a fixed version is newer than what ships.

    grype reports state "fixed" even when every fixed version belongs to an
    older branch (libpq 18.6 "fixed in 14.25, …, 17.12"); that is no fix for
    the shipped version. Compare in NVD's terms (glibc 2.42-100 is 2.42).
    """
    if finding.fix_state != "fixed":
        return False
    entry = table.get("packages", {}).get(finding.package) or {}
    installed = version_tuple(nvd_version(entry.get("version", "as-is"), finding.version))
    return any(version_tuple(v.lstrip("*")) > installed for v in finding.fixed)


def classify(finding, threshold, patched, waivers, table):
    if finding.id in patched.get(finding.package, set()):
        return "nix-patched"
    if any(waiver_matches(w, finding, table) for w in waivers):
        return "waived"
    if SEVERITY.get(finding.severity, 0) < threshold:
        return "below-threshold"
    if finding.kind == KERNEL:
        return "blocking" if same_branch_fix(finding.version, finding.fixed) else "kernel-unresolved"
    if "grype" in finding.sources:
        return "blocking" if newer_fix(finding, table) else "no-fix"
    return "blocking"  # vulnix-only: no fix data, so never assume none exists


def row(finding, status):
    entry = {"id": finding.id, "package": finding.package, "version": finding.version,
             "severity": finding.severity, "sources": sorted(finding.sources),
             "fixed": list(finding.fixed), "status": status}
    if finding.kind == KERNEL:
        entry["kernel"] = "same-branch-fix" if same_branch_fix(finding.version, finding.fixed) else "unresolved"
    return entry


def per_package(findings, statuses):
    counts = {}
    for finding, status in zip(findings, statuses):
        if status == "nix-patched":
            continue
        counts.setdefault(finding.package, Counter())[finding.severity] += 1
    return {name: dict(counter) for name, counter in sorted(counts.items())}


def evaluate(grype, vulnix, waivers, patched, sbom, closure, table, today, severity="High", grype_raw=None):
    threshold = SEVERITY[severity]
    findings = collect(grype, vulnix, table)
    patched_sets = {}
    for name, cves in patched.items():
        patched_sets.setdefault(canonical(table, name), set()).update(c.upper() for c in cves)
    entries = waivers.get("waivers", []) if isinstance(waivers.get("waivers"), list) else []
    kernel = kernel_version_of(sbom)
    policy = validate_waivers(waivers, findings, today, kernel, table)
    statuses = [classify(f, threshold, patched_sets, [w for w in entries if isinstance(w.get("id"), str)], table)
                for f in findings]
    unresolved = [row(f, s) for f, s in zip(findings, statuses) if s == "kernel-unresolved"]
    baseline = waivers.get("kernel-baseline")
    if unresolved and baseline is None:
        policy.append(f"{len(unresolved)} kernel matches at or above {severity} have no fix in the "
                      f"{'.'.join(map(str, version_tuple(kernel or '')[:2]))} branch: review them and record a "
                      "kernel-baseline (see docs/src/building/vulnerability-scan.md)")
    elif baseline is not None:
        # The baseline names the reviewed CVEs; a kernel CVE it does not name
        # is unreviewed and blocks, and a name no finding carries is stale.
        reviewed = baseline_cves(baseline)
        found = {r["id"] for r in unresolved}
        missing = sorted(found - reviewed)
        if missing:
            policy.append(f"{len(missing)} kernel matches without a branch fix are not in the reviewed "
                          f"kernel-baseline: {' '.join(missing)}")
        stale = sorted(reviewed - found)
        if stale:
            policy.append(f"kernel-baseline names {len(stale)} CVEs no unresolved kernel match carries "
                          f"(stale; remove them): {' '.join(stale)}")
    coverage = critical_coverage(sbom, closure, table)
    blocking = sorted((row(f, s) for f, s in zip(findings, statuses) if s == "blocking"),
                      key=lambda r: (-SEVERITY.get(r["severity"], 0), r["package"], r["id"]))
    sources = Counter("both" if len(f.sources) == 2 else f"{next(iter(f.sources))}-only" for f in findings)
    summary = Counter(statuses)
    summary.update({"findings": len(findings), "grype-only": sources["grype-only"],
                    "vulnix-only": sources["vulnix-only"], "both": sources["both"]})
    verdict = {
        "pass": not (coverage or policy or blocking),
        "severity-threshold": severity, "kernel": kernel,
        "coverage-errors": coverage, "policy-errors": policy, "blocking": blocking,
        "kernel-unresolved": unresolved,
        "summary": {key: summary.get(key, 0) for key in (
            "findings", "blocking", "waived", "nix-patched", "no-fix", "below-threshold",
            "kernel-unresolved", "grype-only", "vulnix-only", "both")},
        "packages": per_package(findings, statuses),
    }
    if grype_raw is not None:
        raw = collect(grype_raw, [], {"aliases": table["aliases"], "first-party": []})
        verdict["packages-raw-grype"] = per_package(raw, ["open"] * len(raw))
    return verdict


def render(verdict):
    lines = [f"{'package':<28} {'C':>4} {'H':>4} {'M':>4} {'L':>4}   (open = not nix-patched)"]
    ranked = sorted(verdict["packages"].items(),
                    key=lambda kv: (-kv[1].get("Critical", 0), -kv[1].get("High", 0), kv[0]))
    for name, counts in ranked:
        lines.append(f"{name:<28} {counts.get('Critical', 0):>4} {counts.get('High', 0):>4} "
                     f"{counts.get('Medium', 0):>4} {counts.get('Low', 0):>4}")
    for item in verdict["blocking"]:
        lines.append(f"BLOCKING {item['severity']:<8} {item['id']:<20} {item['package']} {item['version']} "
                     f"fixed in {', '.join(item['fixed']) or '?'} [{'+'.join(item['sources'])}]")
    lines += [f"COVERAGE {error}" for error in verdict["coverage-errors"]]
    lines += [f"POLICY {error}" for error in verdict["policy-errors"]]
    lines.append("summary: " + json.dumps(verdict["summary"], sort_keys=True))
    lines.append("verdict: " + ("PASS" if verdict["pass"] else "FAIL"))
    return "\n".join(lines)


# --- patched CVEs and waiver generation -------------------------------------

def patch_names(value):
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def patched_cves(derivations):
    drvs = derivations.get("derivations", derivations)
    result = {}
    for drv in drvs.values():
        if not isinstance(drv, dict):
            continue
        env = drv.get("env") or {}
        attrs = drv.get("structuredAttrs") or {}
        pname = env.get("pname") or attrs.get("pname")
        if not pname:
            name = drv.get("name", "")
            if not name:
                continue
            pname = parse_store_name("/nix/store/" + "0" * 32 + "-" + name)[0]
        names = patch_names(env.get("patches")) + patch_names(attrs.get("patches"))
        cves = {m.upper() for patch in names for m in PATCH_CVE.findall(os.path.basename(patch))}
        if cves:
            result.setdefault(pname, set()).update(cves)
    return {name: sorted(cves) for name, cves in sorted(result.items())}


def waive(verdict, ids, reason, reviewer, today, days):
    if not reason.strip() or not reviewer.strip():
        raise ValueError("a waiver needs a reason and a reviewer")
    if not 0 < days <= MAX_WAIVER_DAYS:
        raise ValueError(f"a waiver lasts 1..{MAX_WAIVER_DAYS} days")
    known = {item["id"]: item for item in verdict.get("blocking", []) + verdict.get("kernel-unresolved", [])}
    entries = []
    for cve in ids:
        item = known.get(cve.upper())
        if item is None:
            raise ValueError(f"{cve} is not a blocking finding of this verdict")
        entries.append({"id": item["id"], "package": item["package"], "reason": reason.strip(),
                        "reviewed-by": reviewer.strip(), "reviewed": today.isoformat(),
                        "expires": (today + timedelta(days=days)).isoformat()})
    return entries


# --- running the scanners ----------------------------------------------------

def tool(command, ok=(0,), **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)
    if result.returncode not in ok:
        raise RuntimeError(f"{command[0]} failed ({result.returncode}): {result.stderr[-2000:]}")
    return result.stdout


def extract_store(image, work, sfdisk, fsck_erofs):
    table = json.loads(tool([sfdisk, "--json", str(image)]))["partitiontable"]
    if table.get("sectorsize", 512) != 512:
        raise RuntimeError("expected 512-byte sectors")
    parts = [p for p in table["partitions"] if p.get("name") == "store"]
    if len(parts) != 1:
        raise RuntimeError("expected exactly one partition named store (slot A)")
    blob = work / "store.erofs"
    with open(image, "rb") as source, open(blob, "wb") as target:
        source.seek(parts[0]["start"] * 512)
        remaining = parts[0]["size"] * 512
        while remaining:
            chunk = source.read(min(remaining, 8 << 20))
            if not chunk:
                raise RuntimeError("image shorter than its partition table")
            target.write(chunk)
            remaining -= len(chunk)
    root = work / "root"
    tool([fsck_erofs, f"--extract={root}", str(blob)])
    blob.unlink()
    if not (root / "nix" / "store").is_dir():
        raise RuntimeError("store partition has no nix/store directory")
    return root


def remove_tree(root):
    # Extracted store directories keep the store's read-only modes.
    for directory, _dirs, _files in os.walk(root):
        os.chmod(directory, 0o700)
    shutil.rmtree(root)


def shipped_toplevel(shipped):
    """The one NixOS system the store partition carries, present locally."""
    systems = [p for p in shipped if parse_store_name(p)[0].startswith("nixos-system-")]
    if len(systems) != 1:
        raise RuntimeError(f"expected one nixos-system-* path in the image, found {len(systems)}")
    if not Path(systems[0]).exists():
        raise RuntimeError(f"{systems[0]} is not in the local store; vulnix needs its derivations")
    return systems[0]


def run(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    table = load_table(args.table)
    with tempfile.TemporaryDirectory(prefix="sentinel-cve-gate-", dir=args.work_dir) as temporary:
        work = Path(temporary)
        root = extract_store(Path(args.image), work, args.sfdisk, args.fsck_erofs) if args.image else Path(args.rootfs)
        shipped = sorted(f"/nix/store/{p.name}" for p in (root / "nix" / "store").iterdir()
                         if not p.name.startswith("."))
        (out / "closure.txt").write_text("\n".join(shipped) + "\n")
        tool([args.syft, f"dir:{root}", "--source-name", "velstra-sentinel-image",
              "-o", f"syft-json={out / 'syft-raw.json'}"], env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"})
        if args.image:
            remove_tree(root)
    raw = json.loads((out / "syft-raw.json").read_text())
    corrected, report = rewrite(raw, table)
    (out / "syft-corrected.json").write_text(json.dumps(corrected))
    (out / "rewrite-report.json").write_text(json.dumps(report, indent=1))
    grype_env = {**os.environ, "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
    for name, sbom in (("grype.json", "syft-corrected.json"), ("grype-raw.json", "syft-raw.json")):
        tool([args.grype, f"sbom:{out / sbom}", "-o", "json", "--file", str(out / name)], env=grype_env)
    # vulnix is the independent second source, never optional: without the
    # toplevel's derivations in the local store the gate refuses to judge.
    toplevel = args.toplevel or shipped_toplevel(shipped)
    vulnix = tool([args.vulnix, "--json", "-C", toplevel], ok=(0, 2)) or "[]"
    (out / "vulnix.json").write_text(vulnix)
    patched = patched_cves(json.loads(tool([args.nix, "derivation", "show", "-r", toplevel])))
    (out / "patched.json").write_text(json.dumps(patched, indent=1))
    verdict = evaluate(json.loads((out / "grype.json").read_text()), json.loads(vulnix),
                       json.loads(Path(args.waivers).read_text()), patched, corrected, shipped, table,
                       date.fromisoformat(args.today) if args.today else date.today(), args.severity,
                       grype_raw=json.loads((out / "grype-raw.json").read_text()))
    verdict["rewrite"] = {"rewritten": report["rewritten"], "unmapped": len(report["unmapped"])}
    return verdict


# --- command line -------------------------------------------------------------

def read_json(path):
    return json.loads(Path(path).read_text())


def finish(verdict, output):
    if output:
        Path(output).write_text(json.dumps(verdict, indent=1, sort_keys=True) + "\n")
    print(render(verdict))
    return 0 if verdict["pass"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("rewrite", help="correct the Nix CPEs of a syft JSON SBOM")
    p.add_argument("--sbom", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--table", default=DEFAULT_TABLE)

    def verdict_options(p):
        p.add_argument("--table", default=DEFAULT_TABLE)
        p.add_argument("--waivers", default=DEFAULT_WAIVERS)
        p.add_argument("--severity", default="High", choices=["Low", "Medium", "High", "Critical"])
        p.add_argument("--today", help="ISO date (default: today); for reproducible reruns")
        p.add_argument("--output", help="write the verdict JSON here")

    p = sub.add_parser("evaluate", help="judge grype + vulnix results; exit 1 on failure")
    p.add_argument("--sbom", required=True, help="the CORRECTED syft JSON that grype scanned")
    p.add_argument("--grype", required=True)
    p.add_argument("--grype-raw", help="grype on the uncorrected SBOM, for the comparison table only")
    p.add_argument("--vulnix", required=True)
    p.add_argument("--closure", required=True, help="shipped store paths, one per line")
    p.add_argument("--patched", help="JSON from the `patched` subcommand")
    verdict_options(p)

    p = sub.add_parser("patched", help="CVE ids named by nixpkgs patch files, per package")
    p.add_argument("--derivations", required=True, help="`nix derivation show -r` JSON")
    p.add_argument("--output", required=True)

    p = sub.add_parser("waive", help="print reviewed per-CVE waiver entries for a verdict")
    p.add_argument("--verdict", required=True)
    p.add_argument("--cve", action="append", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--reviewer", required=True)
    p.add_argument("--days", type=int, default=30)

    p = sub.add_parser("run", help="extract, scan (syft, grype, vulnix) and evaluate one image")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--image", help="the raw disk image; slot A's store partition is scanned")
    source.add_argument("--rootfs", help="a directory that contains nix/store")
    p.add_argument("--toplevel", help="NixOS toplevel for vulnix -C and patch names (default: the one nixos-system-* path in the image)")
    p.add_argument("--out", required=True)
    p.add_argument("--work-dir")
    for name, default in (("syft", "syft"), ("grype", "grype"), ("vulnix", "vulnix"), ("nix", "nix"),
                          ("sfdisk", "sfdisk"), ("fsck-erofs", "fsck.erofs")):
        p.add_argument("--" + name, default=default)
    verdict_options(p)

    args = parser.parse_args(argv)
    try:
        if args.command == "rewrite":
            sbom, report = rewrite(read_json(args.sbom), load_table(args.table))
            Path(args.output).write_text(json.dumps(sbom))
            print(json.dumps(report, sort_keys=True))
            return 0
        if args.command == "patched":
            Path(args.output).write_text(json.dumps(patched_cves(read_json(args.derivations)), indent=1) + "\n")
            return 0
        if args.command == "waive":
            entries = waive(read_json(args.verdict), args.cve, args.reason, args.reviewer, date.today(), args.days)
            print(json.dumps(entries, indent=1))
            return 0
        if args.command == "evaluate":
            closure = [line.strip() for line in Path(args.closure).read_text().splitlines() if line.strip()]
            verdict = evaluate(read_json(args.grype), read_json(args.vulnix), read_json(args.waivers),
                               read_json(args.patched) if args.patched else {}, read_json(args.sbom), closure,
                               load_table(args.table),
                               date.fromisoformat(args.today) if args.today else date.today(), args.severity,
                               grype_raw=read_json(args.grype_raw) if args.grype_raw else None)
            return finish(verdict, args.output)
        out = Path(args.out)
        verdict = run(args)
        return finish(verdict, args.output or out / "verdict.json")
    except (OSError, ValueError, KeyError, RuntimeError, json.JSONDecodeError) as error:
        print(f"CVE gate refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
