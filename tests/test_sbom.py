import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "generate_sbom", Path(__file__).resolve().parents[1] / "scripts/generate_sbom.py"
)
sbom = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sbom)


class SourceSbomTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        (self.source / "ui").mkdir(parents=True)
        for name, contents in {
            "Cargo.toml": '[package]\nname="sentinel"\nversion="1.0.0"\n',
            "Cargo.lock": 'version = 4\n[[package]]\nname="serde"\nversion="1.0.0"\n',
            "ui/package.json": '{"name":"sentinel-ui","version":"1.0.0"}',
            "ui/package-lock.json": '{"lockfileVersion":3,"packages":{"node_modules/react":{"version":"19.0.0"}}}',
        }.items():
            (self.source / name).write_text(contents)
        self.output = self.root / "output"
        self.bom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [
                {"type": "library", "name": "serde", "version": "1.0.0", "purl": "pkg:cargo/serde@1.0.0"},
                {"type": "library", "name": "react", "version": "19.0.0", "purl": "pkg:npm/react@19.0.0"},
            ],
        }
        self.seen = []

    def scan(self, argv, **kwargs):
        self.seen.append((argv, kwargs))
        catalog = Path(argv[1].removeprefix("dir:"))
        names = {str(path.relative_to(catalog)) for path in catalog.rglob("*") if path.is_file()}
        self.assertEqual(names, set(sbom.INPUTS))
        self.assertEqual(Path(argv[argv.index("--config") + 1]).read_text(), sbom.SYFT_CONFIG)
        self.assertIn("include-dev-dependencies: true", sbom.SYFT_CONFIG)
        self.assertFalse(any(key.startswith("SYFT_") and key != "SYFT_CHECK_FOR_APP_UPDATE"
                             for key in kwargs["env"]))
        destination = Path(argv[-1].removeprefix("cyclonedx-json@1.6="))
        destination.write_text(json.dumps(self.bom))

    def generate(self, scanner=None):
        with patch.object(sbom, "revision", return_value="a" * 40), \
                patch.object(sbom.subprocess, "run", side_effect=scanner or self.scan):
            return sbom.generate(self.source, self.output, "test-syft")

    def test_generated_cyclonedx_has_hashes_commit_and_explicit_source_only_scope(self):
        result = self.generate()
        self.assertEqual(result["source_commit"], "a" * 40)
        self.assertEqual(result["scope"], "source-lockfiles")
        self.assertFalse(result["image_certification"])
        self.assertEqual(result["ecosystems"], {"cargo": 1, "npm": 1})
        body = (self.output / "sbom.cdx.json").read_bytes()
        self.assertEqual(result["sbom_sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(json.loads((self.output / "sbom.provenance.json").read_text()), result)
        for line in (self.output / "SHA256SUMS").read_text().splitlines():
            expected, name = line.split("  ")
            self.assertEqual(expected, hashlib.sha256((self.output / name).read_bytes()).hexdigest())
        self.assertIn({"name": "velstra:scope", "value": "source-lockfiles"},
                      json.loads(body)["metadata"]["properties"])

    def test_build_artifacts_untracked_files_and_private_configuration_are_not_cataloged(self):
        for name in ("target/Cargo.lock", "work/private.key", ".syft.yaml", "node_modules/secret.json"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("PRIVATE-MARKER")
        with patch.dict(os.environ, {"SYFT_EXCLUDE": "**", "SYFT_CONFIG": "/private/config"}):
            self.generate()
        self.assertNotIn("PRIVATE-MARKER", (self.output / "sbom.cdx.json").read_text())

    def test_existing_output_is_never_overwritten(self):
        self.output.mkdir()
        marker = self.output / "old-evidence"
        marker.write_text("retain")
        with self.assertRaises(FileExistsError):
            self.generate()
        self.assertEqual(marker.read_text(), "retain")
        self.assertFalse(self.seen)

    def test_direct_and_parent_symlink_inputs_are_rejected(self):
        lock = self.source / "Cargo.lock"
        lock.rename(self.root / "outside-lock")
        lock.symlink_to(self.root / "outside-lock")
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            sbom.snapshot(self.source)
        lock.unlink()
        lock.write_text("restored")
        (self.source / "ui").rename(self.root / "outside-ui")
        (self.source / "ui").symlink_to(self.root / "outside-ui", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            sbom.snapshot(self.source)

    def test_empty_and_partial_ecosystem_catalogs_never_publish(self):
        for components in ([], self.bom["components"][:1], self.bom["components"][1:]):
            with self.subTest(components=components):
                candidate = dict(self.bom, components=components)
                with self.assertRaises(ValueError):
                    sbom.validate_bom(candidate)

    def test_wrong_format_and_malformed_components_are_rejected(self):
        for candidate in ({}, dict(self.bom, bomFormat="SPDX"), dict(self.bom, specVersion="99"),
                          dict(self.bom, components="wrong"), dict(self.bom, components=[{}]),
                          dict(self.bom, components=[True])):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                sbom.validate_bom(candidate)

    def test_valid_private_application_without_optional_purl_is_preserved(self):
        self.bom["components"].append({"type": "application", "name": "sentinel-ui"})
        result = self.generate()
        self.assertEqual(result["ecosystems"], {"cargo": 1, "npm": 1})
        self.assertEqual(result["component_count"], 3)

    def test_missing_dev_dependency_cannot_hide_behind_nonempty_npm_catalog(self):
        lock = self.source / "ui/package-lock.json"
        value = json.loads(lock.read_text())
        value["packages"]["node_modules/vitest"] = {"version": "4.0.0", "dev": True}
        lock.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "incomplete npm lock coverage.*vitest"):
            self.generate()
        self.assertFalse((self.output / "sbom.cdx.json").exists())

    def test_wrong_version_and_wrong_ecosystem_cannot_cover_a_locked_package(self):
        inputs = sbom.snapshot(self.source)
        for change in ({"version": "0.0.0"}, {"purl": "pkg:npm/serde@1.0.0"}):
            with self.subTest(change=change):
                candidate = json.loads(json.dumps(self.bom))
                candidate["components"][0].update(change)
                with self.assertRaisesRegex(ValueError, "incomplete cargo|package URL|dependency catalogs"):
                    sbom.validate_lock_coverage(candidate, inputs)

    def test_nested_scoped_packages_and_multiple_versions_are_all_required(self):
        inputs = sbom.snapshot(self.source)
        inputs["ui/package-lock.json"] = json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "private-ui"},
            "node_modules/@scope/tool": {"version": "1.0.0"},
            "node_modules/parent/node_modules/@scope/tool": {"version": "2.0.0", "dev": True},
        }}).encode()
        candidate = json.loads(json.dumps(self.bom))
        for version in ("1.0.0", "2.0.0"):
            candidate["components"].append({"type": "library", "name": "@scope/tool", "version": version,
                                            "purl": "pkg:npm/%40scope/tool@" + version})
        self.assertEqual(sbom.validate_lock_coverage(candidate, inputs), {"cargo": 1, "npm": 2})
        candidate["components"].pop()
        with self.assertRaisesRegex(ValueError, "incomplete npm"):
            sbom.validate_lock_coverage(candidate, inputs)

    def test_empty_and_linked_locks_are_not_complete_inventory(self):
        for body in (b'{"lockfileVersion":3,"packages":{}}',
                     b'{"lockfileVersion":3,"packages":{"node_modules/local":{"link":true}}}'):
            inputs = sbom.snapshot(self.source)
            inputs["ui/package-lock.json"] = body
            with self.subTest(body=body), self.assertRaises(ValueError):
                sbom.validate_lock_coverage(self.bom, inputs)

    def test_local_cargo_without_registry_purl_requires_exact_lock_attribution(self):
        component = self.bom["components"][0]
        component.pop("purl")
        # A registry dependency remains; the local project is not itself
        # evidence of the required versioned ecosystem catalog.
        self.bom["components"].append({"type": "library", "name": "other", "version": "2.0.0",
                                       "purl": "pkg:cargo/other@2.0.0"})
        inputs = sbom.snapshot(self.source)
        with self.assertRaisesRegex(ValueError, "incomplete cargo"):
            sbom.validate_lock_coverage(self.bom, inputs)
        component["properties"] = [
            {"name": "syft:package:foundBy", "value": "rust-cargo-lock-cataloger"},
            {"name": "syft:location:0:path", "value": "/Cargo.lock"},
        ]
        self.assertEqual(sbom.validate_lock_coverage(self.bom, inputs), {"cargo": 1, "npm": 1})

    def test_matching_display_identity_cannot_conceal_an_unrelated_purl(self):
        for purl in ("pkg:cargo/unrelated@99.0.0", "pkg:cargo/serde@2.0.0",
                     "pkg:cargo/serde", "pkg:cargo/ser%GGe@1.0.0"):
            candidate = json.loads(json.dumps(self.bom))
            candidate["components"][0]["purl"] = purl
            with self.subTest(purl=purl), self.assertRaisesRegex(ValueError, "package URL"):
                sbom.validate_lock_coverage(candidate, sbom.snapshot(self.source))

    def test_source_change_during_scan_prevents_publication(self):
        def changed(argv, **kwargs):
            self.scan(argv, **kwargs)
            (self.source / "Cargo.lock").write_text("changed during cataloging")
        with self.assertRaisesRegex(ValueError, "changed during"):
            self.generate(changed)
        self.assertFalse((self.output / "sbom.cdx.json").exists())

    def test_scanner_failure_and_timeout_do_not_publish_partial_evidence(self):
        for exception in (subprocess.CalledProcessError(1, "syft"), subprocess.TimeoutExpired("syft", 180)):
            with self.subTest(exception=type(exception).__name__):
                self.output = self.root / type(exception).__name__
                def failed(*args, **kwargs):
                    raise exception
                with self.assertRaises(type(exception)):
                    self.generate(failed)
                self.assertEqual(list(self.output.iterdir()), [])

    def test_changed_lockfile_cannot_borrow_a_clean_commit_identity(self):
        def captured(argv, **kwargs):
            if "rev-parse" in argv:
                return "a" * 40 + "\n"
            return b"not-the-actual-lockfile"
        with patch.object(sbom.subprocess, "check_output", side_effect=captured), \
                self.assertRaisesRegex(ValueError, "differs from source commit"):
            sbom.revision(self.source)

    def test_real_git_clean_dirty_staged_and_merge_commit_identities(self):
        def git(*args):
            # Disposable local fixture commits only: never touch the user's
            # signing/hook configuration or use this override for publication.
            result = subprocess.run(
                ["git", "-C", str(self.source), "-c", "commit.gpgsign=false",
                 "-c", "core.hooksPath=/dev/null", "-c", "user.name=SBOM fixture",
                 "-c", "user.email=sbom-fixture@example.invalid", *args],
                check=True, capture_output=True, text=True, timeout=15,
            )
            return result.stdout.strip()

        git("init", "--quiet", "--initial-branch=main")
        git("add", "--", *sbom.INPUTS)
        git("commit", "--quiet", "-m", "initial fixture")
        clean = git("rev-parse", "HEAD")
        self.assertEqual(sbom.revision(self.source), clean)
        (self.source / "Cargo.lock").write_text("version = 4\n# changed\n")
        with self.assertRaisesRegex(ValueError, "differs from source commit"):
            sbom.revision(self.source)
        git("add", "--", "Cargo.lock")
        with self.assertRaisesRegex(ValueError, "differs from source commit"):
            sbom.revision(self.source)
        git("commit", "--quiet", "-m", "changed fixture lock")
        git("switch", "--quiet", "-c", "pr-fixture")
        (self.source / "unrelated.txt").write_text("not a catalog input\n")
        git("add", "--", "unrelated.txt")
        git("commit", "--quiet", "-m", "fixture branch")
        git("switch", "--quiet", "main")
        git("merge", "--quiet", "--no-ff", "pr-fixture", "-m", "synthetic PR merge fixture")
        merged = git("rev-parse", "HEAD")
        self.assertNotEqual(merged, clean)
        self.assertEqual(sbom.revision(self.source), merged)


if __name__ == "__main__":
    unittest.main()
