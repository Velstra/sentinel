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
            "Cargo.lock": 'version = 4\n',
            "ui/package.json": '{"name":"sentinel-ui","version":"1.0.0"}',
            "ui/package-lock.json": '{"lockfileVersion":3}',
        }.items():
            (self.source / name).write_text(contents)
        self.output = self.root / "output"
        self.bom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [
                {"type": "library", "name": "serde", "purl": "pkg:cargo/serde@1.0.0"},
                {"type": "library", "name": "react", "purl": "pkg:npm/react@19.0.0"},
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
