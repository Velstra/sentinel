import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "v" + tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load("community_release")
protection = load("check_release_environment")
identity = load("release_identity")
transfer = load("release_transfer")
with patch.dict(sys.modules, {"community_release": release, "check_release_environment": protection}):
    publisher = load("publish_community")


def single_operator_environment(wait_timer=30, reviewers=(), prevent_self_review=False):
    """GitHub's environment shape: one reviewer, a wait timer, custom branches."""
    rules = [{"id": 2, "node_id": "R", "type": "required_reviewers", "prevent_self_review": prevent_self_review,
              "reviewers": list(reviewers) if reviewers != () else
              [{"type": "User", "reviewer": {"login": "owner", "id": 1, "type": "User"}}]},
             {"id": 3, "node_id": "B", "type": "branch_policy"}]
    if wait_timer is not None:
        rules.insert(0, {"id": 1, "node_id": "W", "type": "wait_timer", "wait_timer": wait_timer})
    return {"id": 7, "name": "community-signing", "protection_rules": rules, "can_admins_bypass": False,
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}


class ReleaseTests(unittest.TestCase):
    def test_versions_are_not_shell_or_path_expressions(self):
        self.assertEqual(release.version(VERSION), VERSION)
        self.assertEqual(release.version(VERSION + "-rc.1"), VERSION + "-rc.1")
        for value in ("v01.0.0", VERSION + "/../x", VERSION + ";echo x", VERSION + ".1", VERSION + "-rc.0", VERSION[1:]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                release.version(value)

    def test_partition_layout_cannot_be_silently_converted(self):
        good = {"partitiontable": {"label": "gpt", "sectorsize": 512,
                                  "partitions": [{"name": n} for n in release.LAYOUT]}}
        with patch.object(release, "run", return_value=json.dumps(good)):
            self.assertEqual(len(release.partition_table("disk")), 6)
        good["partitiontable"]["partitions"][2]["name"] = "sentinel_v1.0.0"
        with patch.object(release, "run", return_value=json.dumps(good)), self.assertRaises(ValueError):
            release.partition_table("disk")

    def test_signing_keys_cannot_be_world_readable(self):
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / "db.key"
            key.write_text("test-only")
            key.chmod(0o644)
            with patch.dict(os.environ, {"TEST_KEY": str(key)}), self.assertRaises(ValueError):
                release.secret("TEST_KEY")
            key.chmod(0o600)
            with patch.dict(os.environ, {"TEST_KEY": str(key)}):
                self.assertEqual(release.secret("TEST_KEY"), key)

    def test_artifacts_reject_symlinks_directories_and_large_assets(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            file = directory / "image.iso"
            file.write_bytes(b"test")
            self.assertEqual(release.files(directory), [file])
            link = directory / "escape"
            link.symlink_to(file)
            with self.assertRaises(ValueError): release.files(directory)
            link.unlink()
            with patch.object(release, "ASSET_LIMIT", 4), self.assertRaises(ValueError):
                release.files(directory)

    def test_checksums_reject_added_missing_and_changed_assets(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            item = directory / "image.iso"
            item.write_bytes(b"payload")
            (directory / "SHA256SUMS").write_text(f"{release.digest(item)}  image.iso\n")
            item.write_bytes(b"tamper")
            with self.assertRaisesRegex(ValueError, "inventory/hash"):
                release.verify_bundle(directory)
            item.unlink()
            with self.assertRaisesRegex(ValueError, "inventory/hash"):
                release.verify_bundle(directory)

    def test_environment_requires_real_review_and_restricted_sources(self):
        environment = {"protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "User"}],
                                            "prevent_self_review": True}], "can_admins_bypass": False,
                       "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
        branches = {"total_count": 1, "branch_policies": [{"type": "branch", "name": "main"}]}
        protection.validate(environment, branches)
        for field, value in (("can_admins_bypass", True), ("protection_rules", []), ("deployment_branch_policy", None)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                protection.validate(environment | {field: value}, branches)
        with self.assertRaises(ValueError):
            protection.validate(environment, {"branch_policies": [{"type": "branch", "name": "*"}]})
        with self.assertRaises(ValueError):
            protection.validate(environment, branches | {"total_count": 101})

    def test_protection_api_refuses_truncated_or_paginated_history(self):
        self.assertEqual(protection.response_document('HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n[]'), [])
        for raw in ('[]', 'HTTP/2.0 200 OK\nLink: <next>; rel="next"\n\n[]'):
            with self.assertRaises(ValueError): protection.response_document(raw)

    def test_identity_permissions_and_missing_secrets_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"VELSTRA_GPG_PRIVATE_KEY": "TEST-ONLY"}):
            directory = identity.materialize(temp, "gpg")
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual((directory / "release.asc").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError): identity.materialize(temp, "gpg")

    def test_actual_approval_cannot_be_replaced_by_self_review_or_bypass(self):
        environment = {"id": 7}
        good = {"environments": [{"id": 7}], "state": "approved", "user": {"type": "User", "login": "reviewer"}}
        protection.approval(environment, [good], {"author"})
        for history in ([], [good | {"state": "rejected"}], [good | {"environments": [{"id": 8}]}],
                        [good | {"user": {"type": "User", "login": "author"}}],
                        [good | {"user": {"type": "Bot", "login": "reviewer"}}]):
            with self.subTest(history=history), self.assertRaises(ValueError):
                protection.approval(environment, history, {"author"})

    def test_two_person_mode_is_unchanged_by_single_operator_settings(self):
        # A single-operator environment (self-review allowed) never satisfies the
        # default two-person rule, and the default still refuses self-approval.
        environment, branches = single_operator_environment(), {"total_count": 1,
            "branch_policies": [{"type": "branch", "name": "main"}]}
        with self.assertRaisesRegex(ValueError, "prevent-self-review"):
            protection.validate(environment, branches)
        mine = {"environments": [{"id": 7}], "state": "approved", "user": {"type": "User", "login": "owner"}}
        with self.assertRaisesRegex(ValueError, "independent"):
            protection.approval({"id": 7}, [mine], {"owner"})

    def test_single_operator_mode_is_opt_in_by_exact_value(self):
        for value, expected in (("true", True), ("True", False), ("1", False), ("yes", False),
                                ("", False), ("false", False), (" true", False)):
            with self.subTest(value=value), patch.dict(os.environ, {"RELEASE_SINGLE_OPERATOR": value}):
                self.assertIs(protection.single_operator_enabled(), expected)
        with patch.dict(os.environ):
            os.environ.pop("RELEASE_SINGLE_OPERATOR", None)
            self.assertIs(protection.single_operator_enabled(), False)

    def test_single_operator_mode_accepts_reviewer_wait_timer_and_no_bypass(self):
        self.assertEqual(protection.SINGLE_OPERATOR_MIN_WAIT_MINUTES, 30)
        branches = {"total_count": 2, "branch_policies": [{"type": "branch", "name": "main"},
                                                          {"type": "tag", "name": "v*"}]}
        for environment in (single_operator_environment(),
                            single_operator_environment(prevent_self_review=True),
                            single_operator_environment(wait_timer=43200)):
            with self.subTest(environment=environment):
                protection.validate(environment, branches, single_operator=True)

    def test_single_operator_mode_refuses_weakened_environments(self):
        branches = {"total_count": 1, "branch_policies": [{"type": "branch", "name": "main"}]}
        reviewers = single_operator_environment()["protection_rules"][0]
        cases = {
            "missing wait timer": single_operator_environment(wait_timer=None),
            "short wait timer": single_operator_environment(wait_timer=29),
            "zero wait timer": single_operator_environment(wait_timer=0),
            "boolean wait timer": single_operator_environment(wait_timer=True),
            "string wait timer": single_operator_environment(wait_timer="30"),
            "two wait timers": single_operator_environment() | {"protection_rules":
                single_operator_environment()["protection_rules"] + [{"type": "wait_timer", "wait_timer": 30}]},
            "admin bypass": single_operator_environment() | {"can_admins_bypass": True},
            "no reviewers": single_operator_environment(reviewers=[]),
            "no reviewer rule": single_operator_environment() | {"protection_rules": [
                r for r in single_operator_environment()["protection_rules"] if r["type"] != "required_reviewers"]},
            "two reviewer rules": single_operator_environment() | {"protection_rules":
                single_operator_environment()["protection_rules"] + [reviewers]},
            "no protection": single_operator_environment() | {"protection_rules": []},
        }
        for name, environment in cases.items():
            with self.subTest(case=name), self.assertRaises(ValueError):
                protection.validate(environment, branches, single_operator=True)
        # The branch rules are exactly those of the two-person mode.
        for policy in ({"branch_policies": [{"type": "branch", "name": "*"}]},
                       branches | {"total_count": 101},
                       {"total_count": 1, "branch_policies": [{"type": "tag", "name": "v*"}]}):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                protection.validate(single_operator_environment(), policy, single_operator=True)
        with self.assertRaises(ValueError):
            protection.validate(single_operator_environment() | {"deployment_branch_policy": None},
                                branches, single_operator=True)

    def test_single_operator_approval_may_be_self_but_must_exist(self):
        environment = {"id": 7}
        mine = {"environments": [{"id": 7}], "state": "approved", "user": {"type": "User", "login": "owner"}}
        protection.approval(environment, [mine], {"owner"}, single_operator=True)
        protection.approval(environment, [mine | {"user": {"type": "User", "login": "other"}}], {"owner"},
                            single_operator=True)
        for history in (None, [], [mine | {"state": "rejected"}], [mine | {"state": "pending"}],
                        [mine, mine | {"state": "rejected"}],
                        [mine | {"environments": [{"id": 8}]}], [mine | {"environments": []}],
                        [mine | {"user": {"type": "Bot", "login": "owner"}}],
                        [mine | {"user": {"type": "Organization", "login": "owner"}}],
                        [mine | {"user": {"type": "User"}}], [mine | {"user": {}}], [{"environments": [{"id": 7}]}]):
            with self.subTest(history=history), self.assertRaises(ValueError):
                protection.approval(environment, history, {"owner"}, single_operator=True)

    def test_single_operator_releases_say_so(self):
        with patch.dict(os.environ, {"RELEASE_SINGLE_OPERATOR": "true"}):
            statement = protection.approvals_statement()
        self.assertEqual(statement, "Release approvals: single-operator mode "
                                    "(one maintainer, wait timer \u2265 30 min).")
        with patch.dict(os.environ, {"RELEASE_SINGLE_OPERATOR": "false"}):
            self.assertIsNone(protection.approvals_statement())

    def test_artifact_archive_traversal_symlink_and_size_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for index, name in enumerate(("../outside", "/absolute", "a//b", "a\\b")):
                archive = directory / f"{index}.zip"
                with zipfile.ZipFile(archive, "w") as bundle: bundle.writestr(name, b"data")
                with self.assertRaises(ValueError): transfer.unpack(archive, directory / str(index), 100)
            archive = directory / "valid.zip"
            with zipfile.ZipFile(archive, "w") as bundle: bundle.writestr("receipt.json", b"data")
            with self.assertRaises(ValueError): transfer.unpack(archive, directory / "too-big", 3)
            transfer.unpack(archive, directory / "valid", 4)
            self.assertEqual((directory / "valid/receipt.json").read_bytes(), b"data")
            with zipfile.ZipFile(directory / "symlink.zip", "w") as bundle:
                entry = zipfile.ZipInfo("link")
                entry.create_system = 3
                entry.external_attr = 0o120777 << 16
                bundle.writestr(entry, "../outside")
            with self.assertRaises(ValueError):
                transfer.unpack(directory / "symlink.zip", directory / "link", 100)

    def test_source_check_catalog_rejects_missing_duplicate_and_stale_receipts(self):
        from types import SimpleNamespace
        names = sorted(release.REQUIRED_SAFETY_CHECKS | {"first", "second"})
        with tempfile.TemporaryDirectory() as temp, patch.object(release, "source", return_value="a" * 40), \
                patch.object(release, "run", return_value=json.dumps(names)), \
                patch.dict(os.environ, {"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1"}):
            directory = Path(temp)
            args = SimpleNamespace(input=directory, output=directory / "complete.txt")
            base = {"source": "a" * 40, "run": "42-1", "completed_at": int(time.time())}
            for name in release.REQUIRED_SAFETY_CHECKS:
                (directory / f"{name}.json").write_text(json.dumps(base | {"check": name}))
            (directory / "first.json").write_text(json.dumps(base | {"check": "first"}))
            with self.assertRaises(ValueError): release.aggregate(args)
            (directory / "second.json").write_text(json.dumps(base | {"check": "first"}))
            with self.assertRaises(ValueError): release.aggregate(args)
            (directory / "second.json").write_text(json.dumps(base | {"check": "second", "completed_at": 0}))
            with self.assertRaises(ValueError): release.aggregate(args)
            (directory / "second.json").write_text(json.dumps(base | {"check": "second"}))
            release.aggregate(args)
            self.assertEqual(len(json.loads(args.output.read_text())["checks"]), len(names))

    def test_final_checks_reject_approval_delay_and_changed_catalog(self):
        receipt = {"source": "a" * 40, "run": "42-1", "check": "first", "completed_at": 100000}
        safety_names = sorted(release.REQUIRED_SAFETY_CHECKS)
        safety = [receipt | {"check": name} for name in safety_names]
        with patch.object(release.time, "time", return_value=100001):
            release.validate_checks(safety + [receipt], safety_names + ["first"], "a" * 40, "42-1")
            for receipts, names in (([receipt], ["second"]), (["fixture"], ["first"]),
                                    ([receipt | {"run": "41-1"}], ["first"]),
                                    ([receipt | {"source": "b" * 40}], ["first"]),
                                    ([receipt | {"completed_at": True}], ["first"])):
                with self.subTest(receipts=receipts, names=names), self.assertRaises(ValueError):
                    release.validate_checks(safety + receipts, safety_names + names, "a" * 40, "42-1")
        with patch.object(release.time, "time", return_value=186401), self.assertRaises(ValueError):
            release.validate_checks(safety + [receipt], safety_names + ["first"], "a" * 40, "42-1")

    def test_known_release_blockers_cannot_disappear_from_the_plan_or_receipts(self):
        self.assertTrue({"ha-pair", "ha-two-node", "ha-two-node-flow", "ha-napt-mixed-version"}
                        <= release.REQUIRED_SAFETY_CHECKS)
        names = sorted(release.REQUIRED_SAFETY_CHECKS)
        release.validate_catalog(names + ["future-check"])
        for missing in names:
            reduced = [name for name in names if name != missing]
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "mandatory safety"):
                release.validate_checks([], reduced, "a" * 40, "42-1")
        for malformed in (None, [], [1], names + [names[0]], ["bad/name"], ["x"] * 257):
            with self.subTest(catalog=malformed), self.assertRaises(ValueError):
                release.validate_catalog(malformed)


class RealSignatureTests(unittest.TestCase):
    def test_real_detached_signature_and_wrong_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            keyring, bundle = directory / "gnupg", directory / "bundle"
            keyring.mkdir(mode=0o700)
            bundle.mkdir()
            environment = {"GNUPGHOME": str(keyring), "RELEASE_VERSION": VERSION,
                           "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                           "RELEASE_CHECK_CATALOG": json.dumps({"check": sorted(release.REQUIRED_SAFETY_CHECKS)})}
            with patch.dict(os.environ, environment), patch.object(release, "source", return_value="a" * 40):
                subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                                "--quick-generate-key", "Pipeline test only <test@example.invalid>", "ed25519", "sign", "0"],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                listing = subprocess.check_output(["gpg", "--batch", "--with-colons", "--list-secret-keys"], text=True,
                                                  stderr=subprocess.DEVNULL)
                fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
                prefix = f"velstra-sentinel_{VERSION}_x86_64"
                for name in (f"{prefix}.iso", f"{prefix}.qcow2", f"{prefix}.raw.zst", f"{prefix}.efi", "PK.crt", "KEK.crt", "db.crt", "INSTALL.txt", "source-sbom.cdx.json"):
                    (bundle / name).write_bytes(b"unit fixture, not an image qualification")
                release.document(bundle / "image-evidence.json", {
                    "source": "a" * 40, "version": VERSION, "tested_at": int(time.time()),
                    "raw_sha256": "b" * 64, "compressed_sha256": release.digest(bundle / f"{prefix}.raw.zst"),
                    "disk_secure_boot": True, "installer_secure_boot": False,
                    "qcow2_byte_equivalent": True, "iso_embedded_raw_verified": True})
                release.document(bundle / "release-image-boot.json", {
                    "complete": True, "boots": [{"number": 1}, {"number": 2}],
                    "expected_sha256": "b" * 64, "source_sha256_before": "b" * 64, "source_sha256_after": "b" * 64,
                    "certificate_sha256": {n: release.digest(bundle / f"{n}.crt") for n in ("PK", "KEK", "db")}})
                release.document(bundle / "source-checks.json", {"source": "a" * 40, "run": "123-1", "checks": [
                    {"source": "a" * 40, "run": "123-1", "check": name, "completed_at": int(time.time())}
                    for name in sorted(release.REQUIRED_SAFETY_CHECKS)]})
                release.document(bundle / "source-sbom.provenance.json", {"source_commit": "a" * 40,
                    "scope": "source-lockfiles", "sbom_sha256": release.digest(bundle / "source-sbom.cdx.json")})
                with patch.object(release, "run", side_effect=AssertionError("pre-sign validation must not call GPG")):
                    release.validate_bundle(bundle)
                (bundle / "SHA256SUMS").write_text("".join(f"{release.digest(p)}  {p.name}\n" for p in release.files(bundle)))
                subprocess.run(["gpg", "--batch", "--detach-sign", "--output", str(bundle / "SHA256SUMS.gpg"), str(bundle / "SHA256SUMS")], check=True)
                with patch.dict(os.environ, {"VELSTRA_GPG_FINGERPRINT": fingerprint}):
                    release.verify_bundle(bundle)
                with patch.dict(os.environ, {"VELSTRA_GPG_FINGERPRINT": "0" * 40}), self.assertRaisesRegex(ValueError, "identity"):
                    release.verify_bundle(bundle)
                (bundle / f"{prefix}.iso").write_bytes(b"changed")
                with patch.dict(os.environ, {"VELSTRA_GPG_FINGERPRINT": fingerprint}), self.assertRaisesRegex(ValueError, "inventory/hash"):
                    release.verify_bundle(bundle)
                subprocess.run(["gpgconf", "--kill", "all"], check=True)


class PublicationContracts(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main", "RELEASE_PUBLISH_REQUESTED": "true", "GITHUB_RUN_ATTEMPT": "1"})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_direct_publisher_rejects_unrequested_or_retry_runs_before_api(self):
        for key, value in (("GITHUB_EVENT_NAME", "push"), ("GITHUB_REF", "refs/heads/feature"),
                           ("RELEASE_PUBLISH_REQUESTED", "false"), ("GITHUB_RUN_ATTEMPT", "2")):
            with patch.dict(os.environ, {key: value}), patch.object(publisher, "api") as api, \
                    self.subTest(key=key), self.assertRaises(ValueError):
                publisher.publish(Path("unused"))
            api.assert_not_called()

    def test_ancestry_is_rechecked_after_waiting_for_approval(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(publisher, "verify_bundle"), \
                patch.object(publisher, "source", return_value="a" * 40), \
                patch.object(publisher, "api", return_value={"status": "diverged"}) as api, \
                patch.dict(os.environ, {"RELEASE_VERSION": VERSION, "GITHUB_REPOSITORY": "Velstra/sentinel"}):
            with self.assertRaisesRegex(ValueError, "no longer on main"):
                publisher.publish(Path(temp))
            self.assertEqual(api.call_count, 1)

    def test_existing_release_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(publisher, "verify_bundle"), \
                patch.object(publisher, "source", return_value="a" * 40), \
                patch.object(publisher, "api", side_effect=[{"status": "ahead"}, {"id": 7}]) as api, \
                patch.dict(os.environ, {"RELEASE_VERSION": VERSION, "GITHUB_REPOSITORY": "Velstra/sentinel"}):
            with self.assertRaisesRegex(ValueError, "already exists"):
                publisher.publish(Path(temp))
            self.assertEqual(api.call_count, 2)

    def test_wrong_existing_tag_cannot_publish(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(publisher, "verify_bundle"), \
                patch.object(publisher, "source", return_value="a" * 40), \
                patch.object(publisher, "api", side_effect=[{"status": "identical"}, None, {"object": {"type": "commit", "sha": "b" * 40}}]) as api, \
                patch.dict(os.environ, {"RELEASE_VERSION": VERSION, "GITHUB_REPOSITORY": "Velstra/sentinel"}):
            with self.assertRaisesRegex(ValueError, "qualified source"):
                publisher.publish(Path(temp))
            self.assertEqual(api.call_count, 3)

    def test_failed_readback_leaves_a_draft_without_publishing(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(publisher, "verify_bundle"), \
                patch.object(publisher, "source", return_value="a" * 40), \
                patch.object(publisher, "api", side_effect=[{"status": "identical"}, None, None, {"id": 7, "draft": True, "tag_name": VERSION}]) as api, \
                patch.object(publisher.subprocess, "run"), \
                patch.dict(os.environ, {"RELEASE_VERSION": VERSION, "GITHUB_REPOSITORY": "Velstra/sentinel"}):
            directory = Path(temp)
            (directory / "fixture.iso").write_bytes(b"not a real ISO")
            with self.assertRaisesRegex(ValueError, "draft retained"):
                publisher.publish(directory)
            self.assertEqual(api.call_count, 4)
            self.assertEqual(api.call_args.kwargs["method"], "POST")
            self.assertTrue(api.call_args.args[1]["draft"])

    def draft_body(self, extra):
        with tempfile.TemporaryDirectory() as temp, patch.object(publisher, "verify_bundle"), \
                patch.object(publisher, "source", return_value="a" * 40), \
                patch.object(publisher, "api", side_effect=[{"status": "identical"}, None, None, {"id": 7, "draft": True, "tag_name": VERSION}]) as api, \
                patch.object(publisher.subprocess, "run"), \
                patch.dict(os.environ, {"RELEASE_VERSION": VERSION, "GITHUB_REPOSITORY": "Velstra/sentinel"} | extra):
            directory = Path(temp)
            (directory / "fixture.iso").write_bytes(b"not a real ISO")
            with self.assertRaisesRegex(ValueError, "draft retained"):
                publisher.publish(directory)
            return api.call_args.args[1]["body"]

    def test_release_body_records_single_operator_mode(self):
        default = self.draft_body({"RELEASE_SINGLE_OPERATOR": ""})
        self.assertNotIn("single-operator", default)
        self.assertTrue(default.endswith("no physical-hardware certification is claimed."))
        single = self.draft_body({"RELEASE_SINGLE_OPERATOR": "true"})
        self.assertEqual(single, default + "\n\nRelease approvals: single-operator mode "
                                           "(one maintainer, wait timer \u2265 30 min).")

    def test_cross_run_artifact_is_refused_before_download(self):
        metadata = {"expired": False, "workflow_run": {"id": 1, "head_sha": "a" * 40},
                    "digest": "sha256:" + "b" * 64, "size_in_bytes": 100}
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(transfer.subprocess, "check_output", return_value=json.dumps(metadata)), \
                patch.object(transfer.subprocess, "run") as download, \
                patch.dict(os.environ, {"GITHUB_REPOSITORY": "Velstra/sentinel", "GITHUB_RUN_ID": "2",
                                        "GITHUB_SHA": "a" * 40, "RELEASE_ARTIFACT_BYTE_BUDGET": "1000"}):
            with self.assertRaisesRegex(ValueError, "another run"):
                transfer.download("123", "b" * 64, Path(temp) / "output")
            download.assert_not_called()


if __name__ == "__main__": unittest.main()
