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


attempts = load("release_attempts")
with patch.dict(sys.modules, {"release_attempts": attempts}):
    release = load("community_release")
    protection = load("check_release_environment")
identity = load("release_identity")
transfer = load("release_transfer")
with patch.dict(sys.modules, {"community_release": release, "check_release_environment": protection,
                              "release_attempts": attempts}):
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
                        [mine, mine | {"state": "pending"}], [mine | {"user": {"type": "User", "login": 7}}],
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
                patch.dict(os.environ, {"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1",
                                        "RELEASE_REGRESSION_RUNNER": "github"}):
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


class StallWatchdogTests(unittest.TestCase):
    """A regression build that prints nothing for the stall limit is killed and
    run once more; a build that fails is never run again."""

    def test_output_is_forwarded_and_stdout_returned(self):
        stdout = release.run_watched(["sh", "-c", "echo log >&2; echo /nix/store/x"], os.environ, 30)
        self.assertEqual(stdout, "/nix/store/x")

    def test_a_silent_build_is_killed_with_its_whole_process_group(self):
        with tempfile.TemporaryDirectory() as temp:
            pid_file = Path(temp) / "child"
            start = time.monotonic()
            with self.assertRaises(release.Stalled):
                release.run_watched(["sh", "-c", f"sleep 60 & echo $! > {pid_file}; wait"],
                                    os.environ, 1, poll=0.1)
            self.assertLess(time.monotonic() - start, 15)
            child = int(pid_file.read_text())
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and Path(f"/proc/{child}").exists():
                time.sleep(0.1)
            self.assertFalse(Path(f"/proc/{child}").exists(), "the stalled build's child survived")

    def test_a_failing_build_is_a_failure_not_a_stall(self):
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            release.run_watched(["sh", "-c", "echo broken >&2; exit 3"], os.environ, 30)
        self.assertEqual(failure.exception.returncode, 3)

    def test_steady_output_never_counts_as_a_stall(self):
        # A byte that is not UTF-8 (compiler and test logs have them) must
        # neither stop the forwarding nor count as silence.
        stdout = release.run_watched(
            ["sh", "-c", "printf 'bad \\377 byte\\n' >&2; "
                         "for i in 1 2 3 4 5 6; do echo tick >&2; sleep 0.3; done; echo /nix/store/y"],
            os.environ, 1, poll=0.1)
        self.assertEqual(stdout, "/nix/store/y")

    def test_a_stall_is_retried_once_and_recorded(self):
        with patch.object(release, "run_watched", side_effect=[release.Stalled("silent"), "/nix/store/z"]) as run, \
                patch("sys.stdout", new_callable=__import__("io").StringIO) as out:
            path, stalls = release.build_check("expr", SENTINEL_CHECK="nat")
        self.assertEqual((str(path), stalls, run.call_count), ("/nix/store/z", 1, 2))
        self.assertIn("::warning", out.getvalue())
        self.assertIn("nat", out.getvalue())

    def test_a_second_stall_fails_the_check(self):
        with patch.object(release, "run_watched", side_effect=[release.Stalled("a"), release.Stalled("b")]) as run, \
                patch("sys.stdout", new_callable=__import__("io").StringIO):
            with self.assertRaises(release.Stalled):
                release.build_check("expr", SENTINEL_CHECK="nat")
        self.assertEqual(run.call_count, 2)

    def test_a_failed_check_is_never_retried(self):
        failure = subprocess.CalledProcessError(1, ["nix", "build"])
        with patch.object(release, "run_watched", side_effect=[failure, "/nix/store/never"]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                release.build_check("expr", SENTINEL_CHECK="nat")
        self.assertEqual(run.call_count, 1)

    def test_a_clean_build_records_no_retry(self):
        with patch.object(release, "run_watched", return_value="/nix/store/w"):
            self.assertEqual(release.build_check("expr", SENTINEL_CHECK="nat")[1], 0)

    def test_receipts_carry_at_most_one_stall_retry(self):
        names = sorted(release.REQUIRED_SAFETY_CHECKS)
        base = {"source": "a" * 40, "run": "42-1", "completed_at": int(time.time())}
        receipts = [base | {"check": n} for n in names]
        release.validate_checks(receipts, names, "a" * 40, "42-1")
        release.validate_checks([receipts[0] | {"stall_retries": 1}] + receipts[1:], names, "a" * 40, "42-1")
        for bad in (2, -1, "1", True, None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                release.validate_checks([receipts[0] | {"stall_retries": bad}] + receipts[1:],
                                        names, "a" * 40, "42-1")

    def test_release_builds_are_watched_like_checks(self):
        # The image, the installer ISO and the boot gate are long Nix builds
        # too; package once spent 2.5 h on a log that had stopped moving.
        with patch.object(release, "run_watched", side_effect=[release.Stalled("silent"), "/nix/store/iso"]) as run, \
                patch("sys.stdout", new_callable=__import__("io").StringIO) as out:
            path, stalls = release.build("expr", "installer ISO", SENTINEL_RELEASE_VERSION="1.0.0")
        self.assertEqual((str(path), stalls, run.call_count), ("/nix/store/iso", 1, 2))
        command, env, limit = run.call_args.args
        self.assertEqual(command, release.nix_build_command("expr"))
        self.assertEqual((env["SENTINEL_RELEASE_VERSION"], env["SENTINEL_RELEASE_SOURCE"], limit),
                         ("1.0.0", str(release.ROOT), release.STALL_SECONDS))
        self.assertIn("::warning", out.getvalue())
        self.assertIn("installer ISO", out.getvalue())
        with patch.object(release, "run_watched", side_effect=[release.Stalled("a"), release.Stalled("b")]) as run, \
                patch("sys.stdout", new_callable=__import__("io").StringIO) as out:
            with self.assertRaises(release.Stalled):
                release.build("expr", "boot gate")
        self.assertEqual(run.call_count, 2)
        self.assertIn("::error", out.getvalue())
        self.assertIn("boot gate", out.getvalue())
        failure = subprocess.CalledProcessError(1, ["nix", "build"])
        with patch.object(release, "run_watched", side_effect=[failure, "/nix/store/never"]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                release.build("expr", "image build")
        self.assertEqual(run.call_count, 1, "a failed build is never retried")

    def test_build_stall_retries_travel_with_the_image(self):
        self.assertEqual(release.stall_retries({}), 0)
        self.assertEqual(release.stall_retries({"stall_retries": 1}), 1)
        for bad in (2, -1, True, "1", None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                release.stall_retries({"stall_retries": bad})
        self.assertEqual(release.BUILD_STAGES, ("image-build", "installer-iso", "boot-gate"))
        good = {"image-build": 0, "installer-iso": 1, "boot-gate": 0}
        self.assertEqual(release.build_stalls({"stall_retries": good}), good)
        for bad in (None, {}, {"image-build": 0}, good | {"boot-gate": 2}, good | {"boot-gate": True},
                    good | {"sign": 0}, [0, 1, 0]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                release.build_stalls({"stall_retries": bad})


FIXTURES = ROOT / "tests/fixtures/run-45642647509"
# Release run 45868284650: two regressions failed in attempt 1; attempt 2 re-ran
# both (they passed), sign passed and package failed in its boot gate. The
# approval history is GitHub's, with the maintainer's login replaced.
PACKAGE_FAILED = ROOT / "tests/fixtures/run-45868284650"
DOWNSTREAM = ("sign", "package", "seal", "publish")


def real_jobs(name, fixtures=FIXTURES):
    """A job listing GitHub returned for a release run."""
    return json.loads((fixtures / name).read_text())["jobs"]


def job(name, conclusion, run_attempt=1, number=None, started="2026-11-25T15:13:10Z"):
    """One entry of GitHub's attempt job listing; a skipped job never had a runner."""
    number = number if number is not None else abs(hash((name, run_attempt, started))) % 10**9
    runner = conclusion != "skipped"
    return {"id": number, "name": name, "status": "completed", "conclusion": conclusion,
            "run_attempt": run_attempt, "started_at": started, "completed_at": started.replace("15:", "16:"),
            "runner_id": number if runner else None, "runner_name": f"GitHub Actions {number}" if runner else None,
            "html_url": f"https://github.com/Velstra/sentinel/actions/runs/42/job/{number}"}


def first_attempt(failed=("rip",), passed=("nat", "commit"), overrides=None, downstream=None):
    """Attempt 1: the `failed` regressions failed; downstream jobs as given,
    else skipped."""
    first = [job("plan", "success"), job("build", "success")]
    first += [job(f"regressions ({c})", "success") for c in passed]
    first += [job(f"regressions ({c})", "failure") for c in failed]
    first += [job(n, (downstream or {}).get(n, "skipped")) for n in DOWNSTREAM]
    for name, change in (overrides or {}).items():
        next(j for j in first if j["name"] == name).update(change)
    return first


def again(previous, number, fresh=(), overrides=None):
    """Attempt `number` as "Re-run failed jobs" lists it after `previous`, the
    way GitHub really does: every job that passed again, with a new id and this
    run_attempt but its old times; a skipped job is not listed until it is
    created again. `fresh` names the (job, conclusion) entries it ran anew."""
    listing = [entry | {"id": entry["id"] + 1, "run_attempt": number}
               for entry in previous if entry["conclusion"] == "success" and not attempts.phantom(entry)]
    listing += [job(name, conclusion, number, started=f"2026-11-2{4 + number}T20:23:13Z")
                for name, conclusion in fresh]
    for name, change in (overrides or {}).items():
        next(j for j in listing if j["name"] == name).update(change)
    return listing


def listings(failed=("rip",), passed=("nat", "commit"), first_overrides=None, second_overrides=None):
    """Attempt 1 with failed regressions, and the attempt 2 that re-ran them
    (they passed); downstream jobs are not listed yet."""
    first = first_attempt(failed, passed, first_overrides)
    return first, again(first, 2, [(f"regressions ({c})", "success") for c in failed], second_overrides)


def named(listing, name, status=None):
    return next(j for j in listing if j["name"] == name and (status is None or j["status"] == status))


class ReRunPolicyTests(unittest.TestCase):
    """The owner allows "Re-run failed jobs" up to attempt 3, for jobs that
    failed. Whatever passed is carried over unchanged into every later attempt,
    and an environment job that runs again needs an approval of its own."""

    def test_only_attempts_one_to_three_are_accepted(self):
        self.assertEqual(attempts.MAX_ATTEMPT, 3)
        for value in ("1", "2", "3"):
            with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": value}):
                self.assertEqual(attempts.attempt(), int(value))
        for value in ("4", "0", "", "2a", "03"):
            with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": value}), self.subTest(value=value), \
                    self.assertRaises(ValueError):
                attempts.attempt()

    def test_a_failed_regression_may_run_once_more(self):
        first, second = listings(failed=("rip", "reboot"))
        found = attempts.review([first, second])["reruns"]
        self.assertEqual(sorted(found), ["regressions (reboot)", "regressions (rip)"])
        rip = found["regressions (rip)"]
        self.assertEqual(rip["job"], named(first, "regressions (rip)"))
        self.assertEqual((rip["failed_in"], rip["attempts"], rip["runs"], rip["phantoms"]), (1, [2], 1, 0))

    def test_a_regression_may_fail_twice_and_pass_in_attempt_three(self):
        first, second = listings(second_overrides={"regressions (rip)": {"conclusion": "failure"}})
        with self.assertRaisesRegex(ValueError, "rip"):
            attempts.require_green(attempts.review([first, second]))
        third = again(second, 3, [("regressions (rip)", "success")])
        history = attempts.review([first, second, third])
        attempts.require_green(history)
        rip = history["reruns"]["regressions (rip)"]
        self.assertEqual(rip["job"], named(first, "regressions (rip)"), "the first failure is reported")
        self.assertEqual((rip["failed_in"], rip["attempts"], rip["runs"]), (1, [2, 3], 2))
        self.assertEqual(history["latest"]["regressions (rip)"]["attempt"], 3)
        self.assertEqual(history["latest"]["regressions (nat)"]["attempt"], 1)
        third_failed = again(second, 3, [("regressions (rip)", "failure")])
        with self.assertRaisesRegex(ValueError, "rip"):
            attempts.require_green(attempts.review([first, second, third_failed]))

    def test_a_timed_out_regression_counts_as_failed(self):
        first, second = listings(first_overrides={"regressions (rip)": {"conclusion": "timed_out"}})
        self.assertEqual(attempts.review([first, second])["reruns"]["regressions (rip)"]["attempts"], [2])

    def test_a_failed_build_may_be_built_again(self):
        first = first_attempt(failed=(), overrides={"build": {"conclusion": "failure"}})
        history = attempts.review([first, again(first, 2, [("build", "success")])])
        self.assertEqual(history["reruns"]["build"]["attempts"], [2])
        attempts.require_green(history)
        with self.assertRaisesRegex(ValueError, "build"):
            attempts.require_green(attempts.review([first, again(first, 2, [("build", "failure")])]))

    def test_the_real_package_failure_of_run_45868284650_may_run_again(self):
        first, second = real_jobs("attempt-1.json", PACKAGE_FAILED), real_jobs("attempt-2.json", PACKAGE_FAILED)
        history = attempts.review([first, second])
        self.assertEqual(sorted(history["reruns"]),
                         ["regressions (data-status-readonly)", "regressions (install-boot-raid1)"])
        self.assertEqual(history["latest"]["package"]["conclusion"], "failure")
        attempts.require_green(history)
        # Attempt 3 runs the package job again; sign, which passed, is kept.
        third = again(second, 3, [("package", "success")])
        history = attempts.review([first, second, third])
        package = history["reruns"]["package"]
        self.assertEqual((package["failed_in"], package["attempts"], package["runs"]), (2, [3], 1))
        self.assertEqual(package["job"], named(second, "package"))
        self.assertEqual(history["reruns"]["regressions (install-boot-raid1)"]["attempts"], [2])
        self.assertEqual({n: history["runs"][n] for n in DOWNSTREAM},
                         {"sign": 1, "package": 2, "seal": 0, "publish": 0})
        self.assertEqual({n: history["latest"][n]["attempt"] for n in ("plan", "build", "sign", "package")},
                         {"plan": 1, "build": 1, "sign": 2, "package": 3})
        sealed = third + [job("seal", "success", 3, started="2026-11-27T21:00:00Z")]
        self.assertEqual(attempts.review([first, second, sealed])["runs"]["seal"], 1)
        resigned = again(second, 3, [("package", "success"), ("sign", "success")])
        with self.assertRaisesRegex(ValueError, "sign"):
            attempts.review([first, second, resigned])

    def test_each_run_of_an_environment_job_is_counted(self):
        first = first_attempt(failed=(), downstream={"sign": "success", "package": "success", "seal": "failure"})
        second = again(first, 2, [("seal", "failure")])
        third = again(second, 3, [("seal", "success"), ("publish", "success")])
        history = attempts.review([first, second, third])
        self.assertEqual({n: history["runs"][n] for n in DOWNSTREAM},
                         {"sign": 1, "package": 1, "seal": 3, "publish": 1})
        self.assertEqual(history["reruns"]["seal"]["attempts"], [2, 3])
        self.assertNotIn("publish", history["reruns"], "a job that was only skipped before is no re-run")

    def test_nothing_else_may_change(self):
        first, second = listings()
        failed_build = first_attempt(failed=(), overrides={"build": {"conclusion": "failure"}})
        signed = first_attempt(failed=(), downstream={"sign": "success", "package": "failure"})
        cancelled = first_attempt(failed=(), downstream={"sign": "success", "package": "cancelled"})
        plan_failed = first_attempt(overrides={"plan": {"conclusion": "failure"}})
        cases = {
            "the plan was run again": listings(second_overrides={"plan": {"started_at": "2026-11-25T20:23:13Z"}}),
            "the plan failed in attempt 1": (plan_failed, again(plan_failed, 2, [("plan", "success")])),
            "the build was run again": listings(second_overrides={"build": {"completed_at": "2026-11-25T21:00:00Z"}}),
            "a failed build was not built again": (failed_build, again(failed_build, 2)),
            "a passing regression was run again": listings(
                second_overrides={"regressions (nat)": {"started_at": "2026-11-25T20:23:13Z"}}),
            "the failed regression was only carried over": listings(
                second_overrides={"regressions (rip)": {"conclusion": "failure", "started_at": "2026-11-25T15:13:10Z",
                                                        "completed_at": "2026-11-25T16:13:10Z"}}),
            "the failed regression was not run again": (first, [j for j in second if j["name"] != "regressions (rip)"]),
            "a cancelled regression was run again": listings(first_overrides={"regressions (rip)": {"conclusion": "cancelled"}}),
            "a passed sign was signed again": (signed, again(signed, 2, [("package", "success"), ("sign", "success")])),
            "a cancelled package was run again": (cancelled, again(cancelled, 2, [("package", "success")])),
            "attempt 2 re-ran nothing": listings(failed=()),
            "a passed job is missing": (first, [j for j in second if j["name"] != "regressions (nat)"]),
            "a job appeared": (first, second + [job("regressions (new)", "success", 2)]),
            "an unknown job": (first + [job("debug", "success")], second + [job("debug", "success", 2)]),
            "a duplicate name in attempt 1": (first + [first[2]], second),
            "a passing regression listed twice": (first, second + [second[2] | {"id": 1}]),
            "an entry of another attempt": (first, second[:-1] + [second[-1] | {"run_attempt": 1}]),
            "attempt 1 lists an entry of attempt 2": ([first[0] | {"run_attempt": 2}] + first[1:], second),
        }
        for reason, pair in cases.items():
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                attempts.review(list(pair))
        third_cases = {
            "a regression that passed in attempt 2 ran again": again(
                second, 3, overrides={"regressions (rip)": {"started_at": "2026-11-27T20:23:13Z"}}),
            "attempt 3 re-ran nothing": again(second, 3),
            "a malformed listing": [{"name": 1}],
        }
        for reason, third in third_cases.items():
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                attempts.review([first, second, third])
        for malformed in ([], [None], [first, None]):
            with self.subTest(listings=malformed), self.assertRaises(ValueError):
                attempts.review(malformed)

    def test_the_real_re_run_of_run_45642647509_while_it_ran(self):
        # Every carried-over job came back with a new id and run_attempt 2;
        # routed-reply, the one failure, was listed 34 times: 1 running, 33
        # queued, and sign not created yet. GitHub still waited, so do we.
        first, second = real_jobs("attempt-1.json"), real_jobs("attempt-2-in-progress.json")
        with self.assertRaisesRegex(ValueError, "still waits for 33"):
            attempts.review([first, second])
        plan = next(k for k, j in enumerate(second) if j["name"] == "plan")
        moved = second[:plan] + [second[plan] | {"started_at": "2026-11-25T20:23:13Z"}] + second[plan + 1:]
        with self.assertRaisesRegex(ValueError, "plan"):
            attempts.review([first, moved])

    def test_the_real_re_run_of_run_45642647509_once_sign_waits(self):
        # The one real re-run passed; 33 entries never got a runner (started_at
        # is their creation time); sign is waiting for its approval.
        first, second = real_jobs("attempt-1.json"), real_jobs("attempt-2-sign-waiting.json")
        history = attempts.review([first, second])
        rerun = history["reruns"]["regressions (routed-reply)"]
        self.assertEqual((rerun["attempts"], rerun["runs"], rerun["phantoms"]), ([2], 1, 33))
        self.assertEqual(sorted(history["reruns"]), ["regressions (routed-reply)"])
        self.assertEqual(history["runs"]["sign"], 0, "a job waiting for approval has not run")
        attempts.require_green(history)
        name = "regressions (routed-reply)"
        without_sign = [j for j in second if j["name"] != "sign"]
        with self.assertRaisesRegex(ValueError, "still waits for 33"):
            attempts.review([first, without_sign])
        real = next(k for k, j in enumerate(second) if j["name"] == name and j["status"] == "completed")
        failed = second[:real] + [second[real] | {"conclusion": "failure"}] + second[real + 1:]
        with self.assertRaisesRegex(ValueError, "routed-reply"):
            attempts.require_green(attempts.review([first, failed]))
        queued = next(k for k, j in enumerate(second) if j["name"] == name and j["status"] == "queued")
        started = second[:queued] + [second[queued] | {"runner_name": "GitHub Actions 7", "runner_id": 7}] + second[queued + 1:]
        with self.assertRaisesRegex(ValueError, "routed-reply"):
            attempts.require_green(attempts.review([first, started]))
        only_phantoms = [j for j in second if not (j["name"] == name and j["status"] == "completed")]
        with self.assertRaisesRegex(ValueError, "not run again"):
            attempts.review([first, only_phantoms])

    def test_only_a_fresh_downstream_job_shows_github_has_moved_on(self):
        first = first_attempt(failed=(), downstream={"sign": "success", "package": "failure"})
        latest = attempts.review([first])["latest"]
        carried = again(first, 2)
        self.assertFalse(attempts.moved_on(carried, latest), "a carried-over sign waits for nothing")
        waiting = carried + [job("package", "success", 2) | {"status": "waiting", "conclusion": None}]
        self.assertTrue(attempts.moved_on(waiting, latest))
        queued = carried + [job("package", None, 2) | {"status": "queued", "completed_at": None}]
        self.assertFalse(attempts.moved_on(queued, latest))

    def test_phantoms_of_an_earlier_attempt_no_longer_count(self):
        # Sign of run 45642647509, had it failed after its approval, run in attempt 3.
        first, second = real_jobs("attempt-1.json"), real_jobs("attempt-2-sign-waiting.json")
        sign = next(k for k, j in enumerate(second) if j["name"] == "sign")
        second = second[:sign] + [second[sign] | {"status": "completed", "conclusion": "failure",
                                                  "runner_id": 8, "runner_name": "GitHub Actions 8",
                                                  "completed_at": "2026-11-25T21:30:00Z"}] + second[sign + 1:]
        history = attempts.review([first, second, again(second, 3, [("sign", "success")])])
        attempts.require_green(history)
        self.assertEqual(history["reruns"]["sign"]["attempts"], [3])
        self.assertEqual(history["reruns"]["regressions (routed-reply)"]["phantoms"], 33)
        self.assertEqual(history["runs"]["sign"], 2)

    def test_the_job_listing_is_read_completely(self):
        jobs = real_jobs("attempt-2-sign-waiting.json")
        requests = []

        def fetch(path):
            requests.append(path)
            self.assertIn("per_page=30&", path)
            page = int(path.rsplit("page=", 1)[1])
            return {"total_count": len(jobs), "jobs": jobs[(page - 1) * 30:page * 30]}

        self.assertEqual(attempts.attempt_jobs("Velstra/sentinel", "45642647509", 2, fetch), jobs)
        self.assertEqual(len(requests), 9)
        short = lambda path: {"total_count": 243, "jobs": jobs[:30]} if path.endswith("page=1") else {"total_count": 243, "jobs": []}
        with self.assertRaises(ValueError):
            attempts.attempt_jobs("Velstra/sentinel", "45642647509", 2, short)

    def test_artifact_downloads_retry_server_errors_and_restart_the_file(self):
        from types import SimpleNamespace
        replies, waits = iter([b"gh: Server Error (HTTP 502)", b"gh: Server Error (HTTP 503)", None]), []

        def run(command, stdout, **kw):
            failure = next(replies)
            stdout.write(b"partial " if failure else b"complete zip")
            return SimpleNamespace(returncode=1 if failure else 0, stderr=failure or b"")

        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "artifact.zip"
            attempts.gh_download(["repos/Velstra/sentinel/actions/artifacts/1/zip"], target, run=run, sleep=waits.append)
            self.assertEqual((target.read_bytes(), waits), (b"complete zip", [5, 10]))

    def test_api_reads_retry_server_errors_and_then_fail_closed(self):
        from types import SimpleNamespace
        ok = SimpleNamespace(returncode=0, stdout='{"total_count": 0, "jobs": []}', stderr="")
        bad = SimpleNamespace(returncode=1, stdout="", stderr="gh: Server Error (HTTP 502)\n")
        replies, calls, waits = iter([bad, bad, ok]), [], []
        out = attempts.gh_get(["repos/Velstra/sentinel/actions/runs/1/attempts/2/jobs?per_page=30&page=1"],
                              run=lambda command, **kw: calls.append(command) or next(replies), sleep=waits.append)
        self.assertEqual((out, len(calls), waits), (ok.stdout, 3, [5, 10]))
        waits.clear()
        with self.assertRaisesRegex(ValueError, r"failed 5 times; last: gh: Server Error \(HTTP 502\)"):
            attempts.gh_get(["jobs"], run=lambda command, **kw: bad, sleep=waits.append)
        self.assertEqual(waits, [5, 10, 20, 40])
        waits.clear()
        missing = SimpleNamespace(returncode=1, stdout="", stderr="gh: Not Found (HTTP 404)")
        with self.assertRaisesRegex(ValueError, "HTTP 404"):
            attempts.gh_get(["jobs"], run=lambda command, **kw: missing, sleep=waits.append)
        self.assertEqual(waits, [], "only a server error is retried")

        def hang(command, **kw):
            raise subprocess.TimeoutExpired(command, 60)

        with self.assertRaisesRegex(ValueError, "timed out"):
            attempts.gh_get(["jobs"], run=hang, sleep=waits.append)

    def test_the_first_failure_names_the_real_error(self):
        failed = job("regressions (rip)", "failure")
        generic = {"annotation_level": "failure", "message": "Process completed with exit code 1."}
        specific = {"annotation_level": "failure", "message": "rip: no build output for 30 min again\nmore"}
        warning = {"annotation_level": "warning", "message": "Node.js 20 is deprecated"}
        self.assertEqual(attempts.first_failure(failed, [warning, generic, specific]),
                         "rip: no build output for 30 min again")
        self.assertEqual(attempts.first_failure(failed, [warning, generic]), "Process completed with exit code 1.")
        self.assertEqual(attempts.first_failure(failed, []), "job failure")

    def api(self, listings, messages, starters=None):
        """A fetch that serves one listing per attempt and each job's annotations."""
        def fetch(path):
            if "/attempts/" in path and "/jobs" not in path:
                number = int(path.rsplit("/", 1)[1])
                starter = starters[number - 1] if starters else "owner"
                return {"run_attempt": number, "actor": {"login": "owner"}, "triggering_actor": {"login": starter}}
            if "/attempts/" in path:
                listing = listings[int(path.split("/attempts/", 1)[1].split("/", 1)[0]) - 1]
                return {"total_count": len(listing), "jobs": listing}
            job_id = int(path.split("check-runs/", 1)[1].split("/", 1)[0])
            self.assertIn(job_id, messages, path)
            return [{"annotation_level": "failure", "message": messages[job_id]}]
        return fetch

    def test_the_current_run_is_judged_from_the_api(self):
        environment = {"GITHUB_RUN_ID": "42", "GITHUB_REPOSITORY": "Velstra/sentinel"}
        with patch.dict(os.environ, environment | {"GITHUB_RUN_ATTEMPT": "1"}):
            self.assertEqual(attempts.current(fetch=lambda path: self.fail(path)),
                             {"attempt": 1, "checks": {}, "jobs": {}, "runs": {}, "gates": {}, "actors": [],
                              "ran_in": {}})
        first = first_attempt()
        second = again(first, 2, [("regressions (rip)", "success"), ("sign", "success"), ("package", "failure")])
        third = again(second, 3, [("package", "success")])
        rip, package = named(first, "regressions (rip)"), named(second, "package")
        fetch = self.api([first, second, third], {rip["id"]: "rip failed: OSPF never converged",
                                                  package["id"]: "boot gate: no login prompt"},
                         ["owner", "reviewer", "owner"])
        with patch.dict(os.environ, environment | {"GITHUB_RUN_ATTEMPT": "2"}):
            record = attempts.current(fetch=fetch)
        self.assertEqual(record["checks"], {"rip": {
            "first_failure": "rip failed: OSPF never converged", "first_job": rip["html_url"], "failed_in": 1,
            "attempts": [2], "runs": 1, "phantoms": 0}})
        self.assertEqual(record["jobs"], {})
        with patch.dict(os.environ, environment | {"GITHUB_RUN_ATTEMPT": "3"}):
            record = attempts.current(fetch=fetch)
        self.assertEqual(record["attempt"], 3)
        self.assertEqual(record["checks"]["rip"]["attempts"], [2])
        self.assertEqual(record["jobs"], {"package": {
            "first_failure": "boot gate: no login prompt", "first_job": package["html_url"], "failed_in": 2,
            "attempts": [3], "runs": 1, "phantoms": 0}})
        self.assertEqual((record["runs"]["sign"], record["runs"]["package"]), (1, 2))
        self.assertEqual((record["gates"]["sign"], record["gates"]["package"], record["gates"]["seal"]),
                         ([2], [2, 3], []))
        self.assertEqual(record["actors"], [["owner", "owner"], ["owner", "reviewer"], ["owner", "owner"]])
        self.assertEqual((record["ran_in"]["sign"], record["ran_in"]["package"]), (2, 3))
        self.assertEqual((attempts.gate_runs(record, "sign"), attempts.ran_in(record, "package")), (1, 3))
        attempt_one = {"attempt": 1, "checks": {}, "jobs": {}, "runs": {}, "gates": {}, "actors": [], "ran_in": {}}
        self.assertEqual((attempts.gate_runs(attempt_one, "seal"), attempts.ran_in(attempt_one, "package")), (1, 1))
        broken = self.api([first, again(first, 2, [("regressions (rip)", "failure")]), third], {})
        bad_starter = self.api([first, second, third], {rip["id"]: "x", package["id"]: "y"}, ["owner", None, "owner"])
        with patch.dict(os.environ, environment | {"GITHUB_RUN_ATTEMPT": "3"}), self.assertRaises(ValueError):
            attempts.current(fetch=bad_starter)
        with patch.dict(os.environ, environment | {"GITHUB_RUN_ATTEMPT": "2"}), self.assertRaisesRegex(ValueError, "rip"):
            attempts.current(fetch=broken)

    def test_receipts_must_come_from_the_attempt_that_ran_them(self):
        from types import SimpleNamespace
        names = sorted(release.REQUIRED_SAFETY_CHECKS | {"rip"})
        rerun = {"first_failure": "rip failed", "first_job": "https://example.invalid/job/1", "failed_in": 1,
                 "attempts": [2, 3], "runs": 2, "phantoms": 0}
        record = {"attempt": 3, "checks": {"rip": rerun}, "jobs": {}, "runs": {}, "gates": {}, "actors": [],
                  "ran_in": {"package": 3}}
        with tempfile.TemporaryDirectory() as temp, patch.object(release, "source", return_value="a" * 40), \
                patch.object(release, "run", return_value=json.dumps(names)), \
                patch.object(attempts, "current", return_value=record), \
                patch.dict(os.environ, {"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "3",
                                        "RELEASE_REGRESSION_RUNNER": "velstra-rel-a1b2c3d4"}):
            directory = Path(temp)
            args = SimpleNamespace(input=directory, output=directory / "complete.txt")
            base = {"source": "a" * 40, "completed_at": int(time.time())}
            for name in release.REQUIRED_SAFETY_CHECKS:
                (directory / f"{name}.json").write_text(json.dumps(base | {"check": name, "run": "42-1"}))
            for stale in ("42-1", "42-2"):
                (directory / "rip.json").write_text(json.dumps(base | {"check": "rip", "run": stale}))
                with self.subTest(receipt=stale), self.assertRaises(ValueError):
                    release.aggregate(args)
            (directory / "rip.json").write_text(json.dumps(base | {"check": "rip", "run": "42-3"}))
            release.aggregate(args)
            summary = json.loads(args.output.read_text())
            self.assertEqual((summary["run"], summary["reruns"]), ("42-3", {"rip": rerun}))
            self.assertEqual(summary["regression_runner"],
                             {"class": "self-hosted-ephemeral", "label": "velstra-rel-a1b2c3d4"})
            args.output.unlink()
            nat = next(iter(sorted(release.REQUIRED_SAFETY_CHECKS)))
            (directory / f"{nat}.json").write_text(json.dumps(base | {"check": nat, "run": "42-3"}))
            with self.assertRaises(ValueError): release.aggregate(args)

    def test_the_bundle_records_exactly_the_reruns_of_its_attempts(self):
        names = ["nat", "rip"]
        entry = {"first_failure": "rip failed", "first_job": "https://example.invalid/job/1", "failed_in": 1,
                 "attempts": [2], "runs": 1, "phantoms": 0}
        self.assertEqual(release.expected_receipt_runs({"run": "42-2", "reruns": {"rip": entry}}, names, "42", 2),
                         {"nat": "42-1", "rip": "42-2"})
        twice = entry | {"attempts": [2, 3], "runs": 2}
        self.assertEqual(release.expected_receipt_runs({"run": "42-3", "reruns": {"rip": twice}}, names, "42", 3),
                         {"nat": "42-1", "rip": "42-3"})
        # Package itself ran again in attempt 2; no regression did.
        self.assertEqual(release.expected_receipt_runs({"run": "42-2"}, names, "42", 2),
                         {"nat": "42-1", "rip": "42-1"})
        self.assertEqual(release.expected_receipt_runs({"run": "42-1"}, names, "42", 1),
                         {"nat": "42-1", "rip": "42-1"})
        for bad, package in (({"run": "42-1", "reruns": {"rip": entry}}, 1),           # attempt 1 with a re-run
                             ({"run": "42-2", "reruns": {"rip": entry}}, 3),           # not the package's attempt
                             ({"run": "42-2", "reruns": {"other": entry}}, 2),         # not a catalogued check
                             ({"run": "42-2", "reruns": {"rip": {"first_failure": 1}}}, 2),
                             ({"run": "42-2", "reruns": {"rip": entry | {"runs": 0}}}, 2),
                             ({"run": "42-2", "reruns": {"rip": entry | {"phantoms": -1}}}, 2),
                             ({"run": "42-2", "reruns": {"rip": entry | {"attempts": [3]}}}, 2),
                             ({"run": "42-3", "reruns": {"rip": twice | {"attempts": [3, 2]}}}, 3),
                             ({"run": "42-3", "reruns": {"rip": entry | {"attempts": [1]}}}, 3),
                             ({"run": "42-3", "reruns": {"rip": entry | {"attempts": []}}}, 3),
                             ({"run": "42-3", "reruns": {"rip": twice | {"attempts": [2, True]}}}, 3),
                             ({"run": "42-3", "reruns": {"rip": twice | {"runs": 1}}}, 3),
                             ({"run": "42-3", "reruns": {"rip": entry | {"failed_in": 2}}}, 3),
                             ({"run": "42-1", "reruns": []}, 1)):
            with self.subTest(bad=bad, package=package), self.assertRaises(ValueError):
                release.expected_receipt_runs(bad, names, "42", package)

    def test_approval_is_counted_against_the_runs_of_its_job(self):
        environment = {"id": 7}
        approval = {"state": "approved", "environments": [{"id": 7}], "user": {"type": "User", "login": "reviewer"}}
        hosted = {"RUNNER_ENVIRONMENT": "github-hosted"}
        first = {"attempt": 1, "checks": {}, "jobs": {}, "runs": {}, "ran_in": {}}
        third = {"attempt": 3, "checks": {}, "jobs": {"seal": {}}, "runs": {"seal": 2}, "gates": {"seal": [2, 3]},
                 "actors": [["owner", "owner"]] * 3, "ran_in": {}}
        with patch.dict(os.environ, hosted), patch.object(attempts, "current", return_value=first) as current:
            self.assertIs(protection.approved(environment, [approval], {"owner"}, job="seal"), first)
        current.assert_called_once()
        with patch.dict(os.environ, hosted), patch.object(attempts, "current", return_value=third):
            with self.assertRaisesRegex(ValueError, "approval"):
                protection.approved(environment, [approval], {"owner"}, job="seal")
            protection.approved(environment, [approval, approval], {"owner"}, job="seal")
            with self.assertRaisesRegex(ValueError, "independent"):
                protection.approved(environment, [approval, approval | {"user": {"type": "User", "login": "owner"}}],
                                    {"owner"}, job="seal")
        with patch.dict(os.environ, hosted), patch.object(attempts, "current", side_effect=ValueError("attempt 4")), \
                self.assertRaises(ValueError):
            protection.approved(environment, [approval], {"owner"}, job="seal")
        with patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "self-hosted"}), \
                patch.object(attempts, "current", return_value=first), self.assertRaisesRegex(ValueError, "GitHub-hosted"):
            protection.approved(environment, [approval], {"owner"}, job="seal")
        self.assertEqual(protection.ENVIRONMENT_JOBS, {"community-signing": "sign",
                                                       "community-attestation": "seal",
                                                       "community-publish": "publish"})

    def test_every_run_of_an_environment_job_needs_its_own_approval(self):
        environment = {"id": 7}
        timer = {"environments": [{"id": 7}], "state": "approved", "comment": "30 minute wait timer",
                 "user": {"type": "Bot", "login": "github-actions[bot]"}}
        mine = {"environments": [{"id": 7}], "state": "approved", "user": {"type": "User", "login": "owner"}}
        protection.approval(environment, [timer, mine], {"owner"}, single_operator=True, runs=1)
        protection.approval(environment, [timer, mine, timer, mine], {"owner"}, single_operator=True, runs=2)
        for history, runs in (([timer, mine], 2),          # the run now would reuse an earlier approval
                              ([timer, mine, timer, mine], 1),
                              ([timer, mine, timer], 2),
                              ([timer, mine], 0)):
            with self.subTest(history=history, runs=runs), self.assertRaisesRegex(ValueError, "approval"):
                protection.approval(environment, history, {"owner"}, single_operator=True, runs=runs)

    def test_a_rejected_review_closes_the_gate_and_is_no_run(self):
        # Rejected in attempt 2: the job failed without a runner. Re-run in
        # attempt 3, approved there: one run, one approval.
        environment = {"id": 7}
        mine = {"environments": [{"id": 7}], "state": "approved", "user": {"type": "User", "login": "owner"}}
        rejected = mine | {"state": "rejected"}
        protection.approval(environment, [rejected, mine], {"owner"}, single_operator=True, runs=1)
        protection.approval(environment, [mine, rejected], {"owner"}, single_operator=True, runs=1)
        with self.assertRaisesRegex(ValueError, "approval"):
            protection.approval(environment, [rejected, mine], {"owner"}, single_operator=True, runs=2)

    def test_two_person_approvals_are_matched_to_the_attempts_of_their_runs(self):
        environment = {"id": 7}
        def by(login):
            return {"environments": [{"id": 7}], "state": "approved", "user": {"type": "User", "login": login}}
        # A dispatched; seal ran in attempt 2 (re-run started by B, approved by
        # C) and in attempt 3 (re-run started by C, approved by B).
        runs = [{"A", "B"}, {"A", "C"}]
        protection.approval(environment, [by("C"), by("B")], {"A", "C"}, runs=runs)
        protection.approval(environment, [by("B"), by("C")], {"A", "C"}, runs=runs)
        for history in ([by("B"), by("B")],    # B cannot have approved the run B started
                        [by("A"), by("C")],    # the dispatcher never approves
                        [by("C"), by("C")]):   # C cannot have approved the run C started
            with self.subTest(history=history), self.assertRaisesRegex(ValueError, "independent"):
                protection.approval(environment, history, {"A", "C"}, runs=runs)
        with self.assertRaisesRegex(ValueError, "approval"):
            protection.approval(environment, [by("C")], {"A", "C"}, runs=runs)

    def test_approved_takes_the_starters_of_each_attempt_from_github(self):
        environment = {"id": 7}
        def by(login):
            return {"environments": [{"id": 7}], "state": "approved", "user": {"type": "User", "login": login}}
        record = {"attempt": 3, "checks": {}, "jobs": {"seal": {}}, "runs": {"seal": 2},
                  "gates": {"seal": [2, 3]}, "actors": [["A", "A"], ["A", "B"], ["A", "C"]], "ran_in": {}}
        with patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "github-hosted"}), \
                patch.object(attempts, "current", return_value=record):
            protection.approved(environment, [by("C"), by("B")], {"A", "C"}, job="seal")
            with self.assertRaisesRegex(ValueError, "independent"):
                protection.approved(environment, [by("B"), by("B")], {"A", "C"}, job="seal")
            # Single-operator mode: the owner dispatches, approves and re-runs.
            protection.approved(environment, [by("A"), by("A")], {"A"}, single_operator=True, job="seal")

    def test_the_real_approval_history_of_run_45868284650(self):
        history = json.loads((PACKAGE_FAILED / "approvals.json").read_text())
        signing = {"id": history[0]["environments"][0]["id"]}
        protection.approval(signing, history, {"maintainer"}, single_operator=True, runs=1)
        with self.assertRaisesRegex(ValueError, "approval"):
            protection.approval(signing, history, {"maintainer"}, single_operator=True, runs=2)
        with self.assertRaises(ValueError):
            protection.approval({"id": 1}, history, {"maintainer"}, single_operator=True, runs=1)


class RunnerTests(unittest.TestCase):
    """Only the regression jobs may run on self-hosted ephemeral runners;
    every job that builds, signs or publishes stays on GitHub's."""

    def test_github_hosted_regressions_by_default(self):
        runner = release.regression_runner("github")
        self.assertEqual((runner["runs_on"], runner["max_parallel"], runner["record"]),
                         ("ubuntu-24.04", 19, {"class": "github-hosted", "label": "ubuntu-24.04"}))
        self.assertEqual(release.runner_outputs("github"),
                         'regression_runner=github\nregression_runs_on="ubuntu-24.04"\nregression_max_parallel=19\n')

    def test_a_self_hosted_label_selects_the_ephemeral_runners(self):
        runner = release.regression_runner("velstra-rel-a1b2c3d4")
        self.assertEqual((runner["runs_on"], runner["max_parallel"], runner["record"]),
                         (["self-hosted", "linux", "x64", "velstra-rel-a1b2c3d4"], 40,
                          {"class": "self-hosted-ephemeral", "label": "velstra-rel-a1b2c3d4"}))
        self.assertEqual(release.runner_outputs("velstra-rel-a1b2c3d4"),
                         "regression_runner=velstra-rel-a1b2c3d4\n"
                         'regression_runs_on=["self-hosted","linux","x64","velstra-rel-a1b2c3d4"]\n'
                         "regression_max_parallel=40\n")
        release.regression_runner("velstra-rel-" + "a" * 32)

    def test_any_other_runner_fails_closed(self):
        for value in ("", "GitHub", "ubuntu-24.04", "self-hosted", "velstra-rel-abc1234",
                      "velstra-rel-" + "a" * 33, "velstra-rel-ABCDEFGH", "velstra-rel-abcdefgh\n",
                      "velstra-rel-abcdefgh x", "velstra-rel-abcd_efgh", "x-velstra-rel-abcdefgh",
                      "velstra-rel-abcdefgh\nregression_max_parallel=999", None, ["velstra-rel-abcdefgh"]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                release.regression_runner(value)

    def test_release_jobs_refuse_a_self_hosted_runner(self):
        with patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "github-hosted"}):
            attempts.require_github_hosted()
        for value in ("self-hosted", "", "GitHub-hosted"):
            with self.subTest(value=value), patch.dict(os.environ, {"RUNNER_ENVIRONMENT": value}), \
                    self.assertRaisesRegex(ValueError, "GitHub-hosted"):
                attempts.require_github_hosted()
        with patch.dict(os.environ):
            os.environ.pop("RUNNER_ENVIRONMENT", None)
            with self.assertRaisesRegex(ValueError, "GitHub-hosted"):
                attempts.require_github_hosted()

    def test_every_release_command_but_the_checks_requires_a_github_hosted_runner(self):
        handlers = {"build": "build_image", "sign": "sign_image", "package": "package", "aggregate": "aggregate",
                    "validate": "validate_bundle", "verify": "verify_bundle", "seal": "files"}
        for command, handler in handlers.items():
            with self.subTest(command=command), patch.object(sys, "argv", ["community_release.py", command]), \
                    patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "self-hosted"}), \
                    patch.object(release, handler) as called, self.assertRaisesRegex(ValueError, "GitHub-hosted"):
                release.main()
            called.assert_not_called()
        for command, handler in (("checks", "checks"),):
            with self.subTest(command=command), patch.object(sys, "argv", ["community_release.py", command]), \
                    patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "self-hosted"}), \
                    patch.object(release, handler) as called:
                release.main()
            called.assert_called_once()
        with patch.object(sys, "argv", ["community_release.py", "runner", "--runner", "github"]), \
                patch("sys.stdout", new_callable=__import__("io").StringIO) as out:
            release.main()
        self.assertEqual(out.getvalue(), release.runner_outputs("github"))


class RealSignatureTests(unittest.TestCase):
    def test_real_detached_signature_and_wrong_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            keyring, bundle = directory / "gnupg", directory / "bundle"
            keyring.mkdir(mode=0o700)
            bundle.mkdir()
            environment = {"GNUPGHOME": str(keyring), "RELEASE_VERSION": VERSION,
                           "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "RELEASE_REGRESSION_RUNNER": "github",
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
                    "qcow2_byte_equivalent": True, "iso_embedded_raw_verified": True,
                    "stall_retries": {"image-build": 0, "installer-iso": 0, "boot-gate": 1}})
                release.document(bundle / "release-image-boot.json", {
                    "complete": True, "boots": [{"number": 1}, {"number": 2}],
                    "expected_sha256": "b" * 64, "source_sha256_before": "b" * 64, "source_sha256_after": "b" * 64,
                    "certificate_sha256": {n: release.digest(bundle / f"{n}.crt") for n in ("PK", "KEK", "db")}})
                release.document(bundle / "source-checks.json", {"source": "a" * 40, "run": "123-1",
                    "regression_runner": {"class": "github-hosted", "label": "ubuntu-24.04"}, "checks": [
                    {"source": "a" * 40, "run": "123-1", "check": name, "completed_at": int(time.time())}
                    for name in sorted(release.REQUIRED_SAFETY_CHECKS)]})
                release.document(bundle / "source-sbom.provenance.json", {"source_commit": "a" * 40,
                    "scope": "source-lockfiles", "sbom_sha256": release.digest(bundle / "source-sbom.cdx.json")})
                with patch.object(release, "run", side_effect=AssertionError("pre-sign validation must not call GPG")):
                    release.validate_bundle(bundle)
                    # The plan said the regressions ran elsewhere than the bundle says.
                    with patch.dict(os.environ, {"RELEASE_REGRESSION_RUNNER": "velstra-rel-a1b2c3d4"}), \
                            self.assertRaisesRegex(ValueError, "runner"):
                        release.validate_bundle(bundle)
                    rerun = {"first_failure": "x", "first_job": "y", "failed_in": 1, "attempts": [2], "runs": 1}
                    with patch.object(attempts, "current", return_value={
                            "attempt": 2, "checks": {"image-closure": rerun}, "jobs": {}, "runs": {},
                            "ran_in": {"package": 1}}), self.assertRaisesRegex(ValueError, "re-run"):
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
                           ("RELEASE_PUBLISH_REQUESTED", "false"), ("GITHUB_RUN_ATTEMPT", "4"),
                           ("GITHUB_RUN_ATTEMPT", "0")):
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
            (directory / "source-checks.json").write_text(json.dumps(
                {"checks": [], "regression_runner": {"class": "github-hosted", "label": "ubuntu-24.04"}}))
            with self.assertRaisesRegex(ValueError, "draft retained"):
                publisher.publish(directory)
            self.assertEqual(api.call_count, 4)
            self.assertEqual(api.call_args.kwargs["method"], "POST")
            self.assertTrue(api.call_args.args[1]["draft"])

    def draft_body(self, extra, runner=None):
        runner = runner or {"class": "github-hosted", "label": "ubuntu-24.04"}
        with tempfile.TemporaryDirectory() as temp, patch.object(publisher, "verify_bundle"), \
                patch.object(publisher, "source", return_value="a" * 40), \
                patch.object(publisher, "api", side_effect=[{"status": "identical"}, None, None, {"id": 7, "draft": True, "tag_name": VERSION}]) as api, \
                patch.object(publisher.subprocess, "run"), \
                patch.dict(os.environ, {"RELEASE_VERSION": VERSION, "GITHUB_REPOSITORY": "Velstra/sentinel"} | extra):
            directory = Path(temp)
            (directory / "fixture.iso").write_bytes(b"not a real ISO")
            (directory / "source-checks.json").write_text(json.dumps({"checks": [], "regression_runner": runner}))
            with self.assertRaisesRegex(ValueError, "draft retained"):
                publisher.publish(directory)
            return api.call_args.args[1]["body"]

    def test_release_body_records_single_operator_mode(self):
        default = self.draft_body({"RELEASE_SINGLE_OPERATOR": ""})
        self.assertNotIn("single-operator", default)
        self.assertTrue(default.endswith("no physical-hardware certification is claimed.\n\n"
                                         "Regression checks and every release job ran on GitHub-hosted "
                                         "runners (ubuntu-24.04)."))
        single = self.draft_body({"RELEASE_SINGLE_OPERATOR": "true"})
        self.assertEqual(single, default + "\n\nRelease approvals: single-operator mode "
                                           "(one maintainer, wait timer \u2265 30 min).")

    def test_release_body_names_the_runners_of_the_regression_checks(self):
        body = self.draft_body({}, {"class": "self-hosted-ephemeral", "label": "velstra-rel-a1b2c3d4"})
        self.assertIn("\n\nRegression checks ran on self-hosted ephemeral runners (runner label velstra-rel-a1b2c3d4).",
                      body)
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, directory)
        with self.assertRaises(ValueError):
            publisher.runner_statement(directory)
        for record in ({}, {"class": "self-hosted-ephemeral", "label": "ubuntu-24.04"},
                       {"class": "github-hosted", "label": "velstra-rel-a1b2c3d4"}, {"class": "elsewhere", "label": "x"}):
            (directory / "source-checks.json").write_text(json.dumps({"checks": [], "regression_runner": record}))
            with self.subTest(record=record), self.assertRaises(ValueError):
                publisher.runner_statement(directory)

    def test_release_body_names_release_builds_retried_after_a_stall(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, directory)
        self.assertEqual(publisher.build_stall_statement(directory), "")
        (directory / "image-evidence.json").write_text(json.dumps(
            {"stall_retries": {"image-build": 1, "installer-iso": 0, "boot-gate": 1}}))
        self.assertEqual(publisher.build_stall_statement(directory),
                         "Release builds retried once after a stalled build (no output for 30 min; "
                         "a failing build is never retried): image build, boot gate.")
        (directory / "image-evidence.json").write_text(json.dumps(
            {"stall_retries": {"image-build": 0, "installer-iso": 0, "boot-gate": 0}}))
        self.assertEqual(publisher.build_stall_statement(directory), "")

    def test_release_body_names_checks_retried_after_a_stall(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, directory)
        checks = [{"check": "nat"}, {"check": "image-first-boot", "stall_retries": 1},
                  {"check": "commit", "stall_retries": 0}]
        (directory / "source-checks.json").write_text(json.dumps({"checks": checks}))
        self.assertEqual(publisher.stall_statement(directory),
                         "Regression checks retried once after a stalled build (no output for 30 min; "
                         "a failing check is never retried): image-first-boot.")
        (directory / "source-checks.json").write_text(json.dumps({"checks": checks[:1]}))
        self.assertEqual(publisher.stall_statement(directory), "")

    def test_release_body_lists_every_rerun_with_its_first_failure(self):
        checks = {"rip": {"first_failure": "rip failed: OSPF never converged", "failed_in": 1,
                          "first_job": "https://github.com/Velstra/sentinel/actions/runs/42/job/7",
                          "attempts": [2, 3], "runs": 2, "phantoms": 0},
                  "nat": {"first_failure": "nat: timeout", "failed_in": 1,
                          "first_job": "https://github.com/Velstra/sentinel/actions/runs/42/job/8",
                          "attempts": [2], "runs": 1, "phantoms": 33}}
        jobs = {"package": {"first_failure": "boot gate: no login prompt", "failed_in": 2,
                            "first_job": "https://github.com/Velstra/sentinel/actions/runs/42/job/9",
                            "attempts": [3], "runs": 1, "phantoms": 0}}
        record = {"attempt": 3, "checks": checks, "jobs": jobs, "runs": {}, "ran_in": {}}
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, directory)
        (directory / "source-checks.json").write_text(json.dumps({"checks": [], "reruns": checks}))
        with patch.object(attempts, "current", return_value=record):
            self.assertEqual(publisher.rerun_statement(directory),
                             "Regression checks re-run after a failure: "
                             "nat (first failure, attempt 1: nat: timeout; log: "
                             "https://github.com/Velstra/sentinel/actions/runs/42/job/8; "
                             "ran again once in attempt 2 and passed; "
                             "33 phantom entries were listed but never started), "
                             "rip (first failure, attempt 1: rip failed: OSPF never converged; log: "
                             "https://github.com/Velstra/sentinel/actions/runs/42/job/7; "
                             "ran again 2 times in attempts 2 and 3 and passed in attempt 3)."
                             "\n\nRelease jobs re-run after a failure: package (first failure, attempt 2: "
                             "boot gate: no login prompt; log: https://github.com/Velstra/sentinel/actions/runs/42/job/9; "
                             "ran again in attempt 3).")
        self.assertEqual(publisher.rerun_count({"attempts": [2], "runs": 34}), "ran again 34 times in attempt 2 and passed")
        self.assertEqual(publisher.rerun_count({"attempts": [2], "runs": 1, "phantoms": 1}),
                         "ran again once in attempt 2 and passed; 1 phantom entry was listed but never started")
        # The bundle was packaged before the API saw a different re-run.
        for other in (checks | {"rip": checks["rip"] | {"attempts": [2]}}, {"nat": checks["nat"]}, {}):
            with self.subTest(other=other), patch.object(attempts, "current", return_value=record | {"checks": other}), \
                    self.assertRaisesRegex(ValueError, "re-run"):
                publisher.rerun_statement(directory)
        (directory / "source-checks.json").write_text(json.dumps({"checks": []}))
        with patch.object(attempts, "current", return_value=record | {"checks": {}, "jobs": {}}):
            self.assertEqual(publisher.rerun_statement(directory), "")
        with patch.object(attempts, "current", return_value=record | {"checks": {}}):
            self.assertTrue(publisher.rerun_statement(directory).startswith("Release jobs re-run after a failure: package"))

    def test_publication_reads_retry_server_errors_but_writes_never_repeat(self):
        # The class the publisher catches: the module loader above can leave
        # this test process with a second copy of urllib.error.
        HTTPError = publisher.HTTPError

        class Reply:
            def __enter__(self): return self
            def __exit__(self, *exc): return False
            def read(self): return b'{"status": "identical"}'

        def opener(errors):
            calls = []

            class Opener:
                def open(self, request, timeout):
                    calls.append(request.get_method())
                    error = next(errors)
                    if error:
                        raise HTTPError(request.full_url, error, "server error", {}, None)
                    return Reply()
            return calls, Opener()

        with patch.dict(os.environ, {"GH_TOKEN": "test-only"}):
            calls, fake = opener(iter([502, 502, None]))
            waits = []
            with patch.object(publisher, "build_opener", return_value=fake):
                self.assertEqual(publisher.api("repos/x/compare/a...main", sleep=waits.append), {"status": "identical"})
            self.assertEqual((calls, waits), (["GET"] * 3, [5, 10]))
            calls, fake = opener(iter([502] * 5))
            with patch.object(publisher, "build_opener", return_value=fake), \
                    self.assertRaisesRegex(ValueError, "failed 5 times"):
                publisher.api("repos/x/compare/a...main", sleep=lambda s: None)
            calls, fake = opener(iter([502, None]))
            with patch.object(publisher, "build_opener", return_value=fake), self.assertRaises(HTTPError):
                publisher.api("repos/x/releases", {"draft": True}, method="POST", sleep=lambda s: None)
            self.assertEqual(calls, ["POST"], "a write is never repeated")

    def test_cross_run_artifact_is_refused_before_download(self):
        metadata = {"expired": False, "workflow_run": {"id": 1, "head_sha": "a" * 40},
                    "digest": "sha256:" + "b" * 64, "size_in_bytes": 100}
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(transfer.release_attempts, "gh_get", return_value=json.dumps(metadata)), \
                patch.object(transfer.release_attempts, "gh_download") as download, \
                patch.dict(os.environ, {"GITHUB_REPOSITORY": "Velstra/sentinel", "GITHUB_RUN_ID": "2",
                                        "GITHUB_SHA": "a" * 40, "RELEASE_ARTIFACT_BYTE_BUDGET": "1000"}):
            with self.assertRaisesRegex(ValueError, "another run"):
                transfer.download("123", "b" * 64, Path(temp) / "output")
            download.assert_not_called()


if __name__ == "__main__": unittest.main()
