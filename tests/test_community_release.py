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


FIXTURES = ROOT / "tests/fixtures/run-45642647509"


def real_jobs(name):
    """A job listing GitHub returned for release run 45642647509."""
    return json.loads((FIXTURES / name).read_text())["jobs"]


def job(name, conclusion, run_attempt=1, number=None, started="2026-11-25T15:13:10Z"):
    """One entry of GitHub's attempt job listing."""
    number = number if number is not None else abs(hash(name)) % 10**9
    return {"id": number, "name": name, "status": "completed", "conclusion": conclusion,
            "run_attempt": run_attempt, "started_at": started, "completed_at": started.replace("15:", "16:"),
            "html_url": f"https://github.com/Velstra/sentinel/actions/runs/42/job/{number}"}


def listings(failed=("rip",), passed=("nat", "commit"), first_overrides=None, second_overrides=None):
    """Attempt 1, where the `failed` regressions failed and everything downstream
    was skipped, and the attempt 2 "Re-run failed jobs" makes of it, shaped as
    GitHub really lists it: every carried-over job again, with a new id and
    run_attempt 2 but its attempt-1 times; downstream jobs not yet listed."""
    first = [job("plan", "success"), job("build", "success")]
    first += [job(f"regressions ({c})", "success") for c in passed]
    first += [job(f"regressions ({c})", "failure") for c in failed]
    first += [job(n, "skipped") for n in ("sign", "package", "seal", "publish")]
    for name, change in (first_overrides or {}).items():
        next(j for j in first if j["name"] == name).update(change)
    second = []
    for entry in first:
        if entry["name"] in ("sign", "package", "seal", "publish"):
            continue
        copy = entry | {"id": entry["id"] + 1, "run_attempt": 2}
        if entry["name"] in {f"regressions ({c})" for c in failed}:
            copy |= {"conclusion": "success", "started_at": "2026-11-25T20:23:13Z",
                     "completed_at": "2026-11-25T20:48:02Z", "html_url": entry["html_url"] + "-2"}
        second.append(copy)
    for name, change in (second_overrides or {}).items():
        next(j for j in second if j["name"] == name).update(change)
    return first, second


class ReRunPolicyTests(unittest.TestCase):
    """The owner allows "Re-run failed jobs" once, for regression jobs that
    failed. The plan, the build and every regression that passed come from
    attempt 1; the downstream jobs never ran in attempt 1, so none of their
    approvals can be reused."""

    def test_only_attempts_one_and_two_are_accepted(self):
        for value in ("1", "2"):
            with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": value}):
                self.assertEqual(attempts.attempt(), int(value))
        for value in ("3", "0", "", "2a"):
            with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": value}), self.subTest(value=value), \
                    self.assertRaises(ValueError):
                attempts.attempt()

    def test_a_failed_regression_may_run_once_more(self):
        first, second = listings(failed=("rip", "reboot"))
        found = attempts.reruns(first, second)
        self.assertEqual(sorted(found), ["reboot", "rip"])
        self.assertEqual(found["rip"]["job"]["conclusion"], "failure")
        self.assertEqual(len(found["rip"]["runs"]), 1)

    def test_nothing_else_may_change(self):
        cases = {
            "the plan was run again": listings(second_overrides={"plan": {"started_at": "2026-11-25T20:23:13Z"}}),
            "the build was run again": listings(second_overrides={"build": {"completed_at": "2026-11-25T21:00:00Z"}}),
            "the build failed in attempt 1": listings(first_overrides={"build": {"conclusion": "failure"}},
                                                      second_overrides={"build": {"conclusion": "failure"}}),
            "a passing regression was run again": listings(
                second_overrides={"regressions (nat)": {"started_at": "2026-11-25T20:23:13Z"}}),
            "the failed regression was only carried over": listings(
                second_overrides={"regressions (rip)": {"conclusion": "failure", "started_at": "2026-11-25T15:13:10Z",
                                                        "completed_at": "2026-11-25T16:13:10Z"}}),
            "a cancelled regression was run again": listings(first_overrides={"regressions (rip)": {"conclusion": "cancelled"}}),
            "a timed-out regression was run again": listings(first_overrides={"regressions (rip)": {"conclusion": "timed_out"}}),
            "sign ran in attempt 1": listings(first_overrides={"sign": {"conclusion": "success"}}),
            "publish ran in attempt 1": listings(first_overrides={"publish": {"conclusion": "failure"}}),
            "attempt 2 re-ran nothing": listings(failed=()),
        }
        first, second = listings()
        cases["a job appeared"] = (first, second + [job("regressions (new)", "success", 2)])
        cases["a job disappeared"] = (first, [j for j in second if j["name"] != "regressions (nat)"])
        cases["an unknown job"] = (first + [job("debug", "success")], second + [job("debug", "success")])
        cases["a duplicate name in attempt 1"] = (first + [first[2]], second)
        cases["a passing regression listed twice"] = (first, second + [second[2] | {"id": 1}])
        for reason, (one, two) in cases.items():
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                attempts.reruns(one, two)

    def test_the_real_re_run_of_run_45642647509_while_it_ran(self):
        # Every carried-over job came back with a new id and run_attempt 2;
        # routed-reply, the one failure, was listed 34 times: 1 running, 33
        # queued, and sign not created yet. GitHub still waited, so do we.
        first, second = real_jobs("attempt-1.json"), real_jobs("attempt-2-in-progress.json")
        with self.assertRaisesRegex(ValueError, "still waits for 33"):
            attempts.reruns(first, second)
        with self.assertRaisesRegex(ValueError, "routed-reply"):
            attempts.regressions_green(second)
        plan = next(k for k, j in enumerate(second) if j["name"] == "plan")
        moved = second[:plan] + [second[plan] | {"started_at": "2026-11-25T20:23:13Z"}] + second[plan + 1:]
        with self.assertRaisesRegex(ValueError, "plan"):
            attempts.reruns(first, moved)

    def test_the_real_re_run_of_run_45642647509_once_sign_waits(self):
        # The one real re-run passed; 33 entries never got a runner (started_at
        # is their creation time); sign is waiting for its approval.
        first, second = real_jobs("attempt-1.json"), real_jobs("attempt-2-sign-waiting.json")
        found = attempts.reruns(first, second)
        self.assertEqual({k: (len(v["runs"]), v["phantoms"]) for k, v in found.items()}, {"routed-reply": (1, 33)})
        attempts.regressions_green(second)
        rerun = "regressions (routed-reply)"
        without_sign = [j for j in second if j["name"] != "sign"]
        with self.assertRaisesRegex(ValueError, "still waits for 33"):
            attempts.reruns(first, without_sign)
        with self.assertRaisesRegex(ValueError, "routed-reply"):
            attempts.regressions_green(without_sign)
        real = next(k for k, j in enumerate(second) if j["name"] == rerun and j["status"] == "completed")
        failed = second[:real] + [second[real] | {"conclusion": "failure"}] + second[real + 1:]
        with self.assertRaisesRegex(ValueError, "routed-reply"):
            attempts.regressions_green(failed)
        queued = next(k for k, j in enumerate(second) if j["name"] == rerun and j["status"] == "queued")
        started = second[:queued] + [second[queued] | {"runner_name": "GitHub Actions 7", "runner_id": 7}] + second[queued + 1:]
        with self.assertRaisesRegex(ValueError, "routed-reply"):
            attempts.regressions_green(started)
        only_phantoms = [j for j in second if not (j["name"] == rerun and j["status"] == "completed")]
        with self.assertRaisesRegex(ValueError, "not run again"):
            attempts.reruns(first, only_phantoms)

    def test_a_regression_that_fails_twice_blocks_the_release(self):
        first, second = listings(second_overrides={"regressions (rip)": {"conclusion": "failure"}})
        attempts.reruns(first, second)
        with self.assertRaisesRegex(ValueError, "rip"):
            attempts.regressions_green(second)
        attempts.regressions_green(listings()[1])

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

    def test_the_current_run_is_judged_from_the_api(self):
        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "42",
                                     "GITHUB_REPOSITORY": "Velstra/sentinel"}):
            self.assertEqual(attempts.current(fetch=lambda path: self.fail(path)), {})
        first, second = listings()
        rip = next(j for j in first if j["name"] == "regressions (rip)")

        def fetch(path):
            if "/attempts/" in path:
                listing = first if "/attempts/1/" in path else second
                return {"total_count": len(listing), "jobs": listing}
            self.assertIn(f"check-runs/{rip['id']}/annotations", path)
            return [{"annotation_level": "failure", "message": "rip failed: OSPF never converged"}]

        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2", "GITHUB_RUN_ID": "42",
                                     "GITHUB_REPOSITORY": "Velstra/sentinel"}):
            self.assertEqual(attempts.current(fetch=fetch), {"rip": {
                "first_failure": "rip failed: OSPF never converged", "first_job": rip["html_url"], "runs": 1,
                "phantoms": 0}})

    def test_receipts_must_come_from_the_attempt_that_ran_them(self):
        from types import SimpleNamespace
        names = sorted(release.REQUIRED_SAFETY_CHECKS | {"rip"})
        reruns = {"rip": {"first_failure": "rip failed", "first_job": "https://example.invalid/job/1", "runs": 1}}
        with tempfile.TemporaryDirectory() as temp, patch.object(release, "source", return_value="a" * 40), \
                patch.object(release, "run", return_value=json.dumps(names)), \
                patch.object(attempts, "current", return_value=reruns), \
                patch.dict(os.environ, {"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "2"}):
            directory = Path(temp)
            args = SimpleNamespace(input=directory, output=directory / "complete.txt")
            base = {"source": "a" * 40, "completed_at": int(time.time())}
            for name in release.REQUIRED_SAFETY_CHECKS:
                (directory / f"{name}.json").write_text(json.dumps(base | {"check": name, "run": "42-1"}))
            (directory / "rip.json").write_text(json.dumps(base | {"check": "rip", "run": "42-1"}))
            with self.assertRaises(ValueError): release.aggregate(args)
            (directory / "rip.json").write_text(json.dumps(base | {"check": "rip", "run": "42-2"}))
            release.aggregate(args)
            summary = json.loads(args.output.read_text())
            self.assertEqual((summary["run"], summary["reruns"]), ("42-2", reruns))
            nat = next(iter(sorted(release.REQUIRED_SAFETY_CHECKS)))
            (directory / f"{nat}.json").write_text(json.dumps(base | {"check": nat, "run": "42-2"}))
            with self.assertRaises(ValueError): release.aggregate(args)

    def test_the_bundle_records_exactly_the_reruns_of_its_attempt(self):
        names = ["nat", "rip"]
        record = {"rip": {"first_failure": "rip failed", "first_job": "https://example.invalid/job/1", "runs": 1}}
        self.assertEqual(release.expected_receipt_runs({"run": "42-2", "reruns": record}, names, "42", 2),
                         {"nat": "42-1", "rip": "42-2"})
        self.assertEqual(release.expected_receipt_runs({"run": "42-1"}, names, "42", 1),
                         {"nat": "42-1", "rip": "42-1"})
        for bad in ({"run": "42-1", "reruns": record},                   # attempt 1 with a re-run
                    {"run": "42-2", "reruns": {}},                       # attempt 2 that re-ran nothing
                    {"run": "42-2", "reruns": {"other": record["rip"]}},  # not a catalogued check
                    {"run": "42-2", "reruns": {"rip": {"first_failure": 1}}},
                    {"run": "42-2", "reruns": {"rip": record["rip"] | {"runs": 0}}},
                    {"run": "42-2", "reruns": {"rip": record["rip"] | {"phantoms": -1}}},
                    {"run": "42-1", "reruns": []}):
            number = int(bad["run"][-1])
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                release.expected_receipt_runs(bad, names, "42", number)

    def test_approval_is_checked_only_for_an_allowed_attempt(self):
        environment, history = {"id": 7}, [{"state": "approved", "environments": [{"id": 7}],
                                             "user": {"type": "User", "login": "reviewer"}}]
        with patch.object(attempts, "current", return_value={}) as current:
            protection.approved(environment, history, {"owner"})
        current.assert_called_once()
        with patch.object(attempts, "current", side_effect=ValueError("a release run may have at most one re-run")), \
                self.assertRaises(ValueError):
            protection.approved(environment, history, {"owner"})


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
                           ("RELEASE_PUBLISH_REQUESTED", "false"), ("GITHUB_RUN_ATTEMPT", "3")):
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

    def test_release_body_lists_reruns_with_their_first_failure(self):
        reruns = {"rip": {"first_failure": "rip failed: OSPF never converged",
                          "first_job": "https://github.com/Velstra/sentinel/actions/runs/42/job/7", "runs": 34}}
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, directory)
        (directory / "source-checks.json").write_text(json.dumps({"checks": [], "reruns": reruns}))
        with patch.object(attempts, "current", return_value=reruns):
            self.assertEqual(publisher.rerun_statement(directory),
                             "Regression checks re-run once after a failure: rip (first failure: "
                             "rip failed: OSPF never converged; attempt-1 log: "
                             "https://github.com/Velstra/sentinel/actions/runs/42/job/7; "
                             "attempt 2 ran it 34 times (all passed)).")
        self.assertEqual(publisher.rerun_count({"runs": 1, "phantoms": 33}),
                         "attempt 2 ran it once (passed); 33 phantom entries were listed but never started")
        self.assertEqual(publisher.rerun_count({"runs": 1, "phantoms": 1}),
                         "attempt 2 ran it once (passed); 1 phantom entry was listed but never started")
        with patch.object(attempts, "current", return_value={}), \
                self.assertRaisesRegex(ValueError, "re-run"):
            publisher.rerun_statement(directory)
        (directory / "source-checks.json").write_text(json.dumps({"checks": []}))
        with patch.object(attempts, "current", return_value={}):
            self.assertEqual(publisher.rerun_statement(directory), "")

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
