#!/usr/bin/env python3
"""Require an actually protected release environment, not just a YAML name."""
import argparse
import itertools
import json
import os
import re
from pathlib import Path
import sys
from urllib.parse import quote

# The release scripts import each other by name. Put this file's own directory
# on the path, so that works however the file is loaded: as a script, through
# `python3 -c`, or by importlib from a test.
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_attempts  # noqa: E402

# Single-operator mode: the shortest wait_timer (minutes) an environment may
# carry, so a run started with a stolen token cannot release before the owner
# can reject it.
SINGLE_OPERATOR_MIN_WAIT_MINUTES = 30
# A run of this workflow has at most a handful of runs per protected job.
MAX_MATCHED_RUNS = 6
# The one job each environment admits.
ENVIRONMENT_JOBS = {"community-signing": "sign", "community-attestation": "seal", "community-publish": "publish"}


def single_operator_enabled():
    """Opt-in only: the repository variable must be exactly `true`."""
    return os.environ.get("RELEASE_SINGLE_OPERATOR") == "true"


def approvals_statement():
    """The line a release made in single-operator mode carries; None otherwise."""
    if not single_operator_enabled():
        return None
    return ("Release approvals: single-operator mode "
            f"(one maintainer, wait timer \u2265 {SINGLE_OPERATOR_MIN_WAIT_MINUTES} min).")


def rules_of(environment, kind):
    return [r for r in environment.get("protection_rules") or [] if r.get("type") == kind]


def validate_single_operator(environment):
    reviewers = rules_of(environment, "required_reviewers")
    if (len(reviewers) != 1 or not reviewers[0].get("reviewers")
            or environment.get("can_admins_bypass") is True):
        raise ValueError("single-operator mode requires one reviewer rule with a reviewer and no admin bypass")
    timers = rules_of(environment, "wait_timer")
    if (len(timers) != 1 or type(timers[0].get("wait_timer")) is not int
            or timers[0]["wait_timer"] < SINGLE_OPERATOR_MIN_WAIT_MINUTES):
        raise ValueError("single-operator mode requires a wait timer of at least "
                         f"{SINGLE_OPERATOR_MIN_WAIT_MINUTES} minutes")


def validate(environment, branches, single_operator=False):
    policy = environment.get("deployment_branch_policy") or {}
    if single_operator:
        validate_single_operator(environment)
    else:
        rules = [r for r in environment.get("protection_rules", []) if r.get("type") == "required_reviewers"]
        if (len(rules) != 1 or not rules[0].get("reviewers")
                or rules[0].get("prevent_self_review") is not True
                or environment.get("can_admins_bypass") is True):
            raise ValueError("required reviewers and prevent-self-review must be enabled")
    entries = branches.get("branch_policies", [])
    if (type(branches.get("total_count")) is not int
            or branches["total_count"] != len(entries) or not 1 <= len(entries) <= 2):
        raise ValueError("complete exact release branch policies required")
    names = {(b.get("type"), b.get("name")) for b in entries}
    if (policy != {"protected_branches": False, "custom_branch_policies": True}
            or not names or not names <= {("branch", "main"), ("tag", "v*")}
            or ("branch", "main") not in names):
        raise ValueError("only main and optional v* tags may enter the release environment")


def matched(logins, runs):
    """Some order of the approvers gives every run an approver it allows."""
    return any(all(login not in forbidden for login, forbidden in zip(order, runs))
               for order in itertools.permutations(logins))


def approval(environment, history, actors, single_operator=False, runs=1):
    """A human approval in this environment for each run its job has had in
    this run, the run now included. `runs` is how many, or, per run, the
    logins that may not approve it (who dispatched the run and who started
    that run's attempt); a count stands for runs all forbidding `actors`.

    GitHub's review history covers every attempt of the run and says neither
    when nor in which attempt a review was given (run 45868284650). So the
    approvals are counted: one per run, never one shared by two runs. A wait
    timer that elapsed is listed as an approval by github-actions[bot] and
    counts for nothing; a rejected review closed the gate, so its job never
    got a runner, made no run and may run again with a new approval."""
    if not isinstance(history, list):
        raise ValueError("approval history unavailable")
    if type(runs) is int:
        runs = [set(actors)] * runs
    relevant = [r for r in history if isinstance(r, dict) and any(
        isinstance(e, dict) and e.get("id") == environment.get("id") for e in r.get("environments") or [])]
    if any(r.get("state") not in ("approved", "rejected") for r in relevant):
        raise ValueError("an actual human approval for this run is required")
    humans = [r["user"]["login"] for r in relevant if r.get("state") == "approved"
              and isinstance(r.get("user"), dict) and r["user"].get("type") == "User"
              and isinstance(r["user"].get("login"), str) and r["user"]["login"]]
    if not runs or len(humans) != len(runs) or len(runs) > MAX_MATCHED_RUNS:
        raise ValueError(f"{len(humans)} human approval(s) for {len(runs)} run(s) of this job in this run; "
                         "every run needs an approval of its own")
    # The one maintainer may approve their own run, but the approval must
    # exist: a job that merely started (bypass, no rule) is not one.
    if not single_operator and not matched(humans, runs):
        raise ValueError("an actual independent human approval for each run is required")


def approved(environment, history, actors, single_operator=False, job=None):
    """The approvals for this job on a GitHub-hosted runner, in an attempt the
    re-run policy allows: one per run of the job, each by someone who neither
    dispatched the run nor started that run's attempt (GitHub says who did).
    `actors` are this attempt's, as the job sees them. Returns the re-run record."""
    record = release_attempts.current()
    release_attempts.require_github_hosted()
    if record["attempt"] == 1:
        runs = [set(actors)]
    else:
        runs = [set(record["actors"][n - 1]) | (set(actors) if n == record["attempt"] else set())
                for n in record["gates"].get(job, [])]
    approval(environment, history, actors, single_operator, runs)
    return record


def response_document(raw):
    parts = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
    if (len(parts) != 2 or not parts[0].startswith("HTTP/")
            or any(line.lower().startswith("link:") for line in parts[0].splitlines())):
        raise ValueError("incomplete or paginated protection response")
    return json.loads(parts[1])


def api(path):
    return response_document(release_attempts.gh_get(["--include", path]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("environment")
    parser.add_argument("--approved", action="store_true")
    args = parser.parse_args()
    root = f"repos/{os.environ['GITHUB_REPOSITORY']}/environments/{quote(args.environment, safe='')}"
    environment = api(root)
    if environment.get("name") != args.environment or type(environment.get("id")) is not int:
        raise ValueError("environment identity mismatch")
    single = single_operator_enabled()
    validate(environment, api(root + f"/deployment-branch-policies?per_page={release_attempts.PAGE_SIZE}"), single)
    if args.approved:
        record = approved(environment, api(f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/runs/"
                                           f"{os.environ['GITHUB_RUN_ID']}/approvals"),
                          {os.environ.get("GITHUB_ACTOR"), os.environ.get("GITHUB_TRIGGERING_ACTOR")}, single,
                          ENVIRONMENT_JOBS[args.environment])
        rerun = sorted(record["checks"]) + sorted(record["jobs"])
        if rerun:
            print(f"::notice title=Re-run attempt::attempt {record['attempt']} follows failed jobs re-run: "
                  + ", ".join(rerun))
    if single:
        print(f"::notice title={args.environment}::{approvals_statement()}")
