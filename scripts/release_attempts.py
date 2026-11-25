"""The one re-run a Community release may have, and which jobs came from it.

The owner allows GitHub's "Re-run failed jobs" once (run attempt 2), for
regression jobs that failed. Everything else a release depends on must come
from attempt 1: the plan, the build and every regression job that passed. The
jobs after the regressions (sign, package, seal, publish) never ran in attempt
1, because a failed regression skips them, so attempt 2 runs them freshly and
asks for every approval again. Anything else fails closed.
"""
import json
import os
import re
import subprocess

MAX_ATTEMPT = 2
FIRST_ATTEMPT_ONLY = ("plan", "build")
DOWNSTREAM = ("sign", "package", "seal", "publish")
REGRESSION = re.compile(r"regressions \(([a-zA-Z0-9_-]+)\)")
# The runner's own closing line for any failed step; it says nothing about why.
GENERIC_FAILURE = re.compile(r"Process completed with exit code \d+\.?")
PAGE_SIZE = 100
MAX_PAGES = 6


def attempt():
    """This run's attempt: 1, or 2 for the one allowed re-run."""
    value = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if value not in {str(n) for n in range(1, MAX_ATTEMPT + 1)}:
        raise ValueError("a release run may have at most one re-run attempt (GITHUB_RUN_ATTEMPT 1 or 2)")
    return int(value)


def by_name(jobs):
    if not isinstance(jobs, list) or any(not isinstance(j, dict) or not isinstance(j.get("name"), str)
                                         for j in jobs):
        raise ValueError("malformed job listing")
    named = {j["name"]: j for j in jobs}
    if len(named) != len(jobs):
        raise ValueError("ambiguous job listing: duplicate job names")
    return named


def reruns(first, second):
    """The regression jobs attempt 2 ran again, as {check: attempt-1 job}.

    `first` and `second` are GitHub's job listings of attempts 1 and 2; a job
    carried over from attempt 1 keeps run_attempt 1 in the second listing."""
    one, two = by_name(first), by_name(second)
    if set(one) != set(two):
        raise ValueError("the job set changed between attempts")
    if any(j.get("run_attempt") != 1 for j in first):
        raise ValueError("attempt 1 lists a job from another attempt")
    found = {}
    for name, job in two.items():
        before, again = one[name], job.get("run_attempt")
        if again not in (1, 2):
            raise ValueError(f"{name}: run attempt {again!r} is not allowed")
        regression = REGRESSION.fullmatch(name)
        if name in FIRST_ATTEMPT_ONLY:
            if again != 1 or before.get("conclusion") != "success":
                raise ValueError(f"{name} must have succeeded in attempt 1 and not run again")
        elif name in DOWNSTREAM:
            # It never ran in attempt 1, so no approval of attempt 1 can count.
            if before.get("conclusion") != "skipped":
                raise ValueError(f"{name} already ran in attempt 1; start a new run")
        elif regression:
            if again == 1 and before.get("conclusion") != "success":
                raise ValueError(f"{name} did not pass in attempt 1 and was not run again")
            if again == 2:
                if before.get("conclusion") != "failure":
                    raise ValueError(f"{name} was {before.get('conclusion')} in attempt 1; "
                                     "only a failed regression may run again")
                found[regression.group(1)] = before
        else:
            raise ValueError(f"unexpected job {name!r} in a release run")
    if not found:
        raise ValueError("attempt 2 re-ran no failed regression job")
    return found


def regressions_green(jobs):
    """Every regression job passed in its final attempt; one that failed twice blocks."""
    failing = sorted(REGRESSION.fullmatch(j["name"]).group(1) for j in jobs
                     if REGRESSION.fullmatch(j.get("name", "")) and j.get("conclusion") != "success")
    if failing:
        raise ValueError("regression checks not green in their final attempt: " + ", ".join(failing))


def first_failure(job, annotations):
    """One line saying why the job failed: its most specific failure annotation,
    else the runner's generic one, else the job's conclusion."""
    messages = [a["message"].strip() for a in annotations if isinstance(a, dict)
                and a.get("annotation_level") == "failure" and isinstance(a.get("message"), str)
                and a["message"].strip()]
    specific = [m for m in messages if not GENERIC_FAILURE.fullmatch(m)]
    text = (specific or messages or [f"job {job.get('conclusion')}"])[0]
    return text.splitlines()[0][:200]


def gh(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True, timeout=60))


def attempt_jobs(repository, run_id, number, fetch=gh):
    """Every job of one run attempt; a listing that does not add up fails."""
    jobs, total = [], None
    for page in range(1, MAX_PAGES + 1):
        document = fetch(f"repos/{repository}/actions/runs/{run_id}/attempts/{number}/jobs"
                         f"?per_page={PAGE_SIZE}&page={page}")
        if (not isinstance(document, dict) or type(document.get("total_count")) is not int
                or not isinstance(document.get("jobs"), list)
                or (total is not None and document["total_count"] != total)):
            raise ValueError("malformed or changing job listing")
        total = document["total_count"]
        jobs += document["jobs"]
        if len(jobs) >= total or not document["jobs"]:
            break
    if len(jobs) != total:
        raise ValueError("incomplete job listing")
    return jobs


def current(fetch=gh):
    """This run's re-runs, {check: {"first_failure", "first_job"}}: empty in
    attempt 1. Raises ValueError for an attempt or a job set the policy refuses."""
    number = attempt()
    if number == 1:
        return {}
    repository, run_id = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_RUN_ID"]
    first = attempt_jobs(repository, run_id, 1, fetch)
    second = attempt_jobs(repository, run_id, 2, fetch)
    found = reruns(first, second)
    regressions_green(second)
    record = {}
    for check, job in sorted(found.items()):
        # An Actions job is its own check run; prefer the URL GitHub gives.
        url = job.get("check_run_url") or ""
        check_run = url.split("api.github.com/", 1)[1] if "api.github.com/" in url else \
            f"repos/{repository}/check-runs/{job['id']}"
        annotations = fetch(f"{check_run}/annotations?per_page=50")
        record[check] = {"first_failure": first_failure(job, annotations if isinstance(annotations, list) else []),
                         "first_job": job.get("html_url")}
    return record
