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


# What makes an attempt-2 entry the attempt-1 job carried over. GitHub gives
# carried-over jobs a new id and run_attempt 2 (run 45642647509), so only
# these fields identify them.
CARRIED_OVER = ("name", "started_at", "completed_at", "conclusion")


def carried_over(before, after):
    return all(before.get(k) == after.get(k) for k in CARRIED_OVER)


def phantom(job):
    """An entry GitHub listed but never gave a runner (run 45642647509 listed
    33 of them for one re-run job). Its started_at is set anyway, to its
    creation time, so only the missing runner and completion tell it apart."""
    return (job.get("status") == "queued" and job.get("completed_at") is None
            and not job.get("runner_id") and not job.get("runner_name"))


def moved_on(jobs):
    """GitHub has gone past the regressions: a downstream job (sign) exists and
    has left the queue, so it no longer waits for any queued regression entry."""
    return any(j.get("name") in DOWNSTREAM and j.get("status") in ("waiting", "in_progress", "completed")
               for j in jobs)


def reruns(first, second):
    """The regression jobs attempt 2 ran again: {check: {"job": its attempt-1
    job, "runs": its attempt-2 entries that started, "phantoms": how many
    never did}}.

    `first` and `second` are GitHub's job listings of attempts 1 and 2. A job
    carried over from attempt 1 appears in attempt 2 with identical name,
    times and conclusion. A failed regression run again may appear in attempt
    2 more than once."""
    one = by_name(first)
    if any(j.get("run_attempt") != 1 for j in first):
        raise ValueError("attempt 1 lists a job from another attempt")
    if not isinstance(second, list) or any(not isinstance(j, dict) or not isinstance(j.get("name"), str)
                                           for j in second):
        raise ValueError("malformed job listing")
    entries = {}
    for job in second:
        entries.setdefault(job["name"], []).append(job)
    unknown = set(entries) - set(one)
    if unknown:
        raise ValueError("attempt 2 lists jobs attempt 1 did not have: " + ", ".join(sorted(unknown)))
    found = {}
    for name, before in one.items():
        after = entries.get(name, [])
        regression = REGRESSION.fullmatch(name)
        if name in DOWNSTREAM:
            # It never ran in attempt 1, so no approval of attempt 1 can count.
            # In attempt 2 it may be missing yet, or running now.
            if before.get("conclusion") != "skipped":
                raise ValueError(f"{name} already ran in attempt 1; start a new run")
        elif name in FIRST_ATTEMPT_ONLY or (regression and before.get("conclusion") == "success"):
            if (before.get("conclusion") != "success" or len(after) != 1
                    or not carried_over(before, after[0])):
                raise ValueError(f"{name} must pass in attempt 1 and be carried over unchanged")
        elif regression:
            if before.get("conclusion") != "failure":
                raise ValueError(f"{name} was {before.get('conclusion')} in attempt 1; "
                                 "only a failed regression may run again")
            ran = [job for job in after if not phantom(job)]
            if not ran or any(carried_over(before, job) for job in ran):
                raise ValueError(f"{name} failed in attempt 1 and was not run again")
            if len(ran) < len(after) and not moved_on(second):
                raise ValueError(f"{name}: attempt 2 still waits for {len(after) - len(ran)} queued entries")
            found[regression.group(1)] = {"job": before, "runs": ran, "phantoms": len(after) - len(ran)}
        else:
            raise ValueError(f"unexpected job {name!r} in a release run")
    if not found:
        raise ValueError("attempt 2 re-ran no failed regression job")
    return found


def regressions_green(jobs):
    """Every regression entry that ran finished green, and every regression ran:
    one that failed twice blocks, and so does any started entry that is not a
    completed success. A phantom entry counts only while GitHub still waits."""
    ignore = moved_on(jobs)
    counted = [j for j in jobs if REGRESSION.fullmatch(j.get("name", "")) and not (ignore and phantom(j))]
    failing = {REGRESSION.fullmatch(j["name"]).group(1) for j in counted
               if j.get("status") != "completed" or j.get("conclusion") != "success"}
    every = {REGRESSION.fullmatch(j["name"]).group(1) for j in jobs if REGRESSION.fullmatch(j.get("name", ""))}
    failing = sorted(failing | (every - {REGRESSION.fullmatch(j["name"]).group(1) for j in counted}))
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
    """This run's re-runs, {check: {"first_failure", "first_job", "runs", "phantoms"}}: empty in
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
    for check, rerun in sorted(found.items()):
        job = rerun["job"]
        # An Actions job is its own check run; prefer the URL GitHub gives.
        url = job.get("check_run_url") or ""
        check_run = url.split("api.github.com/", 1)[1] if "api.github.com/" in url else \
            f"repos/{repository}/check-runs/{job['id']}"
        annotations = fetch(f"{check_run}/annotations?per_page=50")
        record[check] = {"first_failure": first_failure(job, annotations if isinstance(annotations, list) else []),
                         "first_job": job.get("html_url"), "runs": len(rerun["runs"]),
                         "phantoms": rerun["phantoms"]}
    return record
