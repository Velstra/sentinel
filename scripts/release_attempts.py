"""The re-runs a Community release may have, and which jobs came from which.

The owner allows GitHub's "Re-run failed jobs" up to run attempt 3, for jobs
that failed. Every job that passed is carried over unchanged into each later
attempt: the plan, the build, every passing regression and every release job
(sign, package, seal, publish) that passed before. A job that failed may run
again in the next attempt, the plan excepted; a release job that only ran
because an earlier one failed runs for the first time. Every run of a
protected job needs an approval of its own. Anything else fails closed.
"""
import json
import os
import re
import subprocess
import time

MAX_ATTEMPT = 3
# A plan that failed cost nothing; start a new run instead.
FIRST_ATTEMPT_ONLY = ("plan",)
DOWNSTREAM = ("sign", "package", "seal", "publish")
# Jobs that must be green before any downstream job may act on their output.
UPSTREAM = ("plan", "build")
REGRESSION = re.compile(r"regressions \(([a-zA-Z0-9_-]+)\)")
# What may run again. A timeout is a failure of the job; a cancelled job was
# stopped on purpose and is a reason to start a new run, except when GitHub
# cancelled it at the job's time limit (hit_time_limit).
RERUNNABLE = ("failure", "timed_out")
# GitHub reports a job that hit timeout-minutes as "cancelled" (package of run
# 45963560974, 6 h); only this failure annotation tells it from a cancel.
TIME_LIMIT = re.compile(r"The job has exceeded the maximum execution time of \d+h\d+m\d+s")
# The runner's own closing line for any failed step; it says nothing about why.
GENERIC_FAILURE = re.compile(r"Process completed with exit code \d+\.?")
# GitHub answers 502 for a 100-entry page of a large run (run 45642647509,
# 243 jobs); 30 per page works. 20 pages cover 600 entries.
PAGE_SIZE = 30
MAX_PAGES = 20
# Waits between the attempts of one API read; a 5xx is retried, nothing else.
API_RETRY_DELAYS = (5, 10, 20, 40)


def attempt():
    """This run's attempt: 1 to MAX_ATTEMPT."""
    value = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if value not in {str(n) for n in range(1, MAX_ATTEMPT + 1)}:
        raise ValueError(f"a release run may have at most {MAX_ATTEMPT - 1} re-run attempts "
                         f"(GITHUB_RUN_ATTEMPT 1 to {MAX_ATTEMPT})")
    return int(value)


def require_github_hosted():
    """Keys, signed bytes and release artifacts never reach a runner the
    project operates itself; only the regression checks may run there."""
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise ValueError("this release job must run on a GitHub-hosted runner "
                         f"(RUNNER_ENVIRONMENT={os.environ.get('RUNNER_ENVIRONMENT')!r})")


def by_name(jobs):
    if not isinstance(jobs, list) or any(not isinstance(j, dict) or not isinstance(j.get("name"), str)
                                         for j in jobs):
        raise ValueError("malformed job listing")
    named = {j["name"]: j for j in jobs}
    if len(named) != len(jobs):
        raise ValueError("ambiguous job listing: duplicate job names")
    return named


# What makes a later entry the earlier job carried over. GitHub gives
# carried-over jobs a new id and the new run_attempt (run 45642647509), so
# only these fields identify them.
CARRIED_OVER = ("name", "started_at", "completed_at", "conclusion")


def carried_over(before, after):
    return all(before.get(k) == after.get(k) for k in CARRIED_OVER)


def phantom(job):
    """An entry GitHub listed but never gave a runner (run 45642647509 listed
    33 of them for one re-run job). Its started_at is set anyway, to its
    creation time, so only the missing runner and completion tell it apart."""
    return (job.get("status") == "queued" and job.get("completed_at") is None
            and not job.get("runner_id") and not job.get("runner_name"))


def ran(job):
    """The entry got a runner: it passed its environment's protection, if any."""
    return bool(job.get("runner_id") or job.get("runner_name"))


def moved_on(jobs, latest):
    """GitHub has gone past the regressions in this attempt: a downstream job
    it created anew (not one carried over, per `latest`, the jobs' states
    before this attempt) has left the queue, so GitHub no longer waits for
    any queued regression entry."""
    return any(j.get("name") in DOWNSTREAM and j.get("status") in ("waiting", "in_progress", "completed")
               and not any(carried_over(b, j) for b in latest[j["name"]]["entries"]) for j in jobs)


def outcome(entries):
    """One conclusion for the entries a job had in one attempt: success only
    when every one finished green."""
    if any(j.get("status") != "completed" for j in entries):
        return "in_progress"
    conclusions = {j.get("conclusion") for j in entries}
    if conclusions <= {"success"}:
        return "success"
    if conclusions <= {"skipped"}:
        return "skipped"
    if conclusions <= {"success", *RERUNNABLE}:
        return "failure" if "failure" in conclusions else "timed_out"
    return sorted(str(c) for c in conclusions - {"success", *RERUNNABLE})[0]


def hit_time_limit(annotations):
    """GitHub's own annotation says the job ran out of time."""
    return isinstance(annotations, list) and any(
        isinstance(a, dict) and a.get("annotation_level") == "failure" and isinstance(a.get("message"), str)
        and TIME_LIMIT.fullmatch(a["message"].strip()) for a in annotations)


def listing_of(jobs, number):
    if not isinstance(jobs, list) or any(not isinstance(j, dict) or not isinstance(j.get("name"), str)
                                         for j in jobs):
        raise ValueError("malformed job listing")
    if any(j.get("run_attempt") != number for j in jobs):
        raise ValueError(f"attempt {number} lists a job from another attempt")
    entries = {}
    for job in jobs:
        entries.setdefault(job["name"], []).append(job)
    return entries


def known(name):
    return name in FIRST_ATTEMPT_ONLY or name in UPSTREAM or name in DOWNSTREAM or REGRESSION.fullmatch(name)


def rerunnable(before, timed_out):
    """The job's latest state allows a re-run: it failed, or GitHub cancelled
    every cancelled entry of it at the time limit."""
    if before["conclusion"] in RERUNNABLE:
        return True
    return before["conclusion"] == "cancelled" and all(
        timed_out(job) for job in before["entries"] if job.get("conclusion") == "cancelled")


def judge(name, before, listed, number, waiting, timed_out):
    """What attempt `number` did with one job, given its latest state before:
    None when it kept that state (carried over, or not reached yet), else
    (its fresh entries, the phantoms listed with them, whether it is a re-run
    after a failure). Raises for anything the policy refuses."""
    real = [j for j in listed if not phantom(j)]
    phantoms = len(listed) - len(real)
    if phantoms and waiting:
        raise ValueError(f"{name}: attempt {number} still waits for {phantoms} queued entries")
    kept = [j for j in real if any(carried_over(b, j) for b in before["entries"])]
    fresh = [j for j in real if j not in kept]
    if before["conclusion"] == "success":
        if len(real) != 1 or not kept:
            raise ValueError(f"{name} passed in attempt {before['attempt']} and must be carried over unchanged")
        return None
    if rerunnable(before, timed_out):
        if kept or (not fresh and name not in DOWNSTREAM):
            raise ValueError(f"{name} failed in attempt {before['attempt']} and was not run again")
        # A release job whose turn has not come in this attempt keeps its state.
        return (fresh, phantoms, True) if fresh else None
    if before["conclusion"] == "skipped" and name in DOWNSTREAM:
        return (fresh, phantoms, False) if fresh else None
    raise ValueError(f"{name} was {before['conclusion']} in attempt {before['attempt']}; "
                     "only a failed job may run again; start a new run")


def review(listings, timed_out=lambda job: False):
    """Judge every attempt of a run against the one before it.

    `listings` are GitHub's job listings of attempts 1..N, N being the attempt
    that runs now; `timed_out(job)` says whether a cancelled entry hit its
    time limit (read from GitHub, asked only when a later attempt judges it).
    Returns {"reruns": {job: {"job": its first failed entry,
    "failed_in", "attempts": the later attempts that ran it, "runs",
    "phantoms"}}, "runs": {job: how many of its entries got a runner, over all
    attempts}, "gates": {job: the attempt of each of those runs}, "latest":
    {job: {"attempt", "conclusion", "entries"}}}."""
    if not isinstance(listings, list) or not listings or not 1 <= len(listings) <= MAX_ATTEMPT:
        raise ValueError("malformed attempt listings")
    first = listings[0]
    one = by_name(first)
    listing_of(first, 1)
    unexpected = sorted(name for name in one if not known(name))
    if unexpected:
        raise ValueError(f"unexpected job {unexpected[0]!r} in a release run")
    if one.get("plan", {}).get("conclusion") != "success":
        raise ValueError("plan must pass in attempt 1; start a new run")
    latest = {name: {"attempt": 1, "conclusion": outcome([job]), "entries": [job]} for name, job in one.items()}
    gates = {name: [1] if ran(job) else [] for name, job in one.items()}
    reruns = {}
    for number, jobs in enumerate(listings[1:], start=2):
        entries = listing_of(jobs, number)
        unknown = set(entries) - set(one)
        if unknown:
            raise ValueError(f"attempt {number} lists jobs attempt 1 did not have: " + ", ".join(sorted(unknown)))
        waiting = number == len(listings) and not moved_on(jobs, latest)
        reran = False
        for name in one:
            step = judge(name, latest[name], entries.get(name, []), number, waiting, timed_out)
            if step is None:
                continue
            fresh, phantoms, rerun = step
            if rerun:
                entry = reruns.setdefault(name, {"job": latest[name]["entries"][0],
                                                 "failed_in": latest[name]["attempt"],
                                                 "attempts": [], "runs": 0, "phantoms": 0})
                entry["attempts"].append(number)
                entry["runs"] += len(fresh)
                entry["phantoms"] += phantoms
                reran = True
            latest[name] = {"attempt": number, "conclusion": outcome(fresh), "entries": fresh}
            gates[name] += [number for j in fresh if ran(j)]
        if not reran:
            raise ValueError(f"attempt {number} re-ran no failed job")
    return {"reruns": reruns, "runs": {name: len(g) for name, g in gates.items()}, "gates": gates,
            "latest": latest}


def require_green(history):
    """The plan, the build and every regression check are green in their
    latest attempt: a check that failed in its last allowed attempt blocks,
    and so does any entry that is still running."""
    failing = [name for name in UPSTREAM if history["latest"][name]["conclusion"] != "success"]
    failing += sorted(REGRESSION.fullmatch(name).group(1) for name, state in history["latest"].items()
                      if REGRESSION.fullmatch(name) and state["conclusion"] != "success")
    if failing:
        raise ValueError("not green in their final attempt: " + ", ".join(failing))


def first_failure(job, annotations):
    """One line saying why the job failed: its most specific failure annotation,
    else the runner's generic one, else the job's conclusion."""
    messages = [a["message"].strip() for a in annotations if isinstance(a, dict)
                and a.get("annotation_level") == "failure" and isinstance(a.get("message"), str)
                and a["message"].strip()]
    specific = [m for m in messages if not GENERIC_FAILURE.fullmatch(m)]
    text = (specific or messages or [f"job {job.get('conclusion')}"])[0]
    return text.splitlines()[0][:200]


def retrying(args, once, sleep=time.sleep):
    """Run one `gh api` read until it succeeds. A server error (HTTP 5xx) or a
    timeout is retried after API_RETRY_DELAYS; anything else, or the last
    failure, fails closed with what GitHub said."""
    for attempt, delay in enumerate((*API_RETRY_DELAYS, None), start=1):
        try:
            result = once()
        except subprocess.TimeoutExpired:
            reason = "timed out"
        else:
            if result.returncode == 0:
                return result
            stderr = result.stderr or ""
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            lines = stderr.strip().splitlines()
            reason = lines[-1] if lines else f"exit {result.returncode}"
            if not re.search(r"HTTP 5\d\d", reason):
                raise ValueError(f"GitHub API read {args[-1]} failed: {reason}")
        if delay is None:
            raise ValueError(f"GitHub API read {args[-1]} failed {attempt} times; last: {reason}")
        sleep(delay)


def gh_get(args, run=subprocess.run, sleep=time.sleep):
    """The output of `gh api ARGS`, a read, retried like `retrying`."""
    command = ["gh", "api", *args]
    return retrying(args, lambda: run(command, capture_output=True, text=True, timeout=60), sleep).stdout


def gh_download(args, target, run=subprocess.run, sleep=time.sleep, timeout=1800):
    """`gh api ARGS` written to `target` (an artifact zip), retried like
    `retrying`; every attempt starts the file afresh."""
    command = ["gh", "api", *args]

    def once():
        with open(target, "wb") as stream:
            return run(command, stdout=stream, stderr=subprocess.PIPE, timeout=timeout)

    retrying(args, once, sleep)


def gh(path):
    return json.loads(gh_get([path]))


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


def check_run(job, repository):
    """The check run of an Actions job; prefer the URL GitHub gives."""
    url = job.get("check_run_url") or ""
    return url.split("api.github.com/", 1)[1] if "api.github.com/" in url else \
        f"repos/{repository}/check-runs/{job['id']}"


def starters(document, number):
    """[who dispatched the run, who started attempt `number`], from GitHub's
    run-attempt document."""
    logins = [document.get(key, {}).get("login") if isinstance(document, dict)
              and isinstance(document.get(key), dict) else None for key in ("actor", "triggering_actor")]
    if (not isinstance(document, dict) or document.get("run_attempt") != number
            or not all(isinstance(login, str) and login for login in logins)):
        raise ValueError(f"malformed run attempt {number}")
    return logins


FIRST = {"attempt": 1, "checks": {}, "jobs": {}, "runs": {}, "gates": {}, "actors": [], "ran_in": {}}
_CURRENT = {}


def current(fetch=gh):
    """This run's re-runs, as GitHub lists its attempts: {"attempt", "checks":
    {check: record}, "jobs": {job: record}, "runs": {job: runs over all
    attempts}, "gates": {job: the attempt of each run}, "actors": [[who
    dispatched, who started] per attempt], "ran_in": {job: the attempt of its
    latest run}}, each record
    {"first_failure", "first_job", "failed_in", "attempts", "runs",
    "phantoms"}. Attempt 1 has no re-runs and reads nothing. Raises ValueError
    for an attempt or a job set the policy refuses, or an upstream job that
    is not green."""
    number = attempt()
    if number == 1:
        return json.loads(json.dumps(FIRST))
    repository, run_id = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_RUN_ID"]
    key = (repository, run_id, number)
    if fetch is gh and key in _CURRENT:
        return json.loads(json.dumps(_CURRENT[key]))
    # A failed read of the annotations fails the whole judgement.
    def timed_out(job):
        return hit_time_limit(fetch(f"{check_run(job, repository)}/annotations?per_page={PAGE_SIZE}"))

    history = review([attempt_jobs(repository, run_id, n, fetch) for n in range(1, number + 1)], timed_out)
    require_green(history)
    record = {"attempt": number, "checks": {}, "jobs": {}, "runs": history["runs"], "gates": history["gates"],
              "actors": [starters(fetch(f"repos/{repository}/actions/runs/{run_id}/attempts/{n}"), n)
                         for n in range(1, number + 1)],
              "ran_in": {name: state["attempt"] for name, state in history["latest"].items()}}
    for name, rerun in sorted(history["reruns"].items()):
        job = rerun["job"]
        annotations = fetch(f"{check_run(job, repository)}/annotations?per_page={PAGE_SIZE}")
        regression = REGRESSION.fullmatch(name)
        record["checks" if regression else "jobs"][regression.group(1) if regression else name] = {
            "first_failure": first_failure(job, annotations if isinstance(annotations, list) else []),
            "first_job": job.get("html_url"), "failed_in": rerun["failed_in"], "attempts": rerun["attempts"],
            "runs": rerun["runs"], "phantoms": rerun["phantoms"]}
    if fetch is gh:
        _CURRENT[key] = json.loads(json.dumps(record))
    return record


def gate_runs(record, name):
    """How many times the job `name` has passed its environment gate in this
    run, the run now included."""
    return 1 if record["attempt"] == 1 else record["runs"].get(name, 0)


def ran_in(record, name):
    """The attempt in which `name` last ran (attempt 1 in attempt 1)."""
    return 1 if record["attempt"] == 1 else record["ran_in"][name]
