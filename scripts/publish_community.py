#!/usr/bin/env python3
"""Create a draft, verify uploaded bytes, then expose the release atomically."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener

# The release scripts import each other by name. Put this file's own directory
# on the path, so that works however the file is loaded: as a script, through
# `python3 -c`, or by importlib from a test.
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_release_environment import approvals_statement  # noqa: E402
from community_release import (BUILD_STAGES, HOSTED_LABEL, STALL_SECONDS, build_stalls, digest,  # noqa: E402
                               regression_runner, rerun_attempts, source, verify_bundle, version)
import release_attempts  # noqa: E402


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("GitHub API redirects are forbidden")


def api(path, payload=None, method="GET", missing=False, sleep=time.sleep):
    """One GitHub API call. A read (GET) is retried after a server error
    (HTTP 5xx) or a network failure, like release_attempts' reads; a write
    is never repeated."""
    request = Request("https://api.github.com/" + path,
                      data=json.dumps(payload).encode() if payload is not None else None,
                      headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                               "Accept": "application/vnd.github+json",
                               "Content-Type": "application/json",
                               "X-GitHub-Api-Version": "2022-11-28"}, method=method)
    delays = release_attempts.API_RETRY_DELAYS if method == "GET" else ()
    for attempt, delay in enumerate((*delays, None), start=1):
        try:
            with build_opener(NoRedirect).open(request, timeout=60) as response:
                return json.load(response)
        except HTTPError as error:
            if missing and error.code == 404:
                return None
            if error.code < 500 or not delays:
                raise
            last = error
        except (URLError, TimeoutError) as error:
            if not delays:
                raise
            last = error
        if delay is None:
            raise ValueError(f"GitHub API read {path} failed {attempt} times; last: {last}") from last
        sleep(delay)


def stall_statement(directory):
    """Name the regression checks that ran a second time after a stalled build,
    from the source-check catalog of the verified bundle."""
    path = directory / "source-checks.json"
    if not path.exists():
        return ""
    retried = sorted(entry["check"] for entry in json.loads(path.read_text())["checks"]
                     if entry.get("stall_retries") == 1)
    if not retried:
        return ""
    return ("Regression checks retried once after a stalled build (no output for "
            f"{STALL_SECONDS // 60} min; a failing check is never retried): " + ", ".join(retried) + ".")


# How the release body names each long release build.
BUILD_NAMES = {"image-build": "image build", "installer-iso": "installer ISO", "boot-gate": "boot gate"}


def build_stall_statement(directory):
    """Name the release builds that ran a second time after a stall, from the
    verified bundle's image evidence."""
    path = directory / "image-evidence.json"
    if not path.exists():
        return ""
    stalls = build_stalls(json.loads(path.read_text()))
    retried = [BUILD_NAMES[stage] for stage in BUILD_STAGES if stalls[stage] == 1]
    if not retried:
        return ""
    return ("Release builds retried once after a stalled build (no output for "
            f"{STALL_SECONDS // 60} min; a failing build is never retried): " + ", ".join(retried) + ".")


def runner_statement(directory):
    """Say which runners ran the regression checks, from the verified bundle,
    whose record the plan's own outputs confirmed."""
    path = directory / "source-checks.json"
    if not path.exists():
        raise ValueError("the bundle has no source check record")
    record = json.loads(path.read_text()).get("regression_runner")
    if record == regression_runner("github")["record"]:
        return f"Regression checks and every release job ran on GitHub-hosted runners ({HOSTED_LABEL})."
    if (not isinstance(record, dict) or record.get("class") != "self-hosted-ephemeral"
            or regression_runner(record.get("label"))["record"] != record):
        raise ValueError("the bundle does not say which runners ran the regression checks")
    return f"Regression checks ran on self-hosted ephemeral runners (runner label {record['label']})."


def attempts_text(attempts):
    return f"attempt {attempts[0]}" if len(attempts) == 1 else \
        "attempts " + ", ".join(str(n) for n in attempts[:-1]) + f" and {attempts[-1]}"


def rerun_count(entry):
    """How often later attempts ran a check again, and how many entries they
    only listed. The policy has verified that its last attempt passed."""
    attempts, runs, phantoms = entry["attempts"], entry["runs"], entry.get("phantoms", 0)
    text = f"ran again {'once' if runs == 1 else f'{runs} times'} in {attempts_text(attempts)} and passed"
    if len(attempts) > 1:
        text += f" in attempt {attempts[-1]}"
    if phantoms:
        text += f"; {phantoms} phantom entr{'y was' if phantoms == 1 else 'ies were'} listed but never started"
    return text


def first_failure_text(entry):
    return (f"first failure, attempt {entry['failed_in']}: {entry['first_failure']}; "
            f"log: {entry['first_job']}")


def rerun_statement(directory):
    """Name each job run again after a failure, with its first error and log:
    the regression checks as the verified bundle recorded them, which must
    match what GitHub reports for this run, and the release jobs as GitHub
    reports them now (publication may itself be a re-run)."""
    path = directory / "source-checks.json"
    recorded = json.loads(path.read_text()).get("reruns", {}) if path.exists() else {}
    record = release_attempts.current()
    if rerun_attempts(recorded) != rerun_attempts(record["checks"]):
        raise ValueError("the bundle's re-run record differs from this run's jobs")
    lines = []
    if recorded:
        lines.append("Regression checks re-run after a failure: " + ", ".join(
            f"{check} ({first_failure_text(entry)}; {rerun_count(entry)})"
            for check, entry in sorted(recorded.items())) + ".")
    if record["jobs"]:
        lines.append("Release jobs re-run after a failure: " + ", ".join(
            f"{name} ({first_failure_text(entry)}; ran again "
            + (f"{entry['runs']} times " if entry["runs"] > 1 else "") + f"in {attempts_text(entry['attempts'])})"
            for name, entry in sorted(record["jobs"].items())) + ".")
    return "\n\n".join(lines)


def publish(directory):
    if (os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("RELEASE_PUBLISH_REQUESTED") != "true"
            or os.environ.get("GITHUB_RUN_ATTEMPT") not in
            {str(n) for n in range(1, release_attempts.MAX_ATTEMPT + 1)}):
        raise ValueError("publication requires an explicitly requested main dispatch, "
                         f"in its first attempt or one of its re-runs (attempts 1 to {release_attempts.MAX_ATTEMPT})")
    verify_bundle(directory)
    release = version(os.environ["RELEASE_VERSION"])
    sha = source()
    repository = os.environ["GITHUB_REPOSITORY"]
    if repository != "Velstra/sentinel":
        raise ValueError("publication is restricted to Velstra/sentinel")
    root = f"repos/{repository}"
    comparison = api(root + f"/compare/{sha}...main")
    if comparison.get("status") not in ("identical", "ahead"):
        raise ValueError("qualified source is no longer on main")
    if api(root + "/releases/tags/" + quote(release, safe=""), missing=True) is not None:
        raise ValueError("release already exists; never overwrite or clobber its assets")
    tag = api(root + "/git/ref/tags/" + quote(release, safe=""), missing=True)
    if tag is not None:
        target = tag["object"]
        for _ in range(8):
            if target["type"] == "commit": break
            if target["type"] != "tag": raise ValueError("invalid tag target")
            target = api(root + "/git/tags/" + target["sha"])["object"]
        if target.get("type") != "commit" or target.get("sha") != sha:
            raise ValueError("existing tag does not identify the qualified source")
    body = ("ISO installer, QCOW2 appliance and compressed RAW disk. Verify SHA256SUMS.gpg "
            "using the independently published release fingerprint before installing.\n\n"
            "The live ISO currently requires Secure Boot disabled; the installed disk uses "
            "production-signed UKIs. See INSTALL.txt and image-evidence.json. "
            "source-sbom.cdx.json inventories source dependencies, not the complete OS. "
            "Source regression tests and exact-disk boot tests are separately identified; "
            "no physical-hardware certification is claimed.")
    body += "\n\n" + runner_statement(directory)
    statement = approvals_statement()
    if statement:
        body += "\n\n" + statement
    for line in (stall_statement(directory), build_stall_statement(directory), rerun_statement(directory)):
        if line:
            body += "\n\n" + line
    created = api(root + "/releases", {
        "tag_name": release, "target_commitish": sha, "name": f"Sentinel {release}",
        "draft": True, "prerelease": "-rc." in release, "body": body}, method="POST")
    if created.get("draft") is not True or created.get("tag_name") != release:
        raise ValueError("server did not create the expected draft")
    paths = sorted(directory.iterdir())
    subprocess.run(["gh", "release", "upload", release, "--repo", repository,
                    *[str(p) for p in paths]], check=True, timeout=3600)
    # A successful upload API call alone is not a byte-for-byte publication check.
    with tempfile.TemporaryDirectory(prefix="sentinel-release-readback-", dir=os.environ.get("RUNNER_TEMP")) as temp:
        subprocess.run(["gh", "release", "download", release, "--repo", repository,
                        "--dir", temp], check=True, timeout=3600)
        downloaded = sorted(Path(temp).iterdir())
        if {p.name: digest(p) for p in downloaded} != {p.name: digest(p) for p in paths}:
            raise ValueError("uploaded artifact inventory or bytes differ; draft retained")
    verify_bundle(directory)
    published = api(root + f"/releases/{created['id']}", {"draft": False}, method="PATCH")
    if published.get("draft") is not False:
        raise ValueError("release publication was not confirmed")
    print(published["html_url"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    publish(parser.parse_args().directory)
