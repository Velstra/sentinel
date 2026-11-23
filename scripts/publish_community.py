#!/usr/bin/env python3
"""Create a draft, verify uploaded bytes, then expose the release atomically."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, HTTPRedirectHandler, build_opener

from check_release_environment import approvals_statement
from community_release import digest, source, verify_bundle, version


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("GitHub API redirects are forbidden")


def api(path, payload=None, method="GET", missing=False):
    request = Request("https://api.github.com/" + path,
                      data=json.dumps(payload).encode() if payload is not None else None,
                      headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                               "Accept": "application/vnd.github+json",
                               "Content-Type": "application/json",
                               "X-GitHub-Api-Version": "2022-11-28"}, method=method)
    try:
        with build_opener(NoRedirect).open(request, timeout=60) as response:
            return json.load(response)
    except HTTPError as error:
        if missing and error.code == 404:
            return None
        raise


def publish(directory):
    if (os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("RELEASE_PUBLISH_REQUESTED") != "true"
            or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"):
        raise ValueError("publication requires an explicitly requested first-attempt main dispatch")
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
    statement = approvals_statement()
    if statement:
        body += "\n\n" + statement
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
