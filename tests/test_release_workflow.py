"""The Community release workflow can build images on GitHub's Ubuntu 24.04 runners."""
import re
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/release-community.yml"
USERNS = "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"


def jobs(text):
    """Map each top-level job name to its block of lines."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"(?m)^  ([a-z][a-z-]*):\n", body)
    return dict(zip(parts[1::2], parts[2::2]))


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.jobs = jobs(WORKFLOW.read_text())

    def test_every_job_that_builds_lifts_the_userns_restriction_before_nix(self):
        # Image derivations unshare a user namespace; Ubuntu 24.04 runners
        # refuse that by default ("write failed /proc/self/uid_map").
        for name in ("regressions", "build", "sign", "package"):
            block = self.jobs[name]
            self.assertIn(USERNS, block, name)
            self.assertLess(block.index(USERNS), block.index("cachix/install-nix-action"), name)

    def test_checks_run_with_enough_parallelism_to_finish_in_hours(self):
        match = re.search(r"max-parallel: (\d+)", self.jobs["regressions"])
        self.assertIsNotNone(match)
        self.assertGreaterEqual(int(match.group(1)), 16)


if __name__ == "__main__":
    unittest.main()
