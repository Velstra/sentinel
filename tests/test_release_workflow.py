"""The Community release workflow can build images on GitHub's Ubuntu 24.04 runners."""
import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release-community.yml"
USERNS = "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
RETRY_IF = "if: steps.checkout.outcome == 'failure'"

_spec = importlib.util.spec_from_file_location("community_release", ROOT / "scripts/community_release.py")
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)


def jobs(text):
    """Map each top-level job name to its block of lines."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"(?m)^  ([a-z][a-z-]*):\n", body)
    return dict(zip(parts[1::2], parts[2::2]))


def steps(block):
    """The job's steps, each as its own text, without comment lines."""
    text = block.split("\n    steps:\n", 1)[1]
    text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return [step.rstrip("\n") + "\n" for step in re.split(r"(?m)^      - ", text)[1:]]


def inputs(step):
    """A step's `with:` block, or "" when it has none."""
    return step.split("with:\n", 1)[1] if "with:\n" in step else ""


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

    def test_every_job_retries_a_failed_checkout_once_after_a_pause(self):
        # One unreachable github.com used to end the whole release run: the
        # action's own three attempts took about 7 min and then failed.
        for name, block in self.jobs.items():
            with self.subTest(job=name):
                all_steps = steps(block)
                checkouts = [s for s in all_steps if "uses: actions/checkout@" in s]
                self.assertEqual(len(checkouts), 2)
                first, retry = checkouts
                self.assertTrue(first.startswith("id: checkout\n"), first)
                self.assertIn("continue-on-error: true", first)
                self.assertIn(RETRY_IF, retry)
                sha = re.compile(r"uses: (actions/checkout@[0-9a-f]{40})")
                self.assertEqual(sha.search(first).group(1), sha.search(retry).group(1))
                self.assertEqual(inputs(first), inputs(retry))
                at = all_steps.index(first)
                pause, again = all_steps[at + 1], all_steps[at + 2]
                self.assertIn(RETRY_IF, pause)
                self.assertRegex(pause, r"run: sleep \d+")
                self.assertIs(again, retry)

    def test_a_hung_regression_costs_hours_not_six(self):
        timeout = int(re.search(r"timeout-minutes: (\d+)", self.jobs["regressions"]).group(1))
        self.assertLessEqual(timeout, 150)
        # Room for one stalled attempt plus a whole second attempt.
        self.assertGreater(timeout * 60, 2 * release.STALL_SECONDS)


if __name__ == "__main__":
    unittest.main()
