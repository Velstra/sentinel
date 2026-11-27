"""The Community release workflow can build images on GitHub's Ubuntu 24.04 runners."""
import importlib.util
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release-community.yml"
USERNS = "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
# The only label a job that builds, signs, packages or publishes may run on.
HOSTED = "ubuntu-24.04"
SELECTED_RUNNER = "${{ fromJSON(needs.plan.outputs.regression_runs_on) }}"
RETRY_IF = "if: steps.checkout.outcome == 'failure'"
# wizard-encrypted in release run 45345375933, the longest healthy regression
# job; runners are slower still under night-time load.
SLOWEST_HEALTHY_REGRESSION_MINUTES = 80

# The scripts import each other, as they do when the workflow runs them.
sys.path.insert(0, str(ROOT / "scripts"))
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
        self.assertIn("max-parallel: ${{ fromJSON(needs.plan.outputs.regression_max_parallel) }}",
                      self.jobs["regressions"])
        hosted = release.regression_runner("github")["max_parallel"]
        self.assertGreaterEqual(hosted, 16)
        # GitHub Free runs 20 hosted jobs at once, and build runs alongside.
        self.assertLess(hosted, 20)
        self.assertGreater(release.regression_runner("velstra-rel-a1b2c3d4")["max_parallel"], hosted)

    def test_only_the_regressions_may_leave_github_hosted_runners(self):
        # No key, no signed byte and no release artifact may reach a runner
        # the project operates itself.
        for name, block in self.jobs.items():
            with self.subTest(job=name):
                runs_on = re.findall(r"(?m)^    runs-on: (.*)$", block)
                self.assertEqual(runs_on, [SELECTED_RUNNER if name == "regressions" else HOSTED])
                if name not in ("plan", "regressions"):
                    self.assertNotIn("regression_runs_on", block)
                    self.assertNotIn("inputs.regression_runner", block)

    def test_a_self_hosted_regression_job_holds_no_secret_and_may_write_nothing(self):
        block = self.jobs["regressions"]
        for forbidden in ("secrets.", "environment:", "vars.", "GH_TOKEN", "github.token"):
            self.assertNotIn(forbidden, block)
        self.assertRegex(block, r"(?m)^    permissions:\n      contents: read\n    [^ ]")

    def test_the_plan_validates_the_runner_choice_before_any_regression(self):
        text = WORKFLOW.read_text()
        dispatch = text.split("workflow_dispatch:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertRegex(dispatch, r"(?m)^      regression_runner:\n(?:        .*\n)*        default: github\n")
        self.assertRegex(dispatch, r"(?m)^      regression_runner:\n(?:        .*\n)*        type: string\n")
        plan = self.jobs["plan"]
        self.assertIn("REGRESSION_RUNNER: ${{ inputs.regression_runner || 'github' }}", plan)
        self.assertRegex(plan, r'\n            python3 scripts/community_release.py runner --runner "\$REGRESSION_RUNNER"\n'
                               r'          \} >> "\$GITHUB_OUTPUT"\n')
        for output in ("regression_runner", "regression_runs_on", "regression_max_parallel"):
            self.assertIn(f"{output}: ${{{{ steps.plan.outputs.{output} }}}}", plan)

    def test_the_release_record_learns_which_runners_ran_the_regressions(self):
        for name in ("package", "seal", "publish"):
            with self.subTest(job=name):
                self.assertIn("RELEASE_REGRESSION_RUNNER: ${{ needs.plan.outputs.regression_runner }}",
                              self.jobs[name])

    def test_the_self_hosted_runner_may_have_lifted_the_userns_restriction_already(self):
        step = next(s for s in steps(self.jobs["regressions"]) if USERNS in s)
        self.assertIn("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", step)

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
        self.assertLess(timeout, 360)
        # Room for the slowest healthy job to stall at its very end, sit out
        # the stall limit and then run in full once more.
        self.assertGreaterEqual(timeout, 2 * SLOWEST_HEALTHY_REGRESSION_MINUTES
                                + release.STALL_SECONDS // 60)


    def test_a_failed_job_may_run_again_up_to_attempt_three(self):
        self.assertEqual(release.release_attempts.MAX_ATTEMPT, 3)
        first_only = 'test "$GITHUB_RUN_ATTEMPT" = 1'
        self.assertIn(first_only, self.jobs["plan"])
        at_most = 'test "$GITHUB_RUN_ATTEMPT" -le 3'
        for name, command in (("build", "community_release.py build"), ("regressions", "community_release.py checks")):
            with self.subTest(job=name):
                block = self.jobs[name]
                self.assertNotIn(first_only, block)
                self.assertIn(at_most, block)
                self.assertLess(block.index(at_most), block.index(command))

    def test_a_job_run_again_never_collides_with_its_earlier_upload(self):
        # A job that failed after its upload (the CVE verdict is kept on
        # failure) would fail again on the name it already used; deleting the
        # old artifact first is best effort only. Every job takes its input by
        # artifact ID, so each attempt uploads under its own name instead.
        self.assertNotIn("overwrite:", WORKFLOW.read_text())
        for name, block in self.jobs.items():
            all_steps = steps(block)
            for step in all_steps:
                if "uses: actions/upload-artifact@" not in step:
                    continue
                with self.subTest(job=name, step=step.splitlines()[0]):
                    upload = re.search(r"(?m)^          name: (.*)$", inputs(step)).group(1)
                    if name == "regressions":
                        # The receipt keeps its name for package's check-* download;
                        # it is the last step, so a failed job never uploaded it.
                        self.assertEqual(upload, "check-${{ matrix.check }}")
                        self.assertIs(step, all_steps[-1])
                    else:
                        self.assertTrue(upload.endswith("-attempt-${{ github.run_attempt }}"), upload)

    def test_the_release_never_names_where_the_self_hosted_runners_live(self):
        # Owner decision: self-hosted ephemeral runners and their run label,
        # no provider, host name or address.
        leak = re.compile(r"\bcloud\b|project's own|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.I)
        for path in (WORKFLOW, ROOT / "docs/releases.md", *(ROOT / "scripts" / f"{n}.py" for n in (
                "community_release", "publish_community", "release_attempts", "check_release_environment"))):
            with self.subTest(path=path.name):
                self.assertEqual(leak.findall(path.read_text()), [])

    def test_every_protected_job_checks_the_attempt_before_it_acts(self):
        for name, environment, action in (("sign", "community-signing", "community_release.py sign"),
                                          ("seal", "community-attestation", "community_release.py seal"),
                                          ("publish", "community-publish", "publish_community.py")):
            with self.subTest(job=name):
                block = self.jobs[name]
                check = f"check_release_environment.py {environment} --approved"
                self.assertIn(check, block)
                self.assertLess(block.index(check), block.index(action))

    def test_the_package_job_reads_which_attempt_ran_each_check(self):
        aggregate = next(s for s in steps(self.jobs["package"]) if "community_release.py aggregate" in s)
        self.assertIn("GH_TOKEN: ${{ github.token }}", aggregate)

    def test_every_step_that_judges_the_attempts_can_read_them(self):
        # In attempt 2 or 3 these commands ask GitHub which job ran in which
        # attempt; without a token gh refuses, and the release job fails.
        commands = ("community_release.py aggregate", "community_release.py validate",
                    "community_release.py seal", "community_release.py verify", "--approved")
        for name, block in self.jobs.items():
            job_env = block.split("\n    steps:\n", 1)[0]
            for step in steps(block):
                if any(command in step for command in commands):
                    with self.subTest(job=name, step=step.splitlines()[0]):
                        self.assertTrue("GH_TOKEN: ${{ github.token }}" in step
                                        or "GH_TOKEN: ${{ github.token }}" in job_env)

    def test_the_re_run_policy_may_read_failure_annotations(self):
        text = WORKFLOW.read_text()
        top = text.split("\njobs:\n", 1)[0]
        self.assertRegex(top, r"(?m)^permissions:\n(?:  .*\n)*  checks: read$")
        self.assertRegex(self.jobs["publish"], r"    permissions:\n(?:      .*\n)*      checks: read\n")

if __name__ == "__main__":
    unittest.main()
