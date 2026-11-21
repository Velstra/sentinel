"""Repository policy files agree with each other and with the CLA workflow.

The CLA workflow runs with pull_request_target, so it holds a write token
while handling untrusted pull requests. These tests pin the properties that
keep that safe, and the facts the policy documents state about each other.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SIGN_PHRASE = "I have read the CLA Document and I hereby sign the CLA"


def read(name):
    return (ROOT / name).read_text(encoding="utf-8")


class ClaWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = read(".github/workflows/cla.yml")

    def test_action_is_pinned_to_a_full_commit(self):
        uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)", self.workflow, re.MULTILINE)
        self.assertEqual(len(uses), 1, uses)
        self.assertRegex(uses[0], r"^contributor-assistant/github-action@[0-9a-f]{40}$")

    def test_untrusted_pull_request_code_is_never_checked_out(self):
        self.assertIn("pull_request_target", self.workflow)
        self.assertNotIn("actions/checkout", self.workflow)
        self.assertNotRegex(self.workflow, r"\brun:")

    def test_permissions_are_explicit_and_scoped(self):
        self.assertRegex(self.workflow, r"(?m)^permissions:\s*\{\}\s*$")
        job_permissions = re.search(r"(?m)^    permissions:\n((?:      [^\n]+\n)+)", self.workflow)
        self.assertIsNotNone(job_permissions)
        granted = dict(re.findall(r"(\S+):\s*(\S+)", job_permissions.group(1)))
        self.assertEqual(granted, {"actions": "write", "contents": "write",
                                   "pull-requests": "write", "statuses": "write"})

    def test_signatures_live_on_their_own_branch(self):
        self.assertRegex(self.workflow, r"branch:\s*['\"]?cla-signatures['\"]?")
        self.assertIn("path-to-document: 'https://github.com/Velstra/sentinel/blob/main/CLA.md'", self.workflow)

    def test_bots_and_the_owner_are_allowlisted(self):
        allowlist = re.search(r"allowlist:\s*'([^']*)'", self.workflow).group(1).split(",")
        for bot in ("dependabot[bot]", "github-actions[bot]"):
            self.assertIn(bot, allowlist)
        self.assertGreaterEqual(len(allowlist), 3)

    def test_comment_trigger_only_runs_for_signing_or_recheck(self):
        self.assertIn(f"github.event.comment.body == '{SIGN_PHRASE}'", self.workflow)
        self.assertIn("github.event.comment.body == 'recheck'", self.workflow)
        self.assertIn("github.event.issue.pull_request", self.workflow)
        self.assertIn(f"custom-pr-sign-comment: '{SIGN_PHRASE}'", self.workflow)


class PolicyDocumentTests(unittest.TestCase):
    def test_cla_grants_relicensing_and_keeps_the_agpl_promise(self):
        cla = read("CLA.md")
        for section in ("Individual Contributor License Agreement", "Entity Contributor License Agreement"):
            self.assertIn(section, cla)
        self.assertIn("relicense", cla)
        self.assertIn("AGPL-3.0-or-later", cla)
        self.assertIn(SIGN_PHRASE, cla)
        self.assertIn("TODO(owner): legal review", cla)

    def test_contributing_requires_the_cla_instead_of_denying_it(self):
        contributing = read("CONTRIBUTING.md")
        self.assertIn("CLA.md", contributing)
        self.assertIn(SIGN_PHRASE, contributing)
        self.assertNotIn("no administered Contributor License Agreement", contributing)
        template = read(".github/pull_request_template.md")
        self.assertNotIn("no separate administered CLA", template)
        self.assertIn("CLA.md", template)

    def test_security_policy_lists_supported_versions(self):
        security = read("SECURITY.md")
        rows = dict(re.findall(r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|$", security, re.MULTILINE))
        self.assertTrue(rows.get("1.0.x", "").startswith("Yes"), rows)
        self.assertTrue(rows.get("< 1.0", "").startswith("No"), rows)
        for required in ("security/advisories/new", "https://www.velstra.cloud/security",
                         "24 hours", "no conformity assessment"):
            self.assertIn(required, security)

    def test_support_points_to_community_and_paid_support(self):
        support = read("SUPPORT.md")
        for required in ("https://www.velstra.cloud/pricing", "https://www.velstra.cloud/support",
                         "SECURITY.md", "github.com/Velstra/sentinel/issues"):
            self.assertIn(required, support)


if __name__ == "__main__":
    unittest.main()
