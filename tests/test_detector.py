"""Unit tests for the drift detector. Run: python -m unittest discover tests"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from detector import detect  # noqa: E402
from diff_engine import diff_inventories, _walk_diff, FieldChange  # noqa: E402
from pr_generator import render_pr_body  # noqa: E402
from rules import ALL_RULES, IAM_RULES, NETWORK_RULES  # noqa: E402
from tf_loader import load_observed_state, load_terraform_show  # noqa: E402


class TestDiffEngine(unittest.TestCase):
    def test_added_resource(self):
        items = diff_inventories({}, {"aws_x": {"foo": {"a": 1}}})
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].kind, "ADDED")

    def test_removed_resource(self):
        items = diff_inventories({"aws_x": {"foo": {"a": 1}}}, {})
        self.assertEqual(items[0].kind, "REMOVED")

    def test_modified_resource_field_diff(self):
        items = diff_inventories(
            {"aws_x": {"foo": {"a": 1, "b": 2}}},
            {"aws_x": {"foo": {"a": 1, "b": 9}}},
        )
        self.assertEqual(items[0].kind, "MODIFIED")
        self.assertEqual([c.field for c in items[0].changes], ["b"])

    def test_ignore_fields(self):
        items = diff_inventories(
            {"aws_x": {"foo": {"a": 1, "tags_all": {"x": "y"}}}},
            {"aws_x": {"foo": {"a": 1, "tags_all": {"x": "z"}}}},
            ignore_fields={"tags_all.x"},
        )
        self.assertEqual(items, [])

    def test_walk_diff_lists(self):
        diffs = _walk_diff("xs", [1, 2, 3], [1, 2, 4])
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].field, "xs")


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tf = os.path.join(ROOT, "samples", "terraform.tfstate.json")
        self.obs = os.path.join(ROOT, "samples", "aws_observed_state.json")

    def test_e2e_runs(self):
        items, findings = detect(self.tf, self.obs)
        self.assertGreater(len(items), 5)
        self.assertGreater(len(findings), 5)

    def test_critical_admin_attached(self):
        _, findings = detect(self.tf, self.obs)
        crit = [f for f in findings if f.get("severity") == "CRITICAL"]
        # We expect at least: AdministratorAccess attachment + wildcard policy
        # + S3 BlockPublicAccess relaxed + SSH world ingress.
        self.assertGreaterEqual(len(crit), 3)
        titles = " | ".join(f["title"] for f in crit)
        self.assertIn("AdministratorAccess", titles)

    def test_iam_modified_to_wildcard(self):
        _, findings = detect(self.tf, self.obs)
        wildcards = [f for f in findings if "wildcard" in f.get("title", "").lower()]
        self.assertEqual(len(wildcards), 1)

    def test_iam_password_policy_weakened(self):
        _, findings = detect(self.tf, self.obs)
        weakened = [f for f in findings if "weakened" in f.get("title", "").lower()]
        self.assertGreaterEqual(len(weakened), 1)


class TestPRGenerator(unittest.TestCase):
    def test_empty_findings(self):
        body = render_pr_body([], 0)
        self.assertIn("No actionable drift", body)

    def test_grouped_by_category(self):
        body = render_pr_body([
            {"category": "iam", "severity": "CRITICAL", "title": "x", "address": "a", "kind": "ADDED",
             "detail": "", "remediation": "fix"},
            {"category": "network", "severity": "HIGH", "title": "y", "address": "b", "kind": "MODIFIED",
             "detail": "", "remediation": "fix"},
        ], drift_count=2)
        self.assertIn("### IAM", body)
        self.assertIn("### NETWORK", body)


class TestLoaders(unittest.TestCase):
    def test_load_terraform_show_unwraps_policy_json(self):
        inv = load_terraform_show(os.path.join(ROOT, "samples", "terraform.tfstate.json"))
        pol = inv["aws_iam_policy"]["aws_iam_policy.app_runtime"]["policy"]
        self.assertIsInstance(pol, dict)
        self.assertEqual(pol["Version"], "2012-10-17")

    def test_observed_state_validation(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump([1, 2, 3], fh)
            path = fh.name
        with self.assertRaises(ValueError):
            load_observed_state(path)


class TestRuleCounts(unittest.TestCase):
    def test_iam_rules_present(self):
        self.assertGreaterEqual(len(IAM_RULES), 5)

    def test_network_rules_present(self):
        self.assertGreaterEqual(len(NETWORK_RULES), 5)

    def test_all_rules_aggregate(self):
        self.assertEqual(len(ALL_RULES), len(IAM_RULES) + len(NETWORK_RULES))


if __name__ == "__main__":
    unittest.main()
