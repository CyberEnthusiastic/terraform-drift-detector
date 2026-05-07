"""
IAM-specific drift rules.

Each rule receives a DriftItem and returns 0..N findings with severity.
IAM drift is the highest-impact category because a single console edit
can grant Administrator privileges or expose a role to the world.
"""
from __future__ import annotations

from typing import Callable

CRIT, HIGH, MED, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"


def _wildcard(value) -> bool:
    if value in ("*", ["*"]):
        return True
    if isinstance(value, list) and "*" in value:
        return True
    return False


def _f(item, sev: str, title: str, detail: str, fix: str) -> dict:
    return {
        "category": "iam",
        "severity": sev,
        "title": title,
        "resource_type": item.resource_type,
        "address": item.address,
        "kind": item.kind,
        "detail": detail,
        "remediation": fix,
    }


def iam_added_admin_policy(item) -> list[dict]:
    """A new AdministratorAccess attachment outside Terraform."""
    if item.kind != "ADDED":
        return []
    if item.resource_type not in ("aws_iam_role_policy_attachment",
                                  "aws_iam_user_policy_attachment",
                                  "aws_iam_group_policy_attachment"):
        return []
    o = item.observed or {}
    if "AdministratorAccess" in (o.get("policy_arn") or ""):
        return [_f(item, CRIT,
                   "Out-of-band AdministratorAccess attachment",
                   f"{item.resource_type} attached AdministratorAccess to "
                   f"{o.get('role') or o.get('user') or o.get('group')}.",
                   "Detach via console; codify the actual required permission set.")]
    return []


def iam_modified_policy_to_wildcard(item) -> list[dict]:
    """Live IAM policy edited to grant Action:* + Resource:*."""
    if item.kind != "MODIFIED" or item.resource_type not in (
            "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
        return []
    obs_doc = (item.observed or {}).get("policy") or {}
    if isinstance(obs_doc, str):
        return []  # leave JSON-blob diff for the structural fields handler below
    out = []
    for stmt in (obs_doc.get("Statement") or []):
        if (stmt.get("Effect") == "Allow"
                and _wildcard(stmt.get("Action"))
                and _wildcard(stmt.get("Resource"))):
            out.append(_f(item, CRIT,
                          "Policy edited to wildcard Action+Resource",
                          f"{item.address}: live policy now allows *:*.",
                          "Revert via Terraform apply; or refactor to least-privilege."))
            break
    return out


def iam_removed_role(item) -> list[dict]:
    """Terraform-managed IAM role deleted out-of-band."""
    if item.kind == "REMOVED" and item.resource_type == "aws_iam_role":
        return [_f(item, HIGH,
                   "Terraform-managed IAM role deleted",
                   f"Role {item.address} no longer exists in AWS.",
                   "Restore via `terraform apply` or remove from IaC if intentional.")]
    return []


def iam_modified_assume_role_policy(item) -> list[dict]:
    """Trust policy changed — confused-deputy risk."""
    if item.kind != "MODIFIED" or item.resource_type != "aws_iam_role":
        return []
    diffs = [c for c in item.changes if "assume_role_policy" in c.field]
    if diffs:
        return [_f(item, HIGH,
                   "IAM role trust policy modified out-of-band",
                   f"assume_role_policy on {item.address} differs from Terraform.",
                   "Inspect change for new principals (CrossAccount, *); reapply IaC.")]
    return []


def iam_role_inline_policy_added(item) -> list[dict]:
    """A console-added inline policy on a TF-managed role."""
    if item.kind != "ADDED" or item.resource_type != "aws_iam_role_policy":
        return []
    return [_f(item, MED,
               "Inline IAM policy added out-of-band",
               f"{item.address} is not declared in Terraform.",
               "Promote to managed policy + Terraform; or remove via console.")]


def iam_user_access_key_added(item) -> list[dict]:
    """Access key created outside Terraform — usually leaks."""
    if item.kind != "ADDED" or item.resource_type != "aws_iam_access_key":
        return []
    return [_f(item, HIGH,
               "Access key created out-of-band",
               f"{item.address} created without IaC trail.",
               "Verify owner; rotate; codify in Terraform if legitimate.")]


def iam_password_policy_weakened(item) -> list[dict]:
    if item.kind != "MODIFIED" or item.resource_type != "aws_iam_account_password_policy":
        return []
    out = []
    for c in item.changes:
        if c.field == "minimum_password_length" and (c.observed or 0) < (c.baseline or 0):
            out.append(_f(item, MED,
                          "Password policy minimum length weakened",
                          f"min length: {c.baseline} -> {c.observed}",
                          "Restore baseline via Terraform."))
        if c.field == "password_reuse_prevention" and (c.observed or 0) < (c.baseline or 0):
            out.append(_f(item, LOW,
                          "Password reuse prevention reduced",
                          f"reuse_prev: {c.baseline} -> {c.observed}",
                          "Restore baseline via Terraform."))
    return out


IAM_RULES: list[Callable] = [
    iam_added_admin_policy,
    iam_modified_policy_to_wildcard,
    iam_removed_role,
    iam_modified_assume_role_policy,
    iam_role_inline_policy_added,
    iam_user_access_key_added,
    iam_password_policy_weakened,
]
