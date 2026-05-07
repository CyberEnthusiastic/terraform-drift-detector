"""
Networking-specific drift rules.

Focus: Security Groups, Network ACLs, VPCs, route tables, public-facing changes
that turn an internal resource into an internet-facing one — the second
biggest drift impact category after IAM.
"""
from __future__ import annotations

from typing import Callable

CRIT, HIGH, MED, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"


def _f(item, sev: str, title: str, detail: str, fix: str) -> dict:
    return {
        "category": "network",
        "severity": sev,
        "title": title,
        "resource_type": item.resource_type,
        "address": item.address,
        "kind": item.kind,
        "detail": detail,
        "remediation": fix,
    }


def _has_open_world(rule: dict, port: int | None = None) -> bool:
    cidrs = rule.get("cidr_blocks") or []
    if "0.0.0.0/0" not in cidrs and "::/0" not in cidrs:
        return False
    if port is None:
        return True
    fp = rule.get("from_port")
    tp = rule.get("to_port")
    if fp is None:
        return False
    return fp <= port <= (tp if tp is not None else fp)


def sg_world_ingress_added(item) -> list[dict]:
    """A new security group rule that opens a port to 0.0.0.0/0."""
    if item.resource_type != "aws_security_group_rule":
        return []
    if item.kind not in ("ADDED", "MODIFIED"):
        return []
    o = item.observed or {}
    if o.get("type") != "ingress":
        return []
    cidrs = o.get("cidr_blocks") or []
    if "0.0.0.0/0" in cidrs or "::/0" in cidrs:
        port = o.get("from_port")
        sev = CRIT if port in (22, 3389, 3306, 5432, 6379, 27017) else HIGH
        return [_f(item, sev,
                   f"SG ingress to 0.0.0.0/0 added on port {port}",
                   f"{item.address}: {o.get('protocol')} {port} now world-open.",
                   "Restrict to specific source CIDRs (bastion, VPN, partner range).")]
    return []


def sg_inline_ingress_drift(item) -> list[dict]:
    """The aws_security_group has new inline ingress that wasn't in TF."""
    if item.resource_type != "aws_security_group" or item.kind != "MODIFIED":
        return []
    out = []
    for c in item.changes:
        if "ingress" in c.field:
            obs = c.observed or []
            if isinstance(obs, list):
                for r in obs:
                    if isinstance(r, dict) and _has_open_world(r):
                        port = r.get("from_port")
                        sev = CRIT if port in (22, 3389, 3306, 5432) else HIGH
                        out.append(_f(item, sev,
                                      f"SG inline rule opened port {port} to world",
                                      f"{item.address} ingress now allows 0.0.0.0/0 on {port}.",
                                      "Move rules to aws_security_group_rule; restrict CIDR."))
                        break
    return out


def nacl_open_added(item) -> list[dict]:
    if item.resource_type != "aws_network_acl_rule" or item.kind != "ADDED":
        return []
    o = item.observed or {}
    if o.get("rule_action") == "allow" and o.get("cidr_block") in ("0.0.0.0/0", "::/0") \
            and o.get("egress") is False:
        return [_f(item, HIGH,
                   "NACL ingress rule allows 0.0.0.0/0",
                   f"{item.address}: NACL rule {o.get('rule_number')} ALLOW from world.",
                   "Tighten NACL or fall back to SG-only model.")]
    return []


def vpc_endpoint_removed(item) -> list[dict]:
    """A private VPC endpoint deleted — traffic now hairpins through internet."""
    if item.resource_type == "aws_vpc_endpoint" and item.kind == "REMOVED":
        return [_f(item, MED,
                   "VPC endpoint deleted",
                   f"{item.address} removed; service traffic may now traverse internet.",
                   "Recreate via Terraform; verify SG / route table associations.")]
    return []


def route_to_igw_on_private(item) -> list[dict]:
    """Route 0.0.0.0/0 -> igw added to a private subnet's route table."""
    if item.resource_type != "aws_route" or item.kind != "ADDED":
        return []
    o = item.observed or {}
    if o.get("destination_cidr_block") == "0.0.0.0/0" \
            and (o.get("gateway_id") or "").startswith("igw-"):
        return [_f(item, HIGH,
                   "Default route added pointing to IGW",
                   f"{item.address}: 0.0.0.0/0 -> {o.get('gateway_id')} on private route table.",
                   "Replace with NAT or remove; private subnets must not route to IGW.")]
    return []


def s3_public_block_relaxed(item) -> list[dict]:
    if item.resource_type != "aws_s3_bucket_public_access_block" or item.kind != "MODIFIED":
        return []
    out = []
    for c in item.changes:
        if c.field in ("block_public_acls", "block_public_policy",
                       "ignore_public_acls", "restrict_public_buckets") \
                and c.baseline is True and c.observed is False:
            out.append(_f(item, CRIT,
                          f"S3 BlockPublicAccess relaxed: {c.field}",
                          f"{item.address}: {c.field} {c.baseline} -> {c.observed}",
                          "Re-enable all four BlockPublicAccess settings."))
    return out


def alb_listener_http_added(item) -> list[dict]:
    """An HTTP listener (port 80, no redirect) added on a TF-managed ALB."""
    if item.resource_type != "aws_lb_listener" or item.kind != "ADDED":
        return []
    o = item.observed or {}
    if o.get("port") == 80 and o.get("protocol") == "HTTP":
        actions = o.get("default_action") or []
        if not any((a or {}).get("type") == "redirect" for a in actions):
            return [_f(item, MED,
                       "ALB HTTP listener (no redirect) added",
                       f"{item.address}: port 80 listener without HTTPS redirect.",
                       "Configure default_action redirect → 443.")]
    return []


def cloudfront_origin_changed_to_http(item) -> list[dict]:
    if item.resource_type != "aws_cloudfront_distribution" or item.kind != "MODIFIED":
        return []
    out = []
    for c in item.changes:
        if "origin_protocol_policy" in c.field and c.observed in ("http-only", "match-viewer") \
                and c.baseline == "https-only":
            out.append(_f(item, HIGH,
                          "CloudFront origin protocol downgraded",
                          f"{item.address}: origin policy {c.baseline} -> {c.observed}.",
                          "Restore https-only via Terraform."))
    return out


NETWORK_RULES: list[Callable] = [
    sg_world_ingress_added,
    sg_inline_ingress_drift,
    nacl_open_added,
    vpc_endpoint_removed,
    route_to_igw_on_private,
    s3_public_block_relaxed,
    alb_listener_http_added,
    cloudfront_origin_changed_to_http,
]
