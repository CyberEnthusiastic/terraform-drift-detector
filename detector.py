#!/usr/bin/env python3
"""
Terraform drift detector — diff Terraform state against deployed AWS state,
flag IAM and network drift with severity, auto-generate a remediation PR.

  $ python detector.py --tf samples/terraform.tfstate.json \
                        --observed samples/aws_observed_state.json \
                        --pr-out drift_report.md

  $ python detector.py --tf tf.json --observed aws.json \
                        --create-pr --pr-branch drift-$(date +%s)

Zero dependencies (Python 3.8+ stdlib).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from typing import Any

# Force UTF-8 stdout where the host shell defaulted to cp1252 (Windows).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except (AttributeError, ValueError):  # pragma: no cover
    pass

from diff_engine import DriftItem, diff_inventories
from pr_generator import open_pr_via_gh, render_pr_body, write_pr_body
from rules import ALL_RULES
from tf_loader import load_observed_state, load_terraform_show


_RESET = "\033[0m"
_COL = {
    "CRITICAL": "\033[1;91m", "HIGH": "\033[1;33m",
    "MEDIUM":   "\033[1;36m", "LOW":  "\033[0;90m",
    "DIM":      "\033[2m",    "OK":   "\033[1;92m",
    "TITLE":    "\033[1;94m",
}


def _c(key: str, s: str) -> str:
    if not sys.stdout.isatty() and not os.environ.get("FORCE_COLOR"):
        return s
    return f"{_COL.get(key, '')}{s}{_RESET}"


# ─── Drift + rules ───────────────────────────────────────────────────────────
def detect(tf_path: str, observed_path: str,
           ignore_fields: list[str] | None = None) -> tuple[list[DriftItem], list[dict]]:
    baseline = load_terraform_show(tf_path)
    observed = load_observed_state(observed_path)

    # Default-ignore noise fields that change every plan.
    ignore = set(ignore_fields or []) | {
        "tags_all", "arn", "id", "etag", "last_modified",
        "version_id", "creation_date", "create_date",
    }
    items = diff_inventories(baseline, observed, ignore_fields=ignore)

    findings: list[dict] = []
    for item in items:
        for rule in ALL_RULES:
            try:
                findings.extend(rule(item) or [])
            except Exception as exc:  # pragma: no cover — defensive
                findings.append({
                    "category": "internal",
                    "severity": "LOW",
                    "title": "rule errored",
                    "resource_type": item.resource_type,
                    "address": item.address,
                    "kind": item.kind,
                    "detail": f"{type(exc).__name__}: {exc}",
                    "remediation": "Open an issue with the offending state files.",
                })
    return items, findings


# ─── Output ──────────────────────────────────────────────────────────────────
def print_drift(items: list[DriftItem], findings: list[dict]) -> None:
    by_kind = Counter(it.kind for it in items)
    by_sev = Counter(f.get("severity", "?") for f in findings)
    print(_c("TITLE", "=" * 70))
    print(_c("TITLE", "  Terraform Drift Detector"))
    print(_c("TITLE", "=" * 70))
    print(f"[*] Drift items   : {len(items)}     ({dict(by_kind)})")
    print(f"[*] Rule findings : {len(findings)}  ({dict(by_sev)})")
    print()

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for f in sorted(findings, key=lambda x: order.index(x.get("severity", "LOW"))):
        sev = f.get("severity", "?")
        print(f"{_c(sev, f'[{sev}]')} {f.get('title', '')} "
              f"{_c('DIM', '(' + f.get('category', '') + ')')}")
        print(f"   {_c('DIM', f.get('address', ''))}  kind={f.get('kind', '')}")
        print(f"   {_c('DIM', '> ' + f.get('detail', ''))}")
        print(f"   {_c('OK', '-> ' + f.get('remediation', ''))}")
        print()

    if not findings and items:
        print(_c("DIM", "(structural drift detected, but no rule fired — review manually)"))
    if not items:
        print(_c("OK", "[+] No drift between Terraform baseline and observed state."))


# ─── CLI ─────────────────────────────────────────────────────────────────────
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Diff Terraform state against deployed AWS state; flag IAM/network drift."
    )
    p.add_argument("--tf", required=True,
                   help="Path to `terraform show -json` output")
    p.add_argument("--observed", required=True,
                   help="Path to AWS observed-state JSON (see samples/)")
    p.add_argument("--ignore", action="append", default=[],
                   help="Field name(s) to ignore in diffs (repeatable)")
    p.add_argument("--json", help="Write findings JSON to this path")
    p.add_argument("--pr-out", help="Render PR body Markdown to this path")
    p.add_argument("--create-pr", action="store_true",
                   help="Open a PR using `gh` (requires gh CLI + git repo)")
    p.add_argument("--pr-branch", help="Head branch for the PR (used with --create-pr)")
    p.add_argument("--pr-title", default="chore(drift): remediate detected Terraform drift",
                   help="PR title")
    p.add_argument("--fail-on", default="critical",
                   choices=["never", "low", "medium", "high", "critical"],
                   help="Exit non-zero on findings >= this severity (CI gate)")
    return p.parse_args(argv)


def _fail_threshold(level: str, findings: list[dict]) -> bool:
    if level == "never":
        return False
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    needle = level.upper()
    if needle not in order:
        return False
    cutoff = order.index(needle)
    return any(order.index(f.get("severity", "LOW")) >= cutoff for f in findings)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    items, findings = detect(args.tf, args.observed, args.ignore)
    print_drift(items, findings)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "ts": int(time.time()),
                "drift_items": [it.as_dict() for it in items],
                "findings": findings,
            }, fh, indent=2)
        print(_c("DIM", f"   -> wrote {args.json}"))

    if args.pr_out:
        write_pr_body(findings, len(items), args.pr_out)
        print(_c("DIM", f"   -> wrote PR body to {args.pr_out}"))

    if args.create_pr:
        if not args.pr_out:
            args.pr_out = "drift_report.md"
            write_pr_body(findings, len(items), args.pr_out)
        ok, msg = open_pr_via_gh(args.pr_title, args.pr_out, args.pr_branch)
        if ok:
            print(_c("OK", f"[+] PR opened: {msg}"))
        else:
            print(_c("HIGH", f"[!] gh PR failed: {msg}"))

    return 1 if _fail_threshold(args.fail_on, findings) else 0


if __name__ == "__main__":
    sys.exit(main())
