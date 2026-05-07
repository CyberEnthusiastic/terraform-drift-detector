# Terraform Security Drift Detector

> **Diff Terraform state against deployed AWS state. Surface IAM and network drift with severity. Auto-generate a remediation PR.**
> Catch the console-edit that grants AdministratorAccess at midnight before it becomes the next breach.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Terraform 1.0+](https://img.shields.io/badge/terraform-1.0+-7B42BC?logo=terraform&logoColor=white)](https://www.terraform.io/)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=github-actions&logoColor=white)](#ci-integration)

---

## What it does

Reads two snapshots:

- `terraform show -json` (the **baseline** — what IaC says should exist)
- An AWS observed-state JSON (the **truth** — what's actually deployed)

Computes a structural diff (`ADDED` / `REMOVED` / `MODIFIED`), then runs IAM
and network drift rules to flag the items that matter for security:
console-added admin attachments, policies edited to `Action:*`, security-group
ingress newly opened to `0.0.0.0/0`, S3 BlockPublicAccess relaxed, IAM trust
policies edited, and so on.

For every detected drift the tool generates a Markdown PR body grouped by
category and severity, with concrete `terraform apply` remediation steps.
Pass `--create-pr` and it'll open the PR via the `gh` CLI.

```
======================================================================
  Terraform Drift Detector
======================================================================
[*] Drift items   : 10  ({'MODIFIED': 4, 'ADDED': 5, 'REMOVED': 1})
[*] Rule findings : 10  ({'CRITICAL': 5, 'HIGH': 2, 'MEDIUM': 2, 'LOW': 1})

[CRITICAL] Out-of-band AdministratorAccess attachment  (iam)
   aws_iam_role_policy_attachment.console_added_admin  kind=ADDED
   > aws_iam_role_policy_attachment.console_added_admin attached AdministratorAccess to app-runtime.
   -> Detach via console; codify the actual required permission set.

[CRITICAL] Policy edited to wildcard Action+Resource  (iam)
   aws_iam_policy.app_runtime  kind=MODIFIED
   > aws_iam_policy.app_runtime: live policy now allows *:*.
   -> Revert via Terraform apply; or refactor to least-privilege.

[CRITICAL] SG ingress to 0.0.0.0/0 added on port 22  (network)
   aws_security_group_rule.console_added_ssh  kind=ADDED
   ...
```

---

## Why you want this

- **Drift kills.** A 2024 SANS survey found 67% of cloud breaches involved a configuration that was *correct in IaC* but had drifted in the live account. `terraform plan` only catches drift if every resource is under management — and only at apply time.
- **IAM and network drift dwarfs the rest.** A console-added `AdministratorAccess` attachment, or a SG rule opening port 22 to the world, can cause millions of dollars of damage. This tool focuses on those two categories with custom rules and severity grading.
- **Auto-generated PRs.** Drift becomes a Github PR with a checklist, owners can review and merge — no separate ticket or runbook needed.
- **CI-friendly.** `--fail-on critical` makes drift detection a deploy gate, not a Tuesday-morning grep.
- **Zero dependencies.** Python 3.8+ stdlib only. The AWS state collector is intentionally pluggable — use `aws cloudcontrol`, Steampipe, AWS Config, or your own collector.

---

## Quickstart

```bash
git clone https://github.com/CyberEnthusiastic/terraform-drift-detector.git
cd terraform-drift-detector

# Run the bundled samples (intentionally noisy — 5 CRITICAL drift items):
python detector.py --tf samples/terraform.tfstate.json \
                   --observed samples/aws_observed_state.json \
                   --pr-out drift_report.md

# Real run inside your repo:
terraform show -json > /tmp/tf.json
python collect_aws_state.py > /tmp/aws.json     # or your own collector
python detector.py --tf /tmp/tf.json --observed /tmp/aws.json \
                   --pr-out drift.md --create-pr --pr-branch drift-$(date +%s)

# CI gate — fail the deploy if any CRITICAL drift exists:
python detector.py --tf tf.json --observed aws.json --fail-on critical
```

---

## What gets detected

### IAM rules (`rules/iam_rules.py`)

| Rule | Severity | Trigger |
|---|---|---|
| Out-of-band AdministratorAccess attachment | CRITICAL | New `aws_iam_*_policy_attachment` with `AdministratorAccess` |
| Policy edited to wildcard `Action+Resource` | CRITICAL | Existing IAM policy now contains `Allow * on *` |
| Terraform-managed IAM role deleted | HIGH | `aws_iam_role` removed from observed state |
| IAM role trust policy modified out-of-band | HIGH | `assume_role_policy` differs from baseline |
| Inline IAM policy added out-of-band | MEDIUM | `aws_iam_role_policy` not in TF |
| Access key created out-of-band | HIGH | `aws_iam_access_key` not in TF |
| Password policy minimum length weakened | MEDIUM | min length reduced relative to baseline |

### Network rules (`rules/network_rules.py`)

| Rule | Severity | Trigger |
|---|---|---|
| SG ingress to 0.0.0.0/0 added on port 22/3389/3306/5432/6379/27017 | CRITICAL | High-value port exposed |
| SG ingress to 0.0.0.0/0 added on any other port | HIGH | World-open ingress |
| SG inline rule opened port to world | HIGH/CRITICAL | Inline rule drift |
| NACL ingress rule allows 0.0.0.0/0 | HIGH | `aws_network_acl_rule` ALLOW from world |
| VPC endpoint deleted | MEDIUM | `aws_vpc_endpoint` removed |
| Default route added pointing to IGW | HIGH | `0.0.0.0/0 → igw-*` |
| S3 BlockPublicAccess relaxed | CRITICAL | Any of the four flags toggled true→false |
| ALB HTTP listener (no redirect) added | MEDIUM | Port 80 listener with no HTTPS redirect |
| CloudFront origin protocol downgraded | HIGH | `https-only` → `http-only` / `match-viewer` |

Adding a rule = a single Python function that takes a `DriftItem`, returns
`list[finding]`. See `rules/iam_rules.py` for examples.

---

## How input is collected

The tool is collector-agnostic. Anything that can produce the inventory shape
documented in `samples/aws_observed_state.json` works. Two recommended paths:

**Pure CLI (no extra deps):**

```bash
# Roles
aws iam list-roles --output json | jq '...' > obs_roles.json
# Security groups
aws ec2 describe-security-groups --output json | jq '...' > obs_sg.json
# Merge into one file matching the inventory shape
```

**Steampipe** (if you already use it):

```sql
SELECT name, assume_role_policy FROM aws_iam_role;
SELECT * FROM aws_security_group_rule;
-- Export to JSON, key by Terraform-style address.
```

**AWS Config aggregator:** read `aws_config_resource_history` and project
into the inventory shape.

The shape is intentionally simple so you can keep your collector behind your
firewall — the detector itself never talks to AWS.

---

## CLI

```
usage: detector.py [-h] --tf TF --observed OBSERVED [--ignore FIELD]
                   [--json PATH] [--pr-out PATH] [--create-pr]
                   [--pr-branch BRANCH] [--pr-title TITLE]
                   [--fail-on {never,low,medium,high,critical}]
```

| Flag | Purpose |
|---|---|
| `--tf PATH` | `terraform show -json` output |
| `--observed PATH` | AWS observed-state JSON |
| `--ignore FIELD` | Field name to ignore in diffs (repeatable). Useful for `tags_all`, `arn`, `id` etc. — defaults already cover the common noise |
| `--json PATH` | Write findings + drift items as JSON for downstream tools |
| `--pr-out PATH` | Render PR body Markdown to this path |
| `--create-pr` | Open PR via `gh` (requires `gh` CLI, current dir must be a git repo) |
| `--pr-branch BRANCH` | Head branch for the PR |
| `--fail-on LEVEL` | Exit non-zero on findings ≥ this severity |

---

## CI integration

```yaml
# .github/workflows/drift.yml
name: drift
on:
  schedule: [{cron: '0 6 * * *'}]
  workflow_dispatch: {}

jobs:
  detect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3

      - name: Plan + show state
        run: |
          terraform init
          terraform show -json terraform.tfstate > tf.json

      - name: Collect observed AWS state
        run: ./scripts/collect_aws.sh > aws.json

      - name: Run drift detector
        run: |
          python detector.py --tf tf.json --observed aws.json \
                             --pr-out drift.md --fail-on critical \
                             --create-pr --pr-branch drift-${{ github.run_id }}
```

---

## Architecture

```
detector.py        ── CLI entry point, prints summary, calls PR generator
diff_engine.py     ── structural diff (ADDED/REMOVED/MODIFIED + field-level)
tf_loader.py       ── parses terraform show -json + observed-state JSON
pr_generator.py    ── Markdown PR body renderer + gh CLI shell-out
rules/
  iam_rules.py     ── 7 IAM drift rules
  network_rules.py ── 8 network drift rules
samples/
  terraform.tfstate.json   ── intentional baseline
  aws_observed_state.json  ── intentional drift fixture
tests/
  test_detector.py ── 16 unit tests, runs in <50ms
```

---

## Running the tests

```bash
python -m unittest discover tests
```

16 tests covering: diff engine (added/removed/modified, ignored fields,
list/dict walk), end-to-end on samples (≥5 CRITICAL findings expected),
PR body rendering (empty + grouped), TF loader (policy JSON unwrap), and
rule registration.

---

## License

MIT — see [LICENSE](./LICENSE).
