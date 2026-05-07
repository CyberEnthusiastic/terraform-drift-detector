"""Drift rule packs (IAM, networking, generic)."""
from .iam_rules import IAM_RULES
from .network_rules import NETWORK_RULES

ALL_RULES = IAM_RULES + NETWORK_RULES
