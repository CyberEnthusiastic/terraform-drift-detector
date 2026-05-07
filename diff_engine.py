"""
Drift diff engine.

Compares two normalized inventories of AWS resources:
  baseline   = what Terraform says SHOULD be deployed
  observed   = what AWS actually shows is deployed

Both are dicts of:
  { "<resource_type>": { "<address>": { ...attrs... } } }

The diff identifies four categories per resource:
  ADDED       - present in observed, absent from baseline
                (drift: someone created it manually, no IaC)
  REMOVED     - present in baseline, absent from observed
                (drift: someone deleted via console; TF will recreate)
  MODIFIED    - same address, attribute values differ
                (drift: live attrs were edited; TF would revert)
  UNCHANGED   - identical

Severity is rule-derived; the engine is purely structural.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class FieldChange:
    field: str
    baseline: Any
    observed: Any


@dataclass
class DriftItem:
    resource_type: str
    address: str
    kind: str  # ADDED | REMOVED | MODIFIED
    changes: list[FieldChange] = field(default_factory=list)
    baseline: dict | None = None
    observed: dict | None = None

    def as_dict(self) -> dict:
        return {
            "resource_type": self.resource_type,
            "address": self.address,
            "kind": self.kind,
            "changes": [{"field": c.field, "baseline": c.baseline, "observed": c.observed}
                        for c in self.changes],
            "baseline": self.baseline,
            "observed": self.observed,
        }


def _walk_diff(prefix: str, baseline: Any, observed: Any) -> list[FieldChange]:
    """Recursive shallow diff: yields FieldChange for any leaf value mismatch."""
    out: list[FieldChange] = []
    if type(baseline) is not type(observed) and baseline is not None and observed is not None:
        out.append(FieldChange(prefix or "<root>", baseline, observed))
        return out

    if isinstance(baseline, dict) and isinstance(observed, dict):
        for k in sorted(set(baseline) | set(observed)):
            out.extend(_walk_diff(f"{prefix}.{k}" if prefix else k,
                                  baseline.get(k), observed.get(k)))
    elif isinstance(baseline, list) and isinstance(observed, list):
        # Treat list-of-primitives as a set; compare sorted.
        if all(not isinstance(x, (dict, list)) for x in baseline + observed):
            if sorted(map(str, baseline)) != sorted(map(str, observed)):
                out.append(FieldChange(prefix, baseline, observed))
        else:
            # Length mismatch → record as one diff; structural diff would be noisy.
            if len(baseline) != len(observed):
                out.append(FieldChange(prefix, baseline, observed))
            else:
                for i, (b, o) in enumerate(zip(baseline, observed)):
                    out.extend(_walk_diff(f"{prefix}[{i}]", b, o))
    else:
        if baseline != observed:
            out.append(FieldChange(prefix or "<root>", baseline, observed))
    return out


def diff_inventories(baseline: dict, observed: dict, ignore_fields: Iterable[str] = ()) -> list[DriftItem]:
    """Return DriftItem for every (type, address) where baseline ≠ observed."""
    items: list[DriftItem] = []
    types = set(baseline) | set(observed)

    ignored = set(ignore_fields)

    for rtype in sorted(types):
        b_addrs = baseline.get(rtype, {}) or {}
        o_addrs = observed.get(rtype, {}) or {}
        all_addrs = set(b_addrs) | set(o_addrs)
        for addr in sorted(all_addrs):
            b = b_addrs.get(addr)
            o = o_addrs.get(addr)
            if b is None and o is not None:
                items.append(DriftItem(rtype, addr, "ADDED", baseline=None, observed=o))
            elif o is None and b is not None:
                items.append(DriftItem(rtype, addr, "REMOVED", baseline=b, observed=None))
            elif b != o:
                changes = [c for c in _walk_diff("", b, o) if c.field not in ignored]
                if changes:
                    items.append(DriftItem(rtype, addr, "MODIFIED",
                                           changes=changes, baseline=b, observed=o))
    return items
