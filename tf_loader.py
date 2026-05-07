"""
Load `terraform show -json` output and an AWS observed-state JSON, both
normalized to the same shape:

    { "<resource_type>": { "<address>": {<attrs>} } }

Terraform JSON shape (from `terraform show -json`):

    {
      "values": {
        "root_module": {
          "resources": [
            { "address": "...", "type": "...", "values": {...}, ... },
            ...
          ],
          "child_modules": [ ... recursive ... ]
        }
      }
    }
"""
from __future__ import annotations

import json
from typing import Any


def _walk_module(module: dict) -> list[dict]:
    out = list(module.get("resources") or [])
    for child in (module.get("child_modules") or []):
        out.extend(_walk_module(child))
    return out


def load_terraform_show(path: str) -> dict[str, dict[str, dict]]:
    """Parse terraform show -json output into the canonical inventory shape."""
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    root = (doc.get("values") or {}).get("root_module") or {}
    resources = _walk_module(root)
    inventory: dict[str, dict[str, dict]] = {}
    for r in resources:
        rtype = r.get("type")
        addr = r.get("address")
        if not rtype or not addr:
            continue
        values = r.get("values") or {}
        # Try to JSON-parse policy fields so structural diffs make sense.
        for k in ("policy", "assume_role_policy"):
            v = values.get(k)
            if isinstance(v, str):
                try:
                    values[k] = json.loads(v)
                except (ValueError, TypeError):
                    pass
        inventory.setdefault(rtype, {})[addr] = values
    return inventory


def load_observed_state(path: str) -> dict[str, dict[str, dict]]:
    """
    Load an AWS observed-state JSON. Already in inventory shape — just verify.
    Sample shape in samples/aws_observed_state.json.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("observed-state JSON must be an object at the top level")
    # Light validation
    for rtype, addrs in data.items():
        if not isinstance(addrs, dict):
            raise ValueError(f"{rtype}: expected dict of address -> attrs")
    return data
