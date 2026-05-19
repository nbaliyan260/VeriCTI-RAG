"""Sigma syntax + structural validation.

Tries to use ``pysigma`` (SigmaRule.from_yaml) when available; otherwise
falls back to a strict structural check against the Sigma specification:
required keys, logsource block, detection/condition presence.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import yaml


REQUIRED_TOP_KEYS = {"title", "logsource", "detection"}


def _structural_validate(doc: Dict) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    missing = REQUIRED_TOP_KEYS - set(doc.keys())
    if missing:
        errors.append(f"missing required keys: {sorted(missing)}")
    detection = doc.get("detection") or {}
    if not isinstance(detection, dict):
        errors.append("detection must be a mapping")
    else:
        if "condition" not in detection:
            errors.append("detection.condition is required")
        if len([k for k in detection if k != "condition"]) == 0:
            errors.append("detection must contain at least one selection block")
    logsource = doc.get("logsource") or {}
    if not isinstance(logsource, dict) or not logsource:
        errors.append("logsource must be a non-empty mapping")
    return (not errors, errors)


def validate_sigma(rule_text: str) -> Tuple[bool, List[str]]:
    try:
        doc = yaml.safe_load(rule_text)
    except yaml.YAMLError as e:
        return False, [f"YAML parse error: {e}"]
    if not isinstance(doc, dict):
        return False, ["rule is not a YAML mapping"]

    # Try pysigma first
    try:
        from sigma.rule import SigmaRule  # type: ignore

        SigmaRule.from_yaml(rule_text)
        ok, errs = _structural_validate(doc)
        return ok, errs
    except Exception:
        return _structural_validate(doc)
