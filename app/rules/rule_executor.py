"""Execute Sigma rules against synthetic JSON log streams.

We support the subset of Sigma needed by the MVP templates:
    * field|endswith
    * field|contains  (with string or list values)
    * field           (exact match)
    * AND across keys in the selection block
    * OR across list-valued items
    * condition: ``selection`` (single block)

Logs are JSON-line files (one JSON object per line) typical of Sysmon /
process-creation telemetry.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import yaml


def _matches_value(field_val, modifier: str, target) -> bool:
    if field_val is None:
        return False
    s = str(field_val).lower()
    if isinstance(target, list):
        return any(_matches_value(field_val, modifier, t) for t in target)
    t = str(target).lower()
    if modifier == "endswith":
        return s.endswith(t)
    if modifier == "startswith":
        return s.startswith(t)
    if modifier == "contains":
        return t in s
    # exact / default
    return s == t


def _match_event(event: Dict, selection: Dict) -> bool:
    for raw_key, target in selection.items():
        if "|" in raw_key:
            field, modifier = raw_key.split("|", 1)
        else:
            field, modifier = raw_key, "exact"
        if not _matches_value(event.get(field), modifier, target):
            return False
    return True


def _iter_jsonl(path: Path) -> Iterable[Dict]:
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def execute_rule(rule_text: str, *, malicious_log: Path, benign_log: Path) -> Dict[str, int]:
    """Run a Sigma rule against malicious + benign log files.

    Returns counts: ``malicious_hits``, ``malicious_total``,
    ``benign_hits``, ``benign_total``.
    """
    doc = yaml.safe_load(rule_text)
    detection = doc.get("detection") or {}
    selection = None
    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            selection = val
            break
    if selection is None:
        return {"malicious_hits": 0, "malicious_total": 0,
                "benign_hits": 0, "benign_total": 0}

    mh = mt = bh = bt = 0
    for ev in _iter_jsonl(malicious_log):
        mt += 1
        if _match_event(ev, selection):
            mh += 1
    for ev in _iter_jsonl(benign_log):
        bt += 1
        if _match_event(ev, selection):
            bh += 1
    return {"malicious_hits": mh, "malicious_total": mt,
            "benign_hits": bh, "benign_total": bt}


def collect_log_pair(malicious_dir: Path, benign_dir: Path,
                     technique_id: str) -> Tuple[Path, Path]:
    """Return per-technique log files if present, else default files."""
    mal = malicious_dir / f"{technique_id}.jsonl"
    ben = benign_dir / f"{technique_id}.jsonl"
    if not mal.exists():
        mal = malicious_dir / "default.jsonl"
    if not ben.exists():
        ben = benign_dir / "default.jsonl"
    return mal, ben
