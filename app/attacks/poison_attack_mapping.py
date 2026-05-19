"""Attack C: wrong ATT&CK mapping injection.

Rewrites correct technique IDs to *plausible but wrong* ones in the report.
Also injects a fabricated 'analyst note' claiming the wrong technique.
"""

from __future__ import annotations

import re
from typing import Dict


WRONG_MAP = {
    "T1059.001": ("T1047", "Windows Management Instrumentation"),
    "T1059.003": ("T1059.005", "Visual Basic"),
    "T1218.011": ("T1218.010", "Regsvr32"),
    "T1105": ("T1568.002", "Domain Generation Algorithms"),
}


def inject_wrong_attack_mapping(text: str) -> Dict:
    changed = []
    new_text = text
    for correct, (wrong, wrong_name) in WRONG_MAP.items():
        if correct in new_text:
            new_text = new_text.replace(correct, wrong)
            changed.append({"correct": correct, "wrong": wrong, "wrong_name": wrong_name})

    if changed:
        note = ("\n\nAnalyst note: based on observed behavior, the activity is "
                f"better explained by {changed[0]['wrong']} "
                f"({changed[0]['wrong_name']}) rather than the originally "
                "reported technique.\n")
        new_text += note
    return {
        "attack": "wrong_attack_mapping",
        "poisoned_text": new_text,
        "ground_truth_changes": changed,
    }
