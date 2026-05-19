"""Attack B: false malware-family / threat-actor attribution.

Rewrites threat-actor or malware-family names to incorrect ones while
keeping the surrounding text intact.
"""

from __future__ import annotations

from typing import Dict


ACTOR_SWAPS = {
    "FIN7": "APT29",
    "FIN8": "APT28",
    "Lazarus": "TA505",
    "APT28": "FIN7",
    "APT29": "Lazarus",
}


def inject_false_attribution(text: str) -> Dict:
    changed = []
    new_text = text
    for src, tgt in ACTOR_SWAPS.items():
        if src in new_text:
            new_text = new_text.replace(src, tgt)
            changed.append({"from": src, "to": tgt})
    if not changed and "campaign" in new_text.lower():
        new_text += "\n\nThis campaign is attributed to APT29.\n"
        changed.append({"from": None, "to": "APT29"})
    return {
        "attack": "false_attribution",
        "poisoned_text": new_text,
        "ground_truth_changes": changed,
    }
