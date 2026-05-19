"""Attack F: stale IOC injection.

Adds IOCs with attached "last seen" dates that are well in the past so that
the freshness scorer should down-rank them.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Dict


STALE_DOMAINS = [
    "old-c2-server.example",
    "expired-malware-host.test",
    "legacy-beacon-domain.example",
]


def inject_stale_iocs(text: str, days_old: int = 720) -> Dict:
    last_seen = (date.today() - timedelta(days=days_old)).isoformat()
    lines = [
        f"Indicator {d} was observed during the campaign (last seen {last_seen})."
        for d in STALE_DOMAINS
    ]
    payload = "\n\n" + "\n".join(lines) + "\n"
    return {
        "attack": "stale_ioc",
        "poisoned_text": text + payload,
        "ground_truth_stale_iocs": STALE_DOMAINS,
        "last_seen": last_seen,
    }
