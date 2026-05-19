"""Attack A: fake IOC injection.

Inserts attacker-controlled, *clearly fabricated* IOCs into a clean report.
The output is annotated so evaluation knows the ground-truth poison set.
"""

from __future__ import annotations

import random
from typing import Dict, List

FAKE_DOMAINS = [
    "secure-update-check[.]com",
    "trusted-cdn-mirror[.]net",
    "windows-patch-service[.]org",
    "office365-sync[.]top",
]
FAKE_IPS = ["203.0.113.45", "198.51.100.7", "192.0.2.250"]
FAKE_HASHES = [
    "d41d8cd98f00b204e9800998ecf8427e",  # 32 hex
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # 40 hex
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # 64 hex
]


def inject_fake_iocs(text: str, n_domains: int = 2, n_ips: int = 1,
                     n_hashes: int = 1, seed: int = 17) -> Dict:
    rng = random.Random(seed)
    domains = rng.sample(FAKE_DOMAINS, k=min(n_domains, len(FAKE_DOMAINS)))
    ips = rng.sample(FAKE_IPS, k=min(n_ips, len(FAKE_IPS)))
    hashes = rng.sample(FAKE_HASHES, k=min(n_hashes, len(FAKE_HASHES)))

    injection_lines: List[str] = []
    for d in domains:
        injection_lines.append(
            f"The malware was observed beaconing to {d} as a C2 domain."
        )
    for ip in ips:
        injection_lines.append(
            f"Analysts confirmed connections to the attacker IP {ip}."
        )
    for h in hashes:
        injection_lines.append(
            f"The dropper binary has SHA256/MD5/SHA1 hash {h}."
        )
    inserted = "\n\n" + "\n".join(injection_lines) + "\n"

    # Insert after the first paragraph so retrievers still surface it.
    parts = text.split("\n\n", 1)
    if len(parts) == 2:
        poisoned = parts[0] + inserted + "\n\n" + parts[1]
    else:
        poisoned = text + inserted

    return {
        "attack": "fake_ioc_injection",
        "poisoned_text": poisoned,
        "ground_truth_fake_iocs": {
            "domains": [d.replace("[.]", ".") for d in domains],
            "ips": ips,
            "hashes": hashes,
        },
    }
