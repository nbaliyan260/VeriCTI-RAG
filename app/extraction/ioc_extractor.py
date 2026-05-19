"""Regex-based IOC extraction with evidence linking.

Supports:
* IPv4 addresses (defanged or normal)
* Domains (defanged or normal)
* URLs
* MD5 / SHA1 / SHA256 hashes
* CVE identifiers

Every IOC is linked back to a specific chunk by ``chunk_id``.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List

from ..core.schemas import STIXEntity


def _refang(text: str) -> str:
    return (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[dot]", ".")
        .replace("hxxp", "http")
        .replace("hxxps", "https")
        .replace("[:]", ":")
    )


_PATTERNS = {
    "ipv4": re.compile(
        r"(?<![\d.])((?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3})(?![\d.])"
    ),
    # Domain handling is done via a candidate regex + validation helper
    # to avoid substring false-positives and truncated TLDs.
    "domain": re.compile(
        r"(?:(?<=^)|(?<=[\s\"'\(\[\{<>,;:]))"  # safe left boundary
        r"([A-Za-z0-9][A-Za-z0-9\-\[\]\.]{2,253})"  # candidate token
        r"(?=$|[\s\"'\)\]\}>.,;:]|[^A-Za-z0-9\-])"  # safe right boundary
    ),
    "url": re.compile(
        r"\b(h(?:xx|tt)ps?://[^\s)>\]]+)", re.IGNORECASE
    ),
    "md5": re.compile(r"\b([a-fA-F0-9]{32})\b"),
    "sha1": re.compile(r"\b([a-fA-F0-9]{40})\b"),
    "sha256": re.compile(r"\b([a-fA-F0-9]{64})\b"),
    "cve": re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE),
}


_KNOWN_TLDS = {
    "com",
    "net",
    "org",
    "io",
    "info",
    "biz",
    "co",
    "us",
    "uk",
    "ru",
    "cn",
    "de",
    "fr",
    "app",
    "dev",
    "xyz",
    "top",
    "site",
    "online",
    "me",
    "example",
    "test",
}


def _is_valid_domain(candidate: str) -> bool:
    c = _refang(candidate).strip().strip(".")
    if len(c) < 4 or len(c) > 253:
        return False
    if "/" in c or "\\" in c or "@" in c:
        return False
    if c.count(".") < 1:
        return False
    # Don't allow domains to start/end with '-' in any label
    labels = c.split(".")
    if any((not lab) or lab.startswith("-") or lab.endswith("-") for lab in labels):
        return False
    tld = labels[-1].lower()
    if tld not in _KNOWN_TLDS:
        return False
    return True


def extract_iocs_from_chunk(chunk: Dict) -> List[STIXEntity]:
    """Extract IOCs from a single chunk and emit STIX `indicator` entities."""
    text = chunk["text"]
    start_char = int(chunk.get("start_char") or 0)
    original_text = chunk.get("original_text")
    entities: List[STIXEntity] = []
    seen: set[tuple[str, str]] = set()

    for ioc_type, pattern in _PATTERNS.items():
        for m in pattern.finditer(text):
            raw = m.group(1)

            # If the chunk starts mid-token (because of overlap/snap), the
            # first few characters can be a suffix of the real IOC.
            # Example: "example-c2.com" split -> chunk begins with "xample-c2.com".
            if m.start(1) == 0 and start_char > 0:
                if original_text and start_char - 1 < len(original_text):
                    prev = original_text[start_char - 1]
                    if prev.isalnum():
                        continue
                else:
                    # Conservative fallback when we can't inspect original text.
                    # Avoid extracting IOCs starting at 0 when the chunk is not
                    # the beginning of the document.
                    if ioc_type in {"domain", "url"}:
                        continue

            # Normalize common punctuation wrappers/terminators early.
            # This avoids emitting both `example.com` and `example.com.`.
            raw_norm = raw.strip("'\"()[]{}<>.,;:")
            if not raw_norm:
                continue

            # Domain candidates are matched broadly; validate before emitting.
            if ioc_type == "domain" and not _is_valid_domain(raw_norm):
                continue

            # Heuristic: avoid substring domains that start mid-token.
            # Example: "...example-c2.com" should not yield "xample-c2.com".
            if ioc_type == "domain":
                start = m.start(1)
                if start > 0 and text[start - 1].isalnum():
                    continue

            value = _refang(raw_norm).strip()

            # Filter out invalid IPv4 ranges / common false positives.
            if ioc_type == "ipv4":
                parts = value.split(".")
                if len(parts) != 4:
                    continue
                try:
                    octets = [int(p) for p in parts]
                except ValueError:
                    continue
                if any(o < 0 or o > 255 for o in octets):
                    continue
            key = (ioc_type, value.lower())
            if key in seen:
                continue
            seen.add(key)
            entity_id = f"ioc_{ioc_type}_{abs(hash(value)) % (10**10)}"
            entities.append(
                STIXEntity(
                    entity_id=entity_id,
                    stix_type="indicator",
                    name=f"{ioc_type}: {value}",
                    value=value,
                    confidence=0.75,
                    evidence_chunk_ids=[chunk["chunk_id"]],
                )
            )
    return entities


def extract_iocs(chunks: Iterable[Dict]) -> List[STIXEntity]:
    by_value: Dict[str, STIXEntity] = {}
    for ch in chunks:
        for e in extract_iocs_from_chunk(ch):
            key = (e.stix_type, (e.value or "").lower())
            existing = by_value.get(str(key))
            if existing:
                # Merge evidence
                merged = sorted(set(existing.evidence_chunk_ids + e.evidence_chunk_ids))
                existing.evidence_chunk_ids = merged
                existing.confidence = min(0.99, existing.confidence + 0.05 * (len(merged) - 1))
            else:
                by_value[str(key)] = e
    return list(by_value.values())
