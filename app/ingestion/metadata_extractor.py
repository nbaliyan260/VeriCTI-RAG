"""Best-effort metadata extraction (title / published date) from raw text.

We avoid LLM calls here. Heuristics are deliberate so ingestion stays
deterministic.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Dict, Optional


_DATE_PATTERNS = [
    r"(20\d{2}-\d{2}-\d{2})",
    r"((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s*20\d{2})",
    r"(\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+20\d{2})",
]


def _parse_date(s: str) -> Optional[str]:
    for fmt in ("%Y-%m-%d", "%B %d, %Y", "%b %d, %Y", "%d %B %Y", "%d %b %Y"):
        try:
            return datetime.strptime(s.strip(), fmt).date().isoformat()
        except ValueError:
            continue
    return None


def extract_metadata(text: str, fallback_title: str = "Untitled Report") -> Dict[str, Optional[str]]:
    title = fallback_title
    for line in text.splitlines():
        line = line.strip()
        if 8 <= len(line) <= 140 and any(c.isalpha() for c in line):
            title = line
            break

    published_date = None
    for pat in _DATE_PATTERNS:
        m = re.search(pat, text)
        if m:
            published_date = _parse_date(m.group(1)) or m.group(1)
            break

    return {"title": title, "published_date": published_date}
