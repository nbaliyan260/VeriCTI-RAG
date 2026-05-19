"""Freshness scoring.

Maps a document's age (in days, relative to today) to a 0..1 score using an
exponential decay with configurable half-life.

Motivated by the practical finding that many IOCs are already stale by
publication time; freshness should not be assumed.
"""

from __future__ import annotations

import math
from datetime import datetime, date
from typing import Optional

from ..core.config import get_settings


def _parse(d: Optional[str]) -> Optional[date]:
    if not d:
        return None
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y"):
        try:
            return datetime.strptime(d, fmt).date()
        except ValueError:
            continue
    return None


def freshness_score(published_date: Optional[str],
                    today: Optional[date] = None) -> float:
    today = today or date.today()
    pub = _parse(published_date)
    if pub is None:
        return 0.5  # unknown -> neutral
    days = max(0, (today - pub).days)
    half_life = max(1, get_settings().freshness_half_life_days)
    return float(math.exp(-math.log(2) * days / half_life))
