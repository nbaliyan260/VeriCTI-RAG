"""Common evaluation metrics."""

from __future__ import annotations

from typing import Dict, Iterable, Set, Tuple


def _to_set(items: Iterable) -> Set:
    return set(items or [])


def precision_recall_f1(pred: Iterable, gold: Iterable) -> Tuple[float, float, float]:
    p, g = _to_set(pred), _to_set(gold)
    if not p and not g:
        return 1.0, 1.0, 1.0
    tp = len(p & g)
    precision = tp / len(p) if p else 0.0
    recall = tp / len(g) if g else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def attack_mapping_accuracy(pred: Iterable[str], gold: Iterable[str]) -> float:
    g = _to_set(gold)
    if not g:
        return 1.0
    p = _to_set(pred)
    return len(p & g) / len(g)


def poisoning_success_rate(pred_after: Iterable, fake_items: Iterable) -> float:
    p = _to_set(pred_after)
    f = _to_set(fake_items)
    if not f:
        return 0.0
    return len(p & f) / len(f)


def false_positive_rate(benign_hits: int, benign_total: int) -> float:
    return benign_hits / benign_total if benign_total else 0.0


def true_positive_rate(malicious_hits: int, malicious_total: int) -> float:
    return malicious_hits / malicious_total if malicious_total else 0.0


def evidence_faithfulness(entities) -> float:
    """Mean entity confidence as a proxy for evidence-faithfulness."""
    if not entities:
        return 0.0
    return sum(getattr(e, "confidence", 0.0) for e in entities) / len(entities)


def summarize(label: str, **kwargs) -> Dict:
    out = {"label": label}
    out.update(kwargs)
    return out
