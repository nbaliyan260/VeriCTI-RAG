"""Pretty-printer for the final analyst report (Markdown)."""

from __future__ import annotations

from typing import Iterable

from ..core.schemas import AnalystReport


def report_to_markdown(report: AnalystReport) -> str:
    lines = [
        f"# VeriCTI-RAG Analyst Report",
        "",
        f"**Document:** `{report.doc_id}`",
        f"**Summary:** {report.campaign_summary}",
        f"**Final verdict:** **{report.final_verdict}**  ",
        f"**Final confidence:** {report.final_confidence:.2f}",
        "",
        "## STIX Entities",
    ]
    for e in report.entities[:25]:
        lines.append(
            f"- **{e.stix_type}** `{e.value or e.name}` "
            f"(conf={e.confidence:.2f}, evidence={e.evidence_chunk_ids})"
        )
    lines.append("\n## ATT&CK Mappings")
    for m in report.attack_mappings:
        lines.append(
            f"- `{m.technique_id}` {m.technique_name} ({m.tactic}) "
            f"conf={m.confidence:.2f} ev={m.evidence_chunk_ids}"
        )
    lines.append("\n## Generated Sigma Rules")
    for r in report.generated_rules:
        lines.append(f"### {r.title} (`{r.rule_id}`)\n```yaml\n{r.rule_text}\n```")
    lines.append("\n## Rule Validation")
    for v in report.validation_results:
        lines.append(
            f"- `{v.rule_id}` syntax={v.syntax_valid} semantic={v.semantic_valid} "
            f"tp={v.malicious_hits}/{v.malicious_total} "
            f"fp={v.benign_hits}/{v.benign_total} "
            f"verdict={v.final_verdict}"
        )
    if report.warnings:
        lines.append("\n## Warnings")
        for w in report.warnings:
            lines.append(f"- {w}")
    return "\n".join(lines)
