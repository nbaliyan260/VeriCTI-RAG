import pytest

from app.core.schemas import STIXEntity
from app.extraction.ioc_extractor import extract_iocs_from_chunk
from app.extraction.stix_extractor import extract_stix


def test_ioc_extractor_finds_defanged_domain():
    chunk = {
        "chunk_id": "c1",
        "doc_id": "d1",
        "text": "Beacons to evil-site[.]com and 198.51.100.7",
        "start_char": 0, "end_char": 50,
    }
    iocs = extract_iocs_from_chunk(chunk)
    values = {e.value for e in iocs}
    assert "evil-site.com" in values
    assert "198.51.100.7" in values


def test_entity_must_have_evidence():
    with pytest.raises(ValueError):
        STIXEntity(entity_id="x", stix_type="indicator", name="bad",
                   value="bad.com", confidence=0.9, evidence_chunk_ids=[])


def test_extract_stix_finds_relationships():
    chunks = [{
        "chunk_id": "c1",
        "doc_id": "d1",
        "text": ("FIN7 uses PowerShell to execute encoded commands. "
                 "The malware ExampleRAT communicates with bad-domain.com."),
        "start_char": 0, "end_char": 200,
    }]
    ents, rels = extract_stix(chunks)
    types = {e.stix_type for e in ents}
    assert "threat-actor" in types
    assert "tool" in types
    assert any(r.relationship_type == "uses" for r in rels)
