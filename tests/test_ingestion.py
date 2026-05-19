from app.ingestion.chunker import chunk_text
from app.ingestion.metadata_extractor import extract_metadata
from app.ingestion.text_loader import load_text


def test_load_text_from_bytes():
    assert load_text(b"hello world") == "hello world"


def test_chunker_preserves_offsets():
    text = "A" * 1500
    chunks = chunk_text(text, doc_id="doc1", size=400, overlap=50)
    assert len(chunks) >= 3
    # Every chunk has consistent offsets back into the source
    for c in chunks:
        assert text[c.start_char:c.end_char] == c.text
    # Chunks tile the text (with overlap)
    assert chunks[0].start_char == 0
    assert chunks[-1].end_char == len(text)


def test_metadata_extraction_finds_date():
    text = "ACME Threat Brief\nPublished: 2025-10-01\nBody body body."
    meta = extract_metadata(text)
    assert meta["published_date"] == "2025-10-01"
    assert meta["title"]
