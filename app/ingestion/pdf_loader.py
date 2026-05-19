"""PDF loading using pypdf, with a graceful fallback to pdfplumber."""

from __future__ import annotations

from pathlib import Path
from typing import Union


def load_pdf(path_or_bytes: Union[str, Path, bytes]) -> str:
    text = ""
    try:
        from pypdf import PdfReader  # type: ignore

        if isinstance(path_or_bytes, (str, Path)):
            reader = PdfReader(str(path_or_bytes))
        else:
            import io

            reader = PdfReader(io.BytesIO(path_or_bytes))
        for page in reader.pages:
            try:
                text += (page.extract_text() or "") + "\n"
            except Exception:
                continue
    except Exception:
        # Fallback to pdfplumber if pypdf fails or is unavailable.
        try:
            import pdfplumber  # type: ignore

            if isinstance(path_or_bytes, (str, Path)):
                pdf = pdfplumber.open(str(path_or_bytes))
            else:
                import io

                pdf = pdfplumber.open(io.BytesIO(path_or_bytes))
            with pdf:
                for page in pdf.pages:
                    text += (page.extract_text() or "") + "\n"
        except Exception as exc:  # pragma: no cover - depends on libs
            raise RuntimeError(f"PDF parsing failed: {exc}") from exc
    return text
