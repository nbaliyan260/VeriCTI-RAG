"""LLM abstraction layer.

The system supports three providers:

* ``mock``      – deterministic, no network. Used by default and in tests.
* ``openai``    – uses the ``openai`` SDK if installed and OPENAI_API_KEY set.
* ``anthropic`` – uses the ``anthropic`` SDK if installed and ANTHROPIC_API_KEY.

All callers go through ``LLM.complete_json(prompt, schema_hint)`` so that we
can force JSON output regardless of provider. The mock provider returns an
empty dict – the rule-based extractors in ``extraction/*`` cover the
deterministic path and do not require an LLM for the MVP.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .config import get_settings


@dataclass
class LLMResponse:
    text: str
    data: Dict[str, Any]


class BaseLLM:
    name = "base"

    def complete_json(self, prompt: str, schema_hint: Optional[str] = None) -> LLMResponse:
        raise NotImplementedError


class MockLLM(BaseLLM):
    name = "mock"

    def complete_json(self, prompt: str, schema_hint: Optional[str] = None) -> LLMResponse:
        # The mock LLM is intentionally inert. Callers should fall back to
        # the deterministic rule-based extractors.
        return LLMResponse(text="{}", data={})


class OpenAILLM(BaseLLM):
    name = "openai"

    def __init__(self, model: Optional[str] = None) -> None:
        from openai import OpenAI  # type: ignore

        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = model or get_settings().llm_model

    def complete_json(self, prompt: str, schema_hint: Optional[str] = None) -> LLMResponse:
        sys = (
            "You are a CTI extraction assistant. Respond with strict JSON only. "
            "Do not include any commentary."
        )
        if schema_hint:
            sys += f" Conform to this schema: {schema_hint}"
        resp = self.client.chat.completions.create(
            model=self.model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": sys},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
        )
        text = resp.choices[0].message.content or "{}"
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        return LLMResponse(text=text, data=data)


class AnthropicLLM(BaseLLM):
    name = "anthropic"

    def __init__(self, model: Optional[str] = None) -> None:
        from anthropic import Anthropic  # type: ignore

        self.client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.model = model or "claude-3-5-sonnet-latest"

    def complete_json(self, prompt: str, schema_hint: Optional[str] = None) -> LLMResponse:
        sys = (
            "You are a CTI extraction assistant. Respond with strict JSON only. "
            "Do not include any commentary."
        )
        if schema_hint:
            sys += f" Conform to this schema: {schema_hint}"
        msg = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            system=sys,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in msg.content if hasattr(block, "text"))
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        return LLMResponse(text=text, data=data)


def get_llm() -> BaseLLM:
    provider = get_settings().llm_provider.lower()
    if provider == "openai" and os.getenv("OPENAI_API_KEY"):
        try:
            return OpenAILLM()
        except Exception:
            return MockLLM()
    if provider == "anthropic" and os.getenv("ANTHROPIC_API_KEY"):
        try:
            return AnthropicLLM()
        except Exception:
            return MockLLM()
    return MockLLM()
