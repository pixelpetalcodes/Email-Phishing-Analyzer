from __future__ import annotations

import os

from google import genai
from google.genai import types

from .models import EmailData, Finding, Verdict
from .prompts import chat_system_prompt, verdict_prompt


def _client() -> genai.Client:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("Gemini is not configured. Add GEMINI_API_KEY to your .env file.")
    return genai.Client(api_key=api_key)


def _model() -> str:
    return os.getenv("GEMINI_MODEL", "gemini-3.8-flash")


def get_verdict(email: EmailData, findings: list[Finding]) -> Verdict:
    client = _client()
    try:
        response = client.models.generate_content(
            model=_model(), contents=verdict_prompt(email, findings),
            config=types.GenerateContentConfig(response_mime_type="application/json", response_schema=Verdict),
        )
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()
    if not response.text:
        raise RuntimeError("Gemini returned an empty analysis. Please try again.")
    return Verdict.model_validate_json(response.text)


def chat_about_email(email: EmailData, findings: list[Finding], verdict: Verdict,
                     history: list[dict[str, str]], question: str) -> str:
    client = _client()
    contents = []
    for turn in history[-12:]:
        role = "model" if turn["role"] == "assistant" else "user"
        contents.append(types.Content(role=role, parts=[types.Part.from_text(text=turn["content"])]))
    contents.append(types.Content(role="user", parts=[types.Part.from_text(text=question)]))
    response = client.models.generate_content(
        model=_model(), contents=contents,
        config=types.GenerateContentConfig(system_instruction=chat_system_prompt(email, findings, verdict)),
    )
    if not response.text:
        raise RuntimeError("Gemini returned an empty reply. Please try again.")
    return response.text

