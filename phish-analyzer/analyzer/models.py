from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high"]
VerdictLabel = Literal["safe", "suspicious", "phishing"]


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    evidence: str


class EmailLink(BaseModel):
    visible_text: str
    href: str
    display_url_mismatch: bool = False


class AttachmentInfo(BaseModel):
    filename: str
    content_type: str
    size: int


class EmailData(BaseModel):
    from_header: str = ""
    from_name: str = ""
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    subject: str = ""
    date: str = ""
    received: list[str] = Field(default_factory=list)
    authentication_results: str = ""
    auth_results: dict[str, str] = Field(default_factory=dict)
    text_body: str = ""
    html_body: str = ""
    html_text: str = ""
    links: list[EmailLink] = Field(default_factory=list)
    attachments: list[AttachmentInfo] = Field(default_factory=list)


class Verdict(BaseModel):
    verdict: VerdictLabel
    risk_score: int = Field(ge=0, le=100)
    summary: str
    reasons: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)

