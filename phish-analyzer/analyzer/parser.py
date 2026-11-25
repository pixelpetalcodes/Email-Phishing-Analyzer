from __future__ import annotations

from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
import re

from .models import AttachmentInfo, EmailData, EmailLink

MAX_EMAIL_BYTES = 5 * 1024 * 1024


class _SafeHTMLExtractor(HTMLParser):
    """Extract text and links only; email HTML is never rendered or executed."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[EmailLink] = []
        self._anchors: list[dict[str, str | bool]] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = dict(attrs)
        if tag.lower() in {"script", "style", "head", "iframe", "object", "svg"}:
            self._skip_depth += 1
        if tag.lower() == "a":
            self._anchors.append({"href": attrs_map.get("href") or "", "text": ""})
        if tag.lower() in {"br", "p", "div", "li", "tr", "h1", "h2", "h3"}:
            self.text.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._anchors:
            anchor = self._anchors.pop()
            href = str(anchor["href"]).strip()
            visible = str(anchor["text"]).strip()
            if href:
                self.links.append(EmailLink(visible_text=visible, href=href,
                                            display_url_mismatch=_looks_like_url(visible) and _host(visible) != _host(href)))
        if tag.lower() in {"script", "style", "head", "iframe", "object", "svg"} and self._skip_depth:
            self._skip_depth -= 1
        if tag.lower() in {"p", "div", "li", "tr"}:
            self.text.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.text.append(data)
        for anchor in self._anchors:
            anchor["text"] = str(anchor["text"]) + data


def _host(value: str) -> str:
    value = value.strip().strip("<> ")
    if "@" in value and "://" not in value:
        return value.rsplit("@", 1)[-1].split(">", 1)[0].lower().rstrip(".")
    from urllib.parse import urlsplit
    parsed = urlsplit(value if "://" in value else "//" + value)
    return (parsed.hostname or "").lower().rstrip(".")


def _looks_like_url(value: str) -> bool:
    return bool(re.match(r"^(?:https?://|www\.)", value.strip(), re.I))


def _auth_results(header: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for method, result in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*([\w-]+)", header, re.I):
        results[method.lower()] = result.lower()
    return results


def parse_eml(raw: bytes) -> EmailData:
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError("Email file is larger than the 5 MB limit.")
    if not raw or b"\x00" in raw[:8192]:
        raise ValueError("This file does not look like a valid email (.eml).")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        raise ValueError("Could not parse this file as an email (.eml).") from exc
    if not message.items() or not any(message.get(name) for name in ("From", "Subject", "Date", "To")):
        raise ValueError("This file does not contain recognizable email headers.")

    from_header = str(message.get("From", ""))
    name, address = next(iter(getaddresses([from_header])), ("", ""))
    auth_header = str(message.get("Authentication-Results", ""))
    received = [str(v) for v in message.get_all("Received", [])]
    plain_parts: list[str] = []
    html_parts: list[str] = []
    html_text_parts: list[str] = []
    links: list[EmailLink] = []
    attachments: list[AttachmentInfo] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type().lower()
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename or part.get_content_disposition() == "attachment":
            attachments.append(AttachmentInfo(filename=filename or "(unnamed)",
                                               content_type=content_type, size=len(payload)))
            continue
        if content_type in {"text/plain", "text/html"}:
            try:
                text = part.get_content()
            except (LookupError, UnicodeError, AttributeError):
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            if not isinstance(text, str):
                continue
            if content_type == "text/plain":
                plain_parts.append(text)
                # Bare URLs in plain text count as links too.
                for url in re.findall(r"https?://[^\s<>\"']+", text, re.I):
                    links.append(EmailLink(visible_text=url, href=url))
            else:
                html_parts.append(text)
                extractor = _SafeHTMLExtractor()
                try:
                    extractor.feed(text)
                    links.extend(extractor.links)
                    readable = "\n".join(line.strip() for line in "".join(extractor.text).splitlines() if line.strip())
                    if readable:
                        html_text_parts.append(readable)
                except Exception:
                    pass
    return EmailData(
        from_header=from_header, from_name=name, from_address=address,
        reply_to=str(message.get("Reply-To", "")), return_path=str(message.get("Return-Path", "")),
        to=str(message.get("To", "")), subject=str(message.get("Subject", "")),
        date=str(message.get("Date", "")), received=received,
        authentication_results=auth_header, auth_results=_auth_results(auth_header),
        text_body="\n".join(plain_parts), html_body="\n".join(html_parts),
        html_text="\n".join(html_text_parts),
        links=links, attachments=attachments,
    )
