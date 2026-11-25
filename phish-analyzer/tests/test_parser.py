from pathlib import Path

import pytest

from analyzer.parser import MAX_EMAIL_BYTES, parse_eml

SAMPLES = Path(__file__).parents[1] / "samples"


def test_parser_extracts_headers_auth_links_and_html_text():
    email = parse_eml((SAMPLES / "fake_bank_reset.eml").read_bytes())
    assert email.from_address == "alerts@paypa1.com"
    assert email.reply_to == "alerts@paypa1.com"
    assert email.subject == "Verify your account within 24 hours"
    assert email.auth_results == {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
    assert email.links[0].display_url_mismatch
    assert "<html>" in email.html_body  # kept as data; the UI never renders it
    assert "Verify your account" in email.html_text
    assert email.links[0].visible_text == "https://www.paypal.com/signin"


def test_parser_extracts_attachment_metadata():
    email = parse_eml((SAMPLES / "fake_invoice.eml").read_bytes())
    assert [(a.filename, a.content_type) for a in email.attachments] == [("invoice.html", "text/html")]
    assert email.attachments[0].size > 0


def test_rejects_oversized_file():
    with pytest.raises(ValueError, match="5 MB"):
        parse_eml(b"From: a@b.example\n" + b"x" * MAX_EMAIL_BYTES)


@pytest.mark.parametrize("raw", [b"", b"not an email", b"\x00\x00junk"])
def test_rejects_invalid_email(raw):
    with pytest.raises(ValueError, match="valid email|recognizable"):
        parse_eml(raw)
