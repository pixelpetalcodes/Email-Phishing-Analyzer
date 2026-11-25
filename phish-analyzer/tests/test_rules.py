from pathlib import Path

import pytest

from analyzer.parser import parse_eml
from analyzer.rules import check_rules

SAMPLES = Path(__file__).parents[1] / "samples"


def findings_for(sample):
    return check_rules(parse_eml((SAMPLES / sample).read_bytes()))


@pytest.mark.parametrize("sample,expected", [
    ("fake_bank_reset.eml", {"display-name-domain", "auth-spf", "auth-dkim", "auth-dmarc", "link-text-mismatch", "lookalike-domain", "urgency-language"}),
    ("fake_invoice.eml", {"risky-attachment"}),
    ("microsoft_lockout.eml", {"reply-to-mismatch", "auth-dkim", "auth-dmarc", "urgency-language"}),
])
def test_phishing_samples_trigger_expected_rules(sample, expected):
    assert expected <= {f.id for f in findings_for(sample)}


@pytest.mark.parametrize("sample", ["legitimate_newsletter.eml", "legitimate_receipt.eml"])
def test_legitimate_samples_avoid_high_severity_findings(sample):
    assert not [f for f in findings_for(sample) if f.severity == "high"]


def test_missing_authentication_results_are_reported():
    from analyzer.models import EmailData
    ids = {f.id for f in check_rules(EmailData(from_address="a@example.org"))}
    assert {"auth-spf", "auth-dkim", "auth-dmarc"} <= ids


def test_raw_ip_shortener_and_many_subdomains_are_reported():
    from analyzer.models import EmailData, EmailLink
    email = EmailData(from_address="sender@example.org", auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
                      links=[EmailLink(visible_text="click", href="http://192.0.2.1/login"),
                             EmailLink(visible_text="short", href="https://bit.ly/x"),
                             EmailLink(visible_text="deep", href="https://a.b.c.d.example.org/")])
    ids = {f.id for f in check_rules(email)}
    assert {"raw-ip-link", "shortener-link", "excessive-subdomains"} <= ids

