from types import SimpleNamespace
from unittest.mock import Mock

from analyzer import gemini_client
from analyzer.models import EmailData, Finding, Verdict


def test_verdict_call_uses_mocked_gemini_and_validates_schema(monkeypatch):
    response = SimpleNamespace(text='{"verdict":"phishing","risk_score":94,"summary":"Several strong warning signs.","reasons":["Lookalike domain"],"recommended_actions":["Do not open the link."]}')
    generate = Mock(return_value=response)
    close = Mock()
    client = SimpleNamespace(models=SimpleNamespace(generate_content=generate), close=close)
    monkeypatch.setattr(gemini_client, "_client", lambda: client)
    monkeypatch.setenv("GEMINI_MODEL", "test-flash")

    result = gemini_client.get_verdict(EmailData(subject="test"), [Finding(id="x", title="Lookalike", severity="high", evidence="paypa1.com")])

    assert result.verdict == "phishing"
    assert result.risk_score == 94
    assert generate.call_args.kwargs["model"] == "test-flash"
    close.assert_called_once_with()


def test_follow_up_chat_uses_mocked_gemini(monkeypatch):
    response = SimpleNamespace(text="The sender domain differs from the displayed brand.")
    generate = Mock(return_value=response)
    client = SimpleNamespace(models=SimpleNamespace(generate_content=generate))
    monkeypatch.setattr(gemini_client, "_client", lambda: client)
    email = EmailData(from_address="a@paypa1.com", text_body="Please verify your account.")
    verdict = Verdict(verdict="phishing", risk_score=90, summary="Suspicious signs.")

    answer = gemini_client.chat_about_email(email, [], verdict, [{"role": "user", "content": "Why?"}], "What is suspicious?")

    assert "sender domain" in answer
    assert generate.call_args.kwargs["contents"][-1].parts[0].text == "What is suspicious?"
    assert "untrusted data" in generate.call_args.kwargs["config"].system_instruction.lower()


def test_missing_api_key_has_clear_error(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    try:
        gemini_client._client()
    except RuntimeError as exc:
        assert "GEMINI_API_KEY" in str(exc)
    else:
        raise AssertionError("Expected a clear missing-key error")
