# Email Phishing Analyzer

A Streamlit app that inspects exported `.eml` files using deterministic offline rules and, when configured, the Gemini API. It does not open links or attachments and never renders email HTML.

## Setup

Requires Python 3.11 or newer.

```bash
cd phish-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Add your Gemini API key to `.env` as `GEMINI_API_KEY=...`. The default model is `gemini-3.8-flash`; set `GEMINI_MODEL` in `.env` to choose another compatible model. Keep `.env` private and do not commit it.

Run the app:

```bash
streamlit run app.py
```

If the API key is missing or Gemini is unavailable, the app displays an explanation and still shows the local rule results and a rule-only estimate. The key is never displayed by the app.

## Tests

```bash
pytest
```

The tests use the included sample `.eml` files and do not call Gemini.

## Included samples

`samples/` contains a fake bank reset, fake invoice with HTML attachment, Microsoft account lockout, newsletter, and receipt. Load a phishing sample first, review its findings, then try a legitimate sample to compare the results.

## Safety and limits

- Email HTML is parsed as data and is never inserted into the page as HTML.
- URLs are inspected as strings only; no URL is fetched or opened.
- Attachment metadata is read for analysis; attachments are not opened or executed.
- Email content is not logged by default. Gemini receives the parsed email context only when an API key is configured.
- Rule checks are indicators, not proof. A “safe” result cannot guarantee that a message is harmless.
