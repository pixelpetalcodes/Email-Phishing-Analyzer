auth_results = authentication_statuses(email)
auth_columns = st.columns(3, gap="small")
for column, method in zip(auth_columns, ("spf", "dkim", "dmarc")):
    with column:
        status_card(method, auth_results[method])
st.caption("Only an explicit pass is labeled PASS; fail/softfail is FAIL. Missing or inconclusive results are UNKNOWN.")

section_heading("Signal report", "LOCAL RULE FINDINGS")
filter_col, severity_col, reset_col = st.columns([2, 1, .65])
with filter_col:
    search_text = st.text_input("Search findings", placeholder="Search title or evidence", label_visibility="collapsed")
with severity_col:
    severity_filter = st.selectbox("Severity", ["All severities", "High", "Medium", "Low"], label_visibility="collapsed")
with reset_col:
    if st.button("Reset", use_container_width=True):
        st.rerun()

visible_findings = [
    finding for finding in findings
    if (severity_filter == "All severities" or finding.severity == severity_filter.lower())
    and search_text.lower() in f"{finding.title} {finding.evidence}".lower()
]
st.caption(f"Showing {len(visible_findings)} of {len(findings)} findings")
if visible_findings:
    finding_cols = st.columns(2, gap="small")
    for index, finding in enumerate(visible_findings):
        with finding_cols[index % 2]:
            severity = escape(finding.severity.lower())
            st.markdown(
                f'<div class="finding finding-{severity}"><div class="finding-severity">{severity.upper()} SIGNAL</div>'
                f'<div class="finding-title">{escape(finding.title)}</div>'
                f'<div class="finding-evidence">{escape(finding.evidence)}</div></div>',
                unsafe_allow_html=True,
            )
elif findings:
    st.info("No findings match the current search and severity filters.")
else:
    st.success("No configured rule matched this email. That does not guarantee it is harmless.")

with st.expander("Inspect email details · plain text only"):
    header_col, body_col = st.columns(2)
    with header_col:
        st.markdown("**Message headers**")
        st.text(f"Reply-To: {email.reply_to or '(missing)'}")
        st.text(f"Return-Path: {email.return_path or '(missing)'}")
        st.text(f"Authentication-Results: {email.authentication_results or '(missing)'}")
        st.markdown("**Body text**")
        st.text((email.text_body or email.html_text or "(no readable body available)")[:12000])
    with body_col:
        st.markdown("**Links · destinations shown as text only**")
        if email.links:
            for link in email.links:
                st.text(f"{link.visible_text or '(no link text)'} → {link.href}")
        else:
            st.caption("No links found.")
        st.markdown("**Attachments · metadata only**")
        if email.attachments:
            for attachment in email.attachments:
                st.text(f"{attachment.filename} · {attachment.content_type} · {attachment.size} bytes")
        else:
            st.caption("No attachments found.")

section_heading("Ask the analyst", "CHAT ABOUT THIS EMAIL")
st.caption("Ask follow-up questions about the evidence above. Email HTML is never rendered and URLs are never opened.")
quick_cols = st.columns(3, gap="small")
quick_questions = (
    "Why was this email flagged?",
    "Which link looks unusual?",
    "What should I do next?",
)
for col, prompt in zip(quick_cols, quick_questions):
    with col:
        if st.button(prompt, use_container_width=True):
            st.session_state.pending_question = prompt

with st.expander("Export analysis report", expanded=False):
    st.write("Download a portable report for this email review.")
    safe_name = Path(source_name or "email").stem.replace(" ", "_")
    st.download_button(
        "Download PDF report",
        data=build_pdf_report(source_name or "email.eml", email, verdict, findings, auth_results),
        file_name=f"{safe_name}_analysis.pdf",
        mime="application/pdf",
        use_container_width=True,
    )
    json_report = {
        "source_file": source_name,
        "email": {"from": email.from_header, "to": email.to, "subject": email.subject, "date": email.date},
        "verdict": verdict.model_dump(),
        "authentication": auth_results,
        "findings": [finding.model_dump() for finding in findings],
    }
    st.download_button(
        "Download JSON report",
        data=json.dumps(json_report, indent=2, ensure_ascii=False),
        file_name=f"{safe_name}_analysis.json",
        mime="application/json",
        use_container_width=True,
    )

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.write(message["content"])

question = st.chat_input("Ask about a sender, link, or warning sign…")
if not question:
    question = st.session_state.pop("pending_question", None)
if question:
    st.session_state.messages.append({"role": "user", "content": question})
    try:
        if not st.session_state.gemini_ok:
            raise RuntimeError("Gemini is unavailable. Add GEMINI_API_KEY to .env to enable email chat.")
        answer = chat_about_email(email, findings, verdict, st.session_state.messages[:-1], question)
    except Exception as exc:
        answer = f"Gemini could not answer this question: {exc}\n\nThe offline analysis remains available above."
    st.session_state.messages.append({"role": "assistant", "content": answer})
    st.rerun()

st.markdown(
    '<div class="trust-strip"><span class="trust-tag">EMAIL HTML NEVER RENDERED</span>'
    '<span class="trust-tag">URLS NEVER FETCHED</span><span class="trust-tag">ATTACHMENTS NEVER OPENED</span>'
    '<span class="trust-tag">VERDICT IS A SIGNAL, NOT A GUARANTEE</span></div>',
    unsafe_allow_html=True,
)