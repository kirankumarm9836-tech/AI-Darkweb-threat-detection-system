import os
import re
import json
from datetime import datetime, timezone
from urllib.parse import quote

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

APP_NAME = "DarkShield AI"
HIBP_BASE = "https://haveibeenpwned.com/api/v3"

st.set_page_config(
    page_title="DarkShield AI | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.stApp { background: #0b1020; color: #e8eefc; }
[data-testid="stSidebar"] { background: #111a2e; }
.block-container { padding-top: 1.4rem; }
div[data-testid="stMetric"] {
    background: linear-gradient(135deg, #151f36, #10182a);
    border: 1px solid #263553; padding: 16px; border-radius: 14px;
}
div.stButton > button { border-radius: 9px; border: 1px solid #334766; }
.ds-card { background: #121c31; border: 1px solid #263553; border-radius: 14px; padding: 16px; }
.ds-muted { color: #a7b5d1; font-size: 0.9rem; }
</style>
""", unsafe_allow_html=True)

# All sample incidents and exposure records below are synthetic demo data.
SAMPLE_EXPOSURES = {
    "demo.student@example.com": [
        {
            "name": "CampusPortal Demo Incident",
            "date": "2026-08-14",
            "data_classes": ["Email addresses", "Password hashes"],
            "description": "Synthetic hackathon scenario: a fictional campus portal incident."
        },
        {
            "name": "StudentForum Demo Dataset",
            "date": "2025-11-02",
            "data_classes": ["Email addresses", "Usernames"],
            "description": "Synthetic demonstration record; not a real breach."
        },
    ],
    "demo.admin@example.com": [
        {
            "name": "SmallBiz Demo Incident",
            "date": "2026-09-03",
            "data_classes": ["Email addresses", "Phone numbers", "Password hashes"],
            "description": "Synthetic hackathon scenario: a fictional small-business incident."
        }
    ],
}

SAMPLE_THREATS = [
    {
        "id": "DS-1042", "title": "Student portal credentials exposed (simulation)",
        "category": "Credential Exposure", "severity": "High", "date": "2026-10-24",
        "source": "DarkShield synthetic dataset",
        "summary": "A fictional incident suggests email addresses and password hashes may have been exposed.",
        "status": "Needs review"
    },
    {
        "id": "DS-1041", "title": "Fake scholarship message campaign (simulation)",
        "category": "Phishing", "severity": "Critical", "date": "2026-10-23",
        "source": "DarkShield synthetic dataset",
        "summary": "A fictional message asks students to provide an OTP to claim a scholarship.",
        "status": "Mitigation advised"
    },
    {
        "id": "DS-1039", "title": "Small business customer data leak (simulation)",
        "category": "Data Leak", "severity": "Medium", "date": "2026-10-21",
        "source": "DarkShield synthetic dataset",
        "summary": "A fictional report describes possible exposure of contact details.",
        "status": "Monitoring"
    },
    {
        "id": "DS-1035", "title": "Ransomware advisory review (sample)",
        "category": "Ransomware", "severity": "High", "date": "2026-10-18",
        "source": "Sample security advisory",
        "summary": "Review backups, patch internet-facing services and verify endpoint protection.",
        "status": "Review controls"
    },
]

PHISHING_RULES = [
    ("credential_request", ["password", "login", "sign in", "verify your account", "credentials"], 20,
     "Requests for passwords or account verification"),
    ("otp_request", ["otp", "one time password", "verification code", "2fa code"], 30,
     "Requests for an OTP or verification code"),
    ("urgency", ["urgent", "immediately", "within 24 hours", "account will be blocked", "suspended today"], 15,
     "Urgent or threatening language"),
    ("money_prize", ["claim prize", "you won", "free gift", "cash reward", "scholarship approved"], 15,
     "Unexpected reward or money claim"),
    ("payment", ["upi pin", "bank details", "card number", "cvv", "payment required"], 25,
     "Requests sensitive financial information"),
    ("link_shortener", ["bit.ly/", "tinyurl.com/", "t.co/", "is.gd/"], 15,
     "Shortened link can hide the destination"),
    ("http_link", ["http://"], 10, "Link uses unencrypted HTTP"),
]

def score_phishing(text):
    lower = text.lower()
    findings = []
    score = 0
    urls = re.findall(r"(?:https?://|www\.)\S+", text, flags=re.I)
    for key, patterns, weight, label in PHISHING_RULES:
        if any(p in lower for p in patterns):
            score += weight
            findings.append({"indicator": label, "points": weight})
    # Look for visually suspicious URL/domain cues; this is heuristic only.
    if re.search(r"https?://[^/\s]*@[^/\s]*", text, flags=re.I):
        score += 20
        findings.append({"indicator": "URL contains an @ sign before the destination", "points": 20})
    if re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", text, flags=re.I):
        score += 15
        findings.append({"indicator": "URL uses a raw IP address", "points": 15})
    score = min(score, 100)
    if score >= 70:
        level = "Critical"
    elif score >= 45:
        level = "High"
    elif score >= 20:
        level = "Medium"
    else:
        level = "Low"
    if not findings:
        findings.append({"indicator": "No listed heuristic indicators detected", "points": 0})
    return score, level, findings, urls

def risk_score(exposure_count, sensitive_count, recency_points=0, source_confidence=0):
    # Transparent demo formula; weights are illustrative, not a validated standard.
    score = min(40, exposure_count * 20)
    score += min(30, sensitive_count * 10)
    score += min(20, recency_points)
    score += min(10, source_confidence)
    return min(100, score)

def get_hibp_breaches(email, api_key, timeout=12):
    headers = {
        "hibp-api-key": api_key.strip(),
        "user-agent": "DarkShieldAI-HackathonPrototype/1.0"
    }
    url = f"{HIBP_BASE}/breachedaccount/{quote(email.strip(), safe='')}?truncateResponse=false"
    response = requests.get(url, headers=headers, timeout=timeout)
    if response.status_code == 200:
        return {"status": "found", "breaches": response.json(), "message": "Results returned by Have I Been Pwned."}
    if response.status_code == 404:
        return {"status": "not_found", "breaches": [], "message": "No matching breach was returned by this API query."}
    if response.status_code == 401:
        return {"status": "error", "breaches": [], "message": "API key was rejected. Check the key and subscription."}
    if response.status_code == 403:
        return {"status": "error", "breaches": [], "message": "Access forbidden. Check API permissions and request headers."}
    if response.status_code == 429:
        return {"status": "error", "breaches": [], "message": "Rate limit reached. Wait before trying again."}
    return {"status": "error", "breaches": [], "message": f"API returned HTTP {response.status_code}."}

def breach_rows_to_df(breaches):
    rows = []
    for b in breaches:
        rows.append({
            "Breach": b.get("Title", b.get("Name", "Unknown")),
            "Domain": b.get("Domain", "Not provided"),
            "Breach date": b.get("BreachDate", "Unknown"),
            "Added date": b.get("AddedDate", "Unknown"),
            "Exposed data types": ", ".join(b.get("DataClasses", [])),
            "Verified": b.get("IsVerified", "Not specified"),
            "Source": "Have I Been Pwned API"
        })
    return pd.DataFrame(rows)

def build_report(title, body, recommendations, score=None, level=None):
    payload = {
        "product": APP_NAME,
        "report_title": title,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "risk_score": score,
        "risk_level": level,
        "findings": body,
        "recommended_actions": recommendations,
        "limitations": [
            "DarkShield AI is a hackathon prototype, not a certified security product.",
            "Rule-based phishing results can produce false positives and false negatives.",
            "Synthetic demo records are not evidence of real-world compromise."
        ]
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)

if "last_report" not in st.session_state:
    st.session_state.last_report = build_report(
        "DarkShield AI demo report",
        ["No analysis has been run in this session."],
        ["Run an analysis to generate tailored recommendations."]
    )
if "analysis_history" not in st.session_state:
    st.session_state.analysis_history = []

with st.sidebar:
    st.markdown("## 🛡️ DarkShield AI")
    st.caption("Threat intelligence • Exposure awareness • Response")
    page = st.radio(
        "Navigation",
        ["Overview", "Email Exposure", "Phishing Detector", "Threat Intelligence", "Incident Report"],
        label_visibility="collapsed"
    )
    st.divider()
    st.markdown("### Data mode")
    data_mode = st.radio(
        "Choose source",
        ["Demo mode (safe synthetic data)", "Have I Been Pwned API"],
        help="The API mode requires a valid API key and sends the email address to the provider."
    )
    st.caption("Prototype only. No direct dark-web crawling is performed.")
    st.divider()
    st.markdown("**Privacy note**")
    st.caption("Do not enter passwords, OTPs, private keys, or other secrets. Use synthetic addresses for the demo.")

st.markdown("# 🛡️ DarkShield AI")
st.markdown('<p class="ds-muted">AI-assisted cyber threat awareness and incident response — hackathon prototype</p>', unsafe_allow_html=True)

if page == "Overview":
    st.markdown("### Security overview")
    a, b, c, d = st.columns(4)
    a.metric("Demo incidents", len(SAMPLE_THREATS), "Synthetic/sample")
    b.metric("Critical alerts", sum(t["severity"] == "Critical" for t in SAMPLE_THREATS))
    c.metric("Threat categories", len(set(t["category"] for t in SAMPLE_THREATS)))
    d.metric("Analyses this session", len(st.session_state.analysis_history))
    left, right = st.columns([1.1, 1])
    with left:
        st.markdown("#### Threats by severity")
        df = pd.DataFrame(SAMPLE_THREATS)
        sev_order = ["Critical", "High", "Medium", "Low"]
        counts = df["severity"].value_counts().reindex(sev_order, fill_value=0).rename_axis("Severity").reset_index(name="Count")
        fig = px.bar(counts, x="Severity", y="Count", color="Severity",
                     category_orders={"Severity": sev_order},
                     color_discrete_map={"Critical": "#ff4d6d", "High": "#ff9f43", "Medium": "#ffd166", "Low": "#06d6a0"})
        fig.update_layout(paper_bgcolor="#0b1020", plot_bgcolor="#0b1020", font_color="#e8eefc",
                          margin=dict(l=10, r=10, t=20, b=10), showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    with right:
        st.markdown("#### Recent threat reports")
        for item in sorted(SAMPLE_THREATS, key=lambda x: x["date"], reverse=True)[:4]:
            st.markdown(f"""
            <div class="ds-card" style="margin-bottom:10px">
            <b>{item['title']}</b><br>
            <span class="ds-muted">{item['id']} • {item['date']} • {item['category']}</span><br>
            <b>Severity:</b> {item['severity']} &nbsp; <b>Status:</b> {item['status']}<br>
            <span class="ds-muted">{item['summary']}</span>
            </div>
            """, unsafe_allow_html=True)
    st.info("Demo dashboard data is synthetic/sample data. Replace it with vetted feeds before claiming live threat monitoring.")
    st.markdown("#### Recommended workflow")
    st.write("1. Check exposure → 2. Analyze suspicious content → 3. Review threat context → 4. Export response report.")

elif page == "Email Exposure":
    st.markdown("### Email exposure checker")
    st.write("Check whether an address appears in the selected source. Never enter a password or OTP.")
    email = st.text_input("Email address", placeholder="demo.student@example.com")
    valid_email = bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email.strip()))
    api_key = ""
    if data_mode == "Have I Been Pwned API":
        api_key = st.text_input("Have I Been Pwned API key", type="password",
                                help="Stored only in this running session if you type it here. Prefer Streamlit secrets for deployment.")
        st.caption("The authenticated API requires an API key and sends the queried address to the provider. See official API documentation.")
    if st.button("Check exposure", type="primary"):
        if not valid_email:
            st.error("Enter a valid-looking email address.")
        elif data_mode == "Demo mode (safe synthetic data)":
            normalized = email.strip().lower()
            hits = SAMPLE_EXPOSURES.get(normalized, [])
            if hits:
                sensitive = sum(any(x in " ".join(h["data_classes"]).lower() for x in ["password", "phone", "financial"]) for h in hits)
                score = risk_score(len(hits), sensitive, recency_points=15, source_confidence=0)
                level = "Critical" if score >= 80 else "High" if score >= 55 else "Medium" if score >= 30 else "Low"
                st.warning(f"Demo records matched: {len(hits)}. These are synthetic records, not a real-world breach finding.")
                st.metric("Illustrative risk score", f"{score}/100", level)
                df = pd.DataFrame([{
                    "Incident": h["name"], "Date": h["date"], "Exposed data": ", ".join(h["data_classes"]),
                    "Description": h["description"], "Source": "Synthetic demo dataset"
                } for h in hits])
                st.dataframe(df, use_container_width=True, hide_index=True)
                recs = [
                    "Change the affected account password and any reused passwords.",
                    "Enable multifactor authentication.",
                    "Review active sessions and sign out unknown devices.",
                    "Watch for targeted phishing messages."
                ]
                for r in recs: st.write(f"☑️ {r}")
                st.session_state.last_report = build_report(
                    "Email exposure check (synthetic demo)",
                    [f"{len(hits)} synthetic records matched for {normalized}.", "No real breach was verified."],
                    recs, score, level
                )
                st.session_state.analysis_history.append({"type": "Exposure check", "target": normalized, "risk": score, "level": level, "time": datetime.now().strftime("%H:%M:%S")})
            else:
                st.success("No matching record in this small synthetic demo dataset.")
                st.caption("This does not mean the address has never been exposed. Demo mode searches only the sample records.")
                st.session_state.last_report = build_report(
                    "Email exposure check (synthetic demo)",
                    [f"No matching record in the synthetic dataset for {normalized}.", "This is not a real-world clearance."],
                    ["Use unique passwords and enable multifactor authentication."], 0, "Unknown"
                )
        else:
            if not api_key.strip():
                st.error("Enter an API key, or switch to Demo mode.")
            else:
                try:
                    with st.spinner("Querying the authorized breach-intelligence API..."):
                        result = get_hibp_breaches(email, api_key)
                    if result["status"] == "found":
                        breaches = result["breaches"]
                        st.warning(f"{len(breaches)} breach record(s) returned by Have I Been Pwned.")
                        df = breach_rows_to_df(breaches)
                        st.dataframe(df, use_container_width=True, hide_index=True)
                        sensitive_count = sum(any(k in row["Exposed data types"].lower() for k in ["password", "financial", "payment", "phone"]) for _, row in df.iterrows())
                        score = risk_score(len(breaches), sensitive_count, recency_points=10, source_confidence=10)
                        level = "Critical" if score >= 80 else "High" if score >= 55 else "Medium" if score >= 30 else "Low"
                        st.metric("Illustrative risk score", f"{score}/100", level)
                        recs = [
                            "Change passwords for affected services and any accounts where the same password was reused.",
                            "Enable multifactor authentication, preferably a passkey or authenticator app.",
                            "Review account recovery options and active sessions.",
                            "Be alert for phishing that references the affected service."
                        ]
                        for r in recs: st.write(f"☑️ {r}")
                        st.markdown("Source: [Have I Been Pwned](https://haveibeenpwned.com/)")
                        st.session_state.last_report = build_report("Email exposure check (HIBP API)",
                            [f"{len(breaches)} breach record(s) returned for the queried address.", "Results reflect this provider's dataset and endpoint."],
                            recs, score, level)
                        st.session_state.analysis_history.append({"type": "HIBP exposure check", "target": email.strip(), "risk": score, "level": level, "time": datetime.now().strftime("%H:%M:%S")})
                    elif result["status"] == "not_found":
                        st.success(result["message"])
                        st.caption("A no-match result is not proof that an account has never been exposed; coverage and endpoint limitations apply.")
                        st.markdown("Source: [Have I Been Pwned](https://haveibeenpwned.com/)")
                        st.session_state.last_report = build_report("Email exposure check (HIBP API)",
                            [result["message"]], ["Use unique passwords and enable multifactor authentication."], 0, "No match returned")
                    else:
                        st.error(result["message"])
                except requests.Timeout:
                    st.error("The API request timed out. Try again or use Demo mode.")
                except requests.RequestException as exc:
                    st.error(f"Network error: {exc}")
                except (ValueError, json.JSONDecodeError):
                    st.error("The API response could not be parsed.")

elif page == "Phishing Detector":
    st.markdown("### Phishing and scam message detector")
    st.write("Paste suspicious message text. The analysis is heuristic and does not guarantee whether a message is safe.")
    sample = "URGENT: Your scholarship is approved! Verify your account immediately at http://bit.ly/demo-login and share your OTP to receive the cash reward."
    message = st.text_area("Message or email body", height=180, placeholder="Paste message text here...")
    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button("Load demo phishing message"):
            st.session_state["phish_demo"] = sample
            st.rerun()
    if "phish_demo" in st.session_state and not message:
        message = st.session_state["phish_demo"]
        st.text_area("Demo message loaded (copy it into the field above to analyze)", value=message, height=100, disabled=True)
    if st.button("Analyze message", type="primary"):
        if not message.strip():
            st.error("Paste a message first.")
        else:
            score, level, findings, urls = score_phishing(message)
            color = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}[level]
            st.metric("Heuristic phishing risk", f"{score}/100", f"{color} {level}")
            st.progress(score)
            st.markdown("#### Why this score?")
            st.dataframe(pd.DataFrame(findings), use_container_width=True, hide_index=True)
            if urls:
                st.markdown("#### URLs detected (not opened)")
                for u in urls:
                    st.code(u)
                st.warning("Do not open links just to test them. Verify the destination independently using trusted tools.")
            st.markdown("#### Recommended actions")
            recs = [
                "Do not share passwords, OTPs, PINs or recovery codes.",
                "Open the official app or type the official website address yourself instead of using message links.",
                "Verify unexpected scholarship, banking or payment requests through an independently known contact.",
                "Report the message to the relevant provider or your organization's security team."
            ]
            for r in recs: st.write(f"☑️ {r}")
            st.caption("The score is based on transparent keyword/URL heuristics, not a trained production-grade model.")
            st.session_state.last_report = build_report("Phishing message analysis",
                [f"Heuristic score: {score}/100 ({level})."] + [x["indicator"] for x in findings],
                recs, score, level)
            st.session_state.analysis_history.append({"type": "Phishing analysis", "target": "Pasted message", "risk": score, "level": level, "time": datetime.now().strftime("%H:%M:%S")})

elif page == "Threat Intelligence":
    st.markdown("### Threat intelligence analyzer")
    st.write("Review sample reports or paste a report from a trusted public security advisory. This module summarizes and classifies text using local rules.")
    df = pd.DataFrame(SAMPLE_THREATS)
    st.dataframe(df[["id", "title", "category", "severity", "date", "source", "status"]], use_container_width=True, hide_index=True)
    report_text = st.text_area("Paste a public advisory or incident summary", height=150,
        placeholder="Example: A public advisory describes ransomware exploiting an unpatched VPN appliance...")
    if st.button("Analyze threat report", type="primary"):
        if not report_text.strip():
            st.error("Paste report text to analyze.")
        else:
            lower = report_text.lower()
            categories = {
                "Credential Exposure": ["credential", "password", "login", "token", "stealer"],
                "Ransomware": ["ransomware", "encrypt", "extortion", "ransom"],
                "Phishing": ["phishing", "otp", "spoof", "fake login", "credential harvest"],
                "Vulnerability": ["cve-", "vulnerability", "unpatched", "patch", "exploit"],
                "Data Leak": ["leak", "exposed", "database", "records", "exfiltration"],
                "Malware": ["malware", "trojan", "payload", "backdoor"]
            }
            matched = [name for name, terms in categories.items() if any(term in lower for term in terms)]
            critical_terms = ["active exploitation", "ransomware", "admin credentials", "mass exfiltration", "remote code execution"]
            high_terms = ["exposed passwords", "unpatched", "credential theft", "data exfiltration", "zero-day"]
            severity = "Critical" if any(t in lower for t in critical_terms) else "High" if any(t in lower for t in high_terms) else "Medium" if matched else "Low"
            score = {"Critical": 90, "High": 70, "Medium": 45, "Low": 20}[severity]
            st.metric("Rule-based severity", severity, f"{score}/100 illustrative score")
            st.write("**Likely categories:** " + (", ".join(matched) if matched else "No category confidently matched"))
            st.write("**Summary:** " + " ".join(report_text.split())[:500] + ("..." if len(report_text) > 500 else ""))
            recs = [
                "Confirm the report's publisher, date and affected product before acting.",
                "Prioritize patches and mitigations recommended by the original advisory.",
                "Review authentication logs and revoke suspicious sessions if credential exposure is suspected.",
                "Document the source, decision, owner and follow-up deadline."
            ]
            st.markdown("#### Suggested response")
            for r in recs: st.write(f"☑️ {r}")
            st.caption("Classification is based on keywords; validate conclusions against the original trusted advisory.")
            st.session_state.last_report = build_report("Threat intelligence report analysis",
                [f"Likely categories: {', '.join(matched) if matched else 'No category confidently matched'}.",
                 f"Rule-based severity: {severity}.", "Summary generated by truncating the submitted text; no external threat feed was queried."],
                recs, score, severity)
            st.session_state.analysis_history.append({"type": "Threat report", "target": "Pasted report", "risk": score, "level": severity, "time": datetime.now().strftime("%H:%M:%S")})

elif page == "Incident Report":
    st.markdown("### Incident report")
    st.write("Download the latest analysis report as JSON. Reports are generated locally in this app session.")
    st.download_button(
        "⬇️ Download latest report (JSON)",
        data=st.session_state.last_report,
        file_name="darkshield_incident_report.json",
        mime="application/json",
        type="primary"
    )
    st.markdown("#### Latest report preview")
    try:
        st.json(json.loads(st.session_state.last_report))
    except json.JSONDecodeError:
        st.code(st.session_state.last_report)
    st.markdown("#### Analysis history (current session)")
    if st.session_state.analysis_history:
        st.dataframe(pd.DataFrame(st.session_state.analysis_history), use_container_width=True, hide_index=True)
    else:
        st.info("No analyses yet. Run an exposure check or analyze a message/report first.")
    st.caption("History is held in Streamlit session state and is not a durable database.")

st.divider()
st.caption("DarkShield AI • Hackathon prototype • Use only authorized sources and synthetic data for demonstrations.")
