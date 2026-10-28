# DarkShield AI — Hackathon Prototype

A Streamlit cybersecurity awareness demo with:
- Overview dashboard and sample threat reports
- Email exposure lookup using synthetic records or an authorized Have I Been Pwned API key
- Heuristic phishing/scam message detector
- Rule-based threat report analyzer
- Explainable risk scores and JSON incident report export

## Important limitations
- This is a hackathon prototype, not a certified security product.
- The app does **not** crawl the dark web.
- Sample incident and exposure records are synthetic and clearly labelled.
- Phishing detection uses simple rules and may produce false positives/negatives.
- Never enter passwords, OTPs, API secrets into public demos, or other people's private data without authorization.
- HIBP API lookups send the queried email address to the provider. Authenticated email lookup requires a valid API key and suitable access. Read the official API terms/docs before using it.

## Setup (Windows PowerShell)
1. Install Python 3.10+ from https://www.python.org/downloads/ and enable "Add Python to PATH".
2. Extract this folder.
3. Open PowerShell in the `darkshield_ai` folder.
4. Run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks activation, use Command Prompt instead:

```bat
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Streamlit opens the app in your browser, usually at http://localhost:8501.

## Demo walkthrough
1. Open **Overview** and explain that the displayed incident data is synthetic.
2. Go to **Email Exposure**, keep **Demo mode**, enter `demo.student@example.com`, and click **Check exposure**.
3. Try `someone@example.com` to show the no-match path; explain this is only a small demo dataset.
4. Go to **Phishing Detector**, paste this message, then click **Analyze message**:

   `URGENT: Your scholarship is approved! Verify your account immediately at http://bit.ly/demo-login and share your OTP to receive the cash reward.`

5. Go to **Threat Intelligence**, paste a sample public advisory or the text below:

   `A public advisory reports active exploitation of an unpatched VPN vulnerability. Administrators should patch immediately and review authentication logs for suspicious access.`

6. Go to **Incident Report** and download the JSON report.

## Optional Have I Been Pwned integration
Choose **Have I Been Pwned API** in the sidebar and provide your own valid API key. Never commit the key to GitHub. The email lookup is an authenticated API operation; use a permitted test address for the hackathon if you do not have suitable access. See:
- https://haveibeenpwned.com/API/V3
- https://haveibeenpwned.com/scalar/

For a deployment, store secrets in Streamlit secrets rather than in source code or a public repository. If you add `st.secrets["HIBP_API_KEY"]`, ensure the secret is configured on the deployment host.

## Suggested GitHub hygiene
- Commit `app.py`, `requirements.txt`, and `README.md`.
- Do not commit `.venv/`, `.streamlit/secrets.toml`, real API keys, personal data, or real breach dumps.
