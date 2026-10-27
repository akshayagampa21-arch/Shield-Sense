# ShieldSense

A beginner-friendly Flask web app for link, email, and file safety analysis. It keeps the existing ShieldSense frontend as the base and adds real accounts, hashed passwords, profiles, scan history, file uploads, and Gemini-powered analysis.

## What's new in this upgrade
- **Email OTP verification** on signup — a 6-digit code is emailed before the account can log in.
- **OTP-based password reset** ("Forgot password?" on the login modal).
- **Account lockout**: 5 failed logins locks the account for 15 minutes, stopping brute-force guessing.
- **CSRF protection** on every state-changing request (signup, login, profile edits, scans, etc.).
- **Rate limiting** on auth and scan endpoints to stop abuse/spam.
- **Password strength meter** shown live while creating a password.
- **Scan history export to CSV** from the account panel, one click.
- **Dev-mode OTP fallback**: if no SMTP server is configured, the OTP is printed to the server console and returned in the API response so the whole flow is demoable without setting up email — see `.env.example`.

None of this changes the visual design — same dark/light theme, layout, and colors as before.

## Accuracy & bulk-scan upgrade
- **Grounded AI analysis**: Gemini now calls Google Search internally before scoring, so it checks a domain/brand's real reputation instead of guessing from the raw text — this is the main accuracy fix.
- **Strict JSON output**: the model is forced to return a validated schema (`score`, `danger`, `summary`, `reasons`, `recommendation`), so malformed responses no longer silently fall back to the weak local-only heuristic.
- **Smarter local heuristics**: typosquatting detection (Levenshtein distance against a popular-brand list), punycode/homograph detection, raw-IP hosts, suspicious TLDs, known link shorteners, and multi-category keyword scoring (a single common word like "verify" can no longer swing the score alone).
- **Blended scoring**: the final score combines the AI's contextual judgement with the deterministic structural checks, so a confident AI miss can still be caught by hard structural red flags.
- **Bulk URL scanning**: paste multiple links (one per line) into the URL box and it now scans all of them concurrently via `/api/scan/bulk`, up to 25 at a time — this fixes the earlier "pasting more than one link doesn't work" limitation (the old `<input type="url">` field and its backend regex only ever accepted a single URL).
- **10-minute result caching**: identical repeat scans return instantly instead of re-calling the model.

## 1. Install Python
Use Python 3.10+.

## 2. Open the project folder
```bash
cd ShieldSense
```

## 3. Create a virtual environment
Windows:
```bash
python -m venv .venv
.venv\Scripts\activate
```
macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 4. Install packages
```bash
pip install -r requirements.txt
```

## 5. Add Gemini API key
Create a `.env` file from `.env.example` and set `GEMINI_API_KEY`.
For a quick local run on Windows PowerShell:
```powershell
$env:GEMINI_API_KEY="YOUR_KEY"
$env:SECRET_KEY="a-long-random-secret"
```
The app reads environment variables directly, so no secret is committed to GitHub.

## 6. Run
```bash
python app.py
```
Open http://127.0.0.1:5000

## What works
- Validated signup/login with email and password rules.
- Passwords are stored as secure hashes, never as plaintext.
- Profile name/email editing.
- Profile picture upload/change.
- Profile dropdown with dashboard, new scan, past checks, settings, logout.
- URL, email/message, and file analysis.
- Gemini analysis with JSON risk score, danger level, summary, reasons, and recommendation.
- Scan history saved per account in SQLite.
- Existing dark/light theme, particle animation, sections, FAQ, cards, and imagery remain in the base frontend.
- Local heuristic fallback if Gemini is unavailable.

## GitHub
```bash
git init
git add .
git commit -m "Build ShieldSense full stack app"
git branch -M main
git remote add origin YOUR_GITHUB_REPO_URL
git push -u origin main
```
Never commit `.env`, the SQLite database, or uploaded files.

## Deploy
A Python web host that supports Flask can run this project. Set `GEMINI_API_KEY` and `SECRET_KEY` as hosting-provider environment variables and use:
```bash
gunicorn app:app
```
For production, use a managed database/object storage if you expect multiple users or significant traffic; SQLite and local uploads are intended for a simple hackathon deployment.
