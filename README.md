# 3FA Secure University Portal

A Flask web app that protects a small university portal with **three-factor authentication**:

1. **Password** – checked against a salted Werkzeug hash
2. **Email one-time code** – 6 digits, expires after 5 minutes, max 3 attempts
3. **Google Authenticator (TOTP)** – 30-second codes from a secret shared via QR code at sign-up

After login, private pages (dashboard, student directory, profiles, personal record) are protected by a `@require_3fa` decorator. All student data is fictional demo data.

## Tech stack

Python · Flask · SQLite · Jinja2 · PyOTP · qrcode · Werkzeug · smtplib · Docker

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # then edit .env with your values
python app.py
```

Open http://localhost:5001

## Run with Docker

```bash
docker build -t mfa-portal .
docker run --env-file .env -p 5001:5001 mfa-portal
```

## How to use

1. Go to `/register`, create an account and scan the QR code with Google Authenticator.
2. Log in with username and password.
3. Enter the 6-digit code sent to your email.
4. Enter the current code from Google Authenticator.
5. You are redirected to the dashboard.

## Security features

- Salted password hashing and strong-password rules
- Same error message for wrong username or password (no user enumeration)
- OTP generated with `secrets`, constant-time comparison, expiry and attempt limit
- HttpOnly, SameSite session cookies with a 10-minute lifetime
- Parameterized SQL queries
- Secrets loaded from environment variables (`.env`, not committed)

## Limitations / future work

- Store a hash of the email OTP instead of plain text
- Rate-limit password attempts
- Add CSRF protection to forms
- Backup recovery codes if the phone is lost
- Automated tests for the full login flow
