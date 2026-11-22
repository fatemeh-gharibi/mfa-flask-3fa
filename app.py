import base64
import datetime
import io
import os
import re
import secrets
import smtplib
import sqlite3
import time
from datetime import timezone
from email.message import EmailMessage
 
import jwt
import pyotp
import qrcode
from flask import Flask, abort, redirect, render_template, request, session, url_for
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
 
from dotenv import load_dotenv
load_dotenv()
 
app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=os.environ.get("FLASK_COOKIE_SECURE", "false").lower() == "true", PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=10))
 
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")
 
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
JWT_SECRET = os.environ.get("JWT_SECRET_KEY") or app.secret_key
MAX_OTP_ATTEMPTS = int(os.environ.get("MAX_OTP_ATTEMPTS", "3"))
OTP_EXPIRY_SECONDS = int(os.environ.get("OTP_EXPIRY_SECONDS", "300"))
OTP_LENGTH = 6
APP_NAME = "3FA Demo"
 
 

 
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL") 
    return conn
 
 
def init_db():
    conn = get_db()
    c = conn.cursor()
 
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username     TEXT PRIMARY KEY,
            email        TEXT,
            password     TEXT NOT NULL,
            secret       TEXT NOT NULL,
            otp_code     TEXT,
            otp_attempts INTEGER NOT NULL DEFAULT 0,
            otp_sent_at  REAL    NOT NULL DEFAULT 0,
            totp_verified INTEGER NOT NULL DEFAULT 0
        )
    """)
 
    existing_columns = {
        row["name"] for row in c.execute("PRAGMA table_info(users)").fetchall()
    }
 
    migrations = {
        "email":         "ALTER TABLE users ADD COLUMN email TEXT",
        "otp_code":      "ALTER TABLE users ADD COLUMN otp_code TEXT",
        "otp_attempts":  "ALTER TABLE users ADD COLUMN otp_attempts INTEGER NOT NULL DEFAULT 0",
        "otp_sent_at":   "ALTER TABLE users ADD COLUMN otp_sent_at REAL NOT NULL DEFAULT 0",
        "totp_verified": "ALTER TABLE users ADD COLUMN totp_verified INTEGER NOT NULL DEFAULT 0",
    }
 
    for col, sql in migrations.items():
        if col not in existing_columns:
            c.execute(sql)
 
    c.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email
        ON users(email) WHERE email IS NOT NULL
    """)
 
    c.execute("""
        CREATE TABLE IF NOT EXISTS student_profiles (
            username TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            program TEXT NOT NULL,
            year INTEGER NOT NULL,
            bio TEXT NOT NULL,
            private_note TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def seed_users():
    conn = get_db()
    c = conn.cursor()
 
    users_env = [
        ("admin", "SEED_ADMIN_EMAIL", "SEED_ADMIN_PASSWORD"),
        ("ali",   "SEED_ALI_EMAIL",   "SEED_ALI_PASSWORD"),
        ("sara",  "SEED_SARA_EMAIL",  "SEED_SARA_PASSWORD"),
    ]
 
    for username, email_env, pass_env in users_env:
        email    = os.environ.get(email_env)
        password = os.environ.get(pass_env)
        if not email or not password:
            continue
        c.execute("""
            INSERT OR IGNORE INTO users
            (username, email, password, secret, otp_attempts, otp_sent_at, totp_verified)
            VALUES (?, ?, ?, ?, 0, 0, 0)
        """, (username, email, generate_password_hash(password), pyotp.random_base32()))
 
    conn.commit()
    conn.close()
 
 

 
def normalize_email(email):
    return email.strip().lower()
 
def is_valid_email(email):
    return bool(EMAIL_PATTERN.match(email))
 
def mask_email(email):
    name, domain = email.split("@", 1)
    if len(name) <= 2:
        masked_name = name[0] + "*"
    else:
        masked_name = name[0] + "*" * (len(name) - 2) + name[-1]
    return f"{masked_name}@{domain}"
 
def password_is_strong(password):
    return (
        len(password) >= 8
        and any(c.isupper() for c in password)
        and any(c.islower() for c in password)
        and any(c.isdigit() for c in password)
        and any(not c.isalnum() for c in password)
    )
 
def generate_otp():
    return str(secrets.randbelow(10 ** OTP_LENGTH)).zfill(OTP_LENGTH)
 
def make_qr_base64(username, secret):
    """Generate a QR code image as base64 string for Google Authenticator."""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=APP_NAME)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()
 
def send_otp_email(recipient_email, otp):
    smtp_host     = os.environ.get("SMTP_HOST")
    smtp_port     = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user     = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    smtp_from     = os.environ.get("SMTP_FROM") or smtp_user
    use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}
    use_ssl = os.environ.get("SMTP_USE_SSL", "false").lower() in {"1", "true", "yes", "on"}
 
    if not smtp_host or not smtp_from:
        raise RuntimeError("Email is not configured.")
 
    message = EmailMessage()
    message["Subject"] = "Your MFA OTP code"
    message["From"]    = smtp_from
    message["To"]      = recipient_email
    message.set_content(
        f"Your OTP code is: {otp}\n"
        f"This code expires in {OTP_EXPIRY_SECONDS // 60} minutes.\n\n"
        "If you did not request this code, please ignore this email."
    )
 
    smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    with smtp_class(smtp_host, smtp_port, timeout=10) as server:
        if use_tls and not use_ssl:
            server.starttls()
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.send_message(message)
 
 

 
def store_otp(username, otp):
    conn = get_db()
    conn.execute(
        "UPDATE users SET otp_code=?, otp_attempts=0, otp_sent_at=? WHERE username=?",
        (otp, time.time(), username),
    )
    conn.commit()
    conn.close()

def get_active_otp(username):
    """Return the user's row if they already have a non-expired OTP with attempts left, else None."""
    conn = get_db()
    user = conn.execute(
        "SELECT otp_code, otp_sent_at, otp_attempts FROM users WHERE username=?",
        (username,)
    ).fetchone()
    conn.close()

    if not user or not user["otp_code"]:
        return None

    if time.time() - user["otp_sent_at"] > OTP_EXPIRY_SECONDS:
        return None

    if user["otp_attempts"] >= MAX_OTP_ATTEMPTS:
        return None

    return user

 
def increment_otp_attempts(username):
    conn = get_db()
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("UPDATE users SET otp_attempts=otp_attempts+1 WHERE username=?", (username,))
    row = conn.execute("SELECT otp_attempts FROM users WHERE username=?", (username,)).fetchone()
    attempts = row["otp_attempts"]
    conn.commit()
    conn.close()
    return attempts
 
def clear_otp(username):
    conn = get_db()
    conn.execute("UPDATE users SET otp_code=NULL, otp_attempts=0 WHERE username=?", (username,))
    conn.commit()
    conn.close()
 
def clear_pending_login():
    session.pop("pending_otp_user",  None)
    session.pop("pending_otp_email", None)
    session.pop("pending_totp_user", None)
 
 

 
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email    = normalize_email(request.form["email"])
        password = request.form["password"]
 
        if not username:
            return render_template("error.html", message="Username is required.")
        if not is_valid_email(email):
            return render_template("error.html", message="Enter a valid email.")
        if not password_is_strong(password):
            return render_template("error.html", message="Password does not meet security requirements.")
 
        secret = pyotp.random_base32()
 
        conn = get_db()
        try:
            conn.execute("""
                INSERT INTO users (username, email, password, secret, otp_attempts, otp_sent_at, totp_verified)
                VALUES (?, ?, ?, ?, 0, 0, 0)
            """, (username, email, generate_password_hash(password), secret))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("error.html", message="Username or email already exists.")
        conn.close()
 
        
        qr_base64 = make_qr_base64(username, secret)
        return render_template("register_success.html", qr_base64=qr_base64, username=username)
 
    return render_template("register.html")
 
 
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
 
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT username, email, password, secret FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
 
        dummy_hash = generate_password_hash("dummy")
        password_ok = check_password_hash(user["password"] if user else dummy_hash, password)
 
        if not user or not password_ok:
            return render_template("error.html", message="Invalid username or password.")
 
        if not user["email"]:
            return render_template("error.html", message="No email registered for this account.")
 
        active = get_active_otp(user["username"])
 
        if not active:
            otp = generate_otp()
            try:
                send_otp_email(user["email"], otp)
            except Exception as exc:
                return render_template("error.html", message=f"Could not send OTP email: {exc}")
 
            store_otp(user["username"], otp)
        session.clear()
        session["pending_otp_user"]  = user["username"]
        session["pending_otp_email"] = mask_email(user["email"])
 
        return redirect("/otp")
 
    return render_template("login.html")
 
 
@app.route("/otp", methods=["GET", "POST"])
def otp():
    username = session.get("pending_otp_user")
    if not username:
        return redirect("/")
 
    conn = get_db()
    user = conn.execute(
        "SELECT username, otp_code, otp_attempts, otp_sent_at FROM users WHERE username=?",
        (username,)
    ).fetchone()
    conn.close()
 
    if not user:
        clear_pending_login()
        return redirect("/")
 
    if request.method == "POST":
        user_otp = request.form["otp"].strip()
 
        if time.time() - user["otp_sent_at"] > OTP_EXPIRY_SECONDS:
            clear_otp(username)
            clear_pending_login()
            return render_template("otp_error.html", message="OTP expired. Please login again.")
 
        if user["otp_attempts"] >= MAX_OTP_ATTEMPTS:
            clear_otp(username)
            clear_pending_login()
            return render_template("otp_error.html", message="Too many attempts. Please login again.", max_attempts=MAX_OTP_ATTEMPTS)
 
        stored_otp = user["otp_code"] or ""
        otp_correct = secrets.compare_digest(stored_otp, user_otp)
 
        if otp_correct:
            clear_otp(username)
            
            session.pop("pending_otp_user",  None)
            session.pop("pending_otp_email", None)
            session["pending_totp_user"] = username
            return redirect("/totp")
 
        time.sleep(2)
        attempts = increment_otp_attempts(username)
 
        if attempts >= MAX_OTP_ATTEMPTS:
            clear_otp(username)
            clear_pending_login()
            return render_template("otp_error.html", message="Too many attempts. Please login again.", attempts=attempts, max_attempts=MAX_OTP_ATTEMPTS)
 
        return render_template("otp_error.html", message="Invalid OTP. Please try again.", attempts=attempts, max_attempts=MAX_OTP_ATTEMPTS)
 
    return render_template("otp.html", email=session.get("pending_otp_email"))
 
 
@app.route("/totp", methods=["GET", "POST"])
def totp():
    username = session.get("pending_totp_user")
    if not username:
        return redirect("/")
 
    conn = get_db()
    user = conn.execute("SELECT username, secret FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
 
    if not user:
        clear_pending_login()
        return redirect("/")
 
    if request.method == "POST":
        code = request.form["totp_code"].strip()
        totp_obj = pyotp.TOTP(user["secret"])
 
        if totp_obj.verify(code, valid_window=1):
            session.clear()
            session.permanent = True
            session["user"] = username
            session["three_fa_verified"] = True
 
            token = jwt.encode(
                {
                    "user": username,
                    "exp": datetime.datetime.now(timezone.utc) + datetime.timedelta(minutes=10),
                },
                JWT_SECRET,
                algorithm="HS256",
            )
            return redirect(url_for("dashboard"))
 
        time.sleep(2)
        return render_template("otp_error.html", message="Invalid Google Authenticator code. Please try again.")
 
    return render_template("totp.html")
 
 
# Fictional demo directory: not actual university/student records.
DEMO_STUDENTS = [
    ("demo_marco", "Marco Rossi", "Computer Science", 2, "Interested in web development and robotics.", "Fictional private academic note for Marco."),
    ("demo_giulia", "Giulia Bianchi", "Data Science", 1, "Learning machine learning and statistics.", "Fictional private academic note for Giulia."),
    ("demo_amina", "Amina Conti", "Cybersecurity", 3, "Enjoys secure software engineering.", "Fictional private academic note for Amina."),
    ("demo_luca", "Luca Marino", "Software Engineering", 2, "Building open-source applications.", "Fictional private academic note for Luca."),
]


def seed_demo_profiles():
    conn = get_db()
    conn.executemany("""
        INSERT OR IGNORE INTO student_profiles
        (username, display_name, program, year, bio, private_note)
        VALUES (?, ?, ?, ?, ?, ?)
    """, DEMO_STUDENTS)
    conn.commit()
    conn.close()


def require_3fa(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not (session.get("user") and session.get("three_fa_verified")):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.route("/dashboard")
@require_3fa
def dashboard():
    return render_template("dashboard.html", username=session["user"])


@app.route("/directory")
@require_3fa
def directory():
    query = request.args.get("q", "").strip()[:80]
    conn = get_db()
    if query:
        rows = conn.execute("""
            SELECT username, display_name, program, year, bio
            FROM student_profiles
            WHERE display_name LIKE ? OR program LIKE ?
            ORDER BY display_name LIMIT 30
        """, (f"%{query}%", f"%{query}%")).fetchall()
    else:
        rows = conn.execute("""
            SELECT username, display_name, program, year, bio
            FROM student_profiles ORDER BY display_name LIMIT 30
        """).fetchall()
    conn.close()
    return render_template("directory.html", students=rows, query=query)


@app.route("/student/<username>")
@require_3fa
def student_profile(username):
    conn = get_db()
    profile = conn.execute("""
        SELECT username, display_name, program, year, bio
        FROM student_profiles WHERE username=?
    """, (username,)).fetchone()
    conn.close()
    if profile is None:
        abort(404)
    return render_template("student.html", student=profile)


@app.route("/my-record")
@require_3fa
def my_record():
    # This private record is scoped to the currently authenticated user.
    conn = get_db()
    record = conn.execute("""
        SELECT display_name, program, year, private_note
        FROM student_profiles WHERE username=?
    """, (session["user"],)).fetchone()
    conn.close()
    return render_template("my_record.html", record=record)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
 
 
if __name__ == "__main__":
    init_db()
    seed_users()
    seed_demo_profiles()
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() in {"1", "true", "yes"}
    app.run(host="0.0.0.0", port=5001, debug=debug_mode)
    # app.run(host="0.0.0.0", port=5001 , debug=True)