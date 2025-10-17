# app.py
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import random
import time

# SendGrid imports
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from werkzeug.security import generate_password_hash, check_password_hash

# Flask app setup
app = Flask(__name__, instance_relative_config=True)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")  # better to set SECRET_KEY in env

# Database setup
DB_DIR = "instance"
DB_PATH = os.path.join(DB_DIR, "database.db")
os.makedirs(DB_DIR, exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Read SendGrid API key and sender email from .env
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
MAIL_FROM = os.environ.get("MAIL_FROM", "uvsingh0026@gmail.com")

RESEND_COOLDOWN = 60  # seconds

def send_otp(email, otp):
    try:
        message = Mail(
            from_email=MAIL_FROM,
            to_emails=email,
            subject="Your OTP Verification Code",
            plain_text_content=f"Your OTP is: {otp}\nOTP is valid for 5 minutes\nIf you did not request this, ignore this email."
        )
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        return 200 <= response.status_code < 300
    except Exception as e:
        print("SendGrid error:", e)
        return False

OTP_VALIDITY = 300  # 5 minutes

def generate_otp(email):
    now = int(time.time())
    existing_otp = session.get('otp')
    otp_sent_at = session.get('otp_sent_at', 0)
    
    if not existing_otp or (now - otp_sent_at) > OTP_VALIDITY:
        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        session['email_to_verify'] = email
        session['otp_sent_at'] = now
    return session['otp']

def can_resend():
    sent = session.get('otp_sent_at')
    if not sent:
        return True
    return (int(time.time()) - sent) >= RESEND_COOLDOWN

# ROUTES
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('txt', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('pswd', '').strip()

    if not username or not email or not password:
        flash("All fields required!", "error")
        return redirect(url_for('home'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email=?", (email,))
    if c.fetchone():
        conn.close()
        flash("Email already exists!", "error")
        return redirect(url_for('home'))

    hashed = generate_password_hash(password)
    c.execute("INSERT INTO users (username,email,password) VALUES (?,?,?)", (username, email, hashed))
    conn.commit()
    conn.close()

    otp = generate_otp(email)
    sent = send_otp(email, otp)
    session['user'] = username
    session['verified'] = False

    if sent:
        flash("Account created! OTP sent to your email.", "success")
        return redirect(url_for('verify_otp'))
    else:
        flash("Failed to send OTP. Check console or mail settings.", "error")
        print(f"[DEBUG] OTP for {email}: {otp}")
        return redirect(url_for('home'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('pswd', '').strip()

    if not email or not password:
        flash("Email and password required!", "error")
        return redirect(url_for('home'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username,password,verified FROM users WHERE email=?", (email,))
    row = c.fetchone()
    conn.close()

    if not row or not check_password_hash(row["password"], password):
        flash("Invalid credentials!", "error")
        return redirect(url_for('home'))

    session['user'] = row["username"]
    session['email_to_verify'] = email

    if row["verified"] == 1:
        session['verified'] = True
        flash("Logged in successfully!", "success")
        return redirect(url_for('welcome'))
    else:
        otp = generate_otp(email)
        sent = send_otp(email, otp)
        session['verified'] = False
        if sent:
            flash("OTP sent! Verify your email.", "success")
            return redirect(url_for('verify_otp'))
        else:
            flash("Failed to send OTP. Check console or mail settings.", "error")
            print(f"[DEBUG] OTP for {email}: {otp}")
            return redirect(url_for('home'))

@app.route('/verify-otp', methods=['GET','POST'])
def verify_otp():
    if 'user' not in session or 'email_to_verify' not in session:
        flash("Login or signup first.", "error")
        return redirect(url_for('home'))

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        if otp == session.get('otp'):
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("UPDATE users SET verified=1 WHERE email=?", (session['email_to_verify'],))
            conn.commit()
            conn.close()
            session['verified'] = True
            session.pop('otp', None)
            session.pop('otp_sent_at', None)
            flash("Verified! Welcome!", "success")
            return redirect(url_for('welcome'))
        else:
            flash("Wrong OTP!", "error")

    return render_template('verify.html', otp_sent_at=session.get('otp_sent_at'))

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    if 'email_to_verify' not in session:
        flash("Login first.", "error")
        return redirect(url_for('home'))

    if not can_resend():
        remaining = RESEND_COOLDOWN - (int(time.time()) - session.get('otp_sent_at',0))
        flash(f"Wait {remaining}s before resending", "error")
        return redirect(url_for('verify_otp'))

    otp = generate_otp(session['email_to_verify'])
    sent = send_otp(session['email_to_verify'], otp)
    if sent:
        flash("OTP resent!", "success")
    else:
        flash("Failed to resend OTP. Check console or mail settings.", "error")
        print(f"[DEBUG] OTP for {session['email_to_verify']}: {otp}")
    return redirect(url_for('verify_otp'))

@app.route('/welcome')
def welcome():
    if 'user' in session and session.get('verified'):
        return render_template('welcome.html', username=session['user'])
    flash("Login and verify first!", "error")
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for('home'))

# Render-ready app run
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Render sets PORT automatically
    app.run(host="0.0.0.0", port=port)
