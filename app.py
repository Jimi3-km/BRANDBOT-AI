# app.py
import os
import sqlite3
import hashlib
import hmac
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, redirect, url_for, session, flash
import requests
import json
from functools import wraps
import bcrypt

# =============================================================================
# INITIALIZATION
# =============================================================================
app = Flask(__name__)

# Configuration
app.secret_key = os.environ.get('SECRET_KEY', 'dev-fallback-key')  # CHANGE IN PRODUCTION
DB_PATH = os.path.join(os.path.dirname(__file__), 'instance/brandbot.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# API Keys (Set these in Render dashboard)
HUGGINGFACE_API_KEY = os.environ.get('HUGGINGFACE_API_KEY')

# =============================================================================
# DATABASE SETUP
# =============================================================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            plan TEXT DEFAULT 'free',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS content_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content_type TEXT,
            content TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

# =============================================================================
# CORE FUNCTIONALITY
# =============================================================================
def generate_ai_content(prompt):
    headers = {
        "Authorization": f"Bearer {HUGGINGFACE_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {"inputs": prompt}
    
    try:
        response = requests.post(
            "https://api-inference.huggingface.co/models/gpt2",
            headers=headers,
            json=payload
        )
        return response.json()[0]['generated_text']
    except:
        return "AI generation failed. Please try again."

# =============================================================================
# AUTHENTICATION
# =============================================================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# =============================================================================
# ROUTES
# =============================================================================
@app.route('/')
@login_required
def index():
    return render_template_string('''
        <h1>BrandBot Studio</h1>
        <form action="/generate" method="POST">
            <textarea name="prompt" required></textarea>
            <button type="submit">Generate</button>
        </form>
        <a href="/logout">Logout</a>
    ''')

@app.route('/generate', methods=['POST'])
@login_required
def generate():
    prompt = request.form['prompt']
    content = generate_ai_content(prompt)
    
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO content_history (user_id, content_type, content) VALUES (?, ?, ?)",
        (session['user_id'], 'text', content)
    )
    conn.commit()
    conn.close()
    
    return render_template_string(f'''
        <h2>Generated Content</h2>
        <p>{content}</p>
        <a href="/">Back</a>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect(DB_PATH)
        user = conn.execute(
            "SELECT id, password_hash FROM users WHERE email = ?",
            (email,)
        ).fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode(), user[1].encode()):
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        
        flash('Invalid credentials')
    
    return render_template_string('''
        <h1>Login</h1>
        <form method="POST">
            <input type="email" name="email" required>
            <input type="password" name="password" required>
            <button type="submit">Login</button>
        </form>
        <a href="/register">Register</a>
    ''')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode())
            )
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered')
    
    return render_template_string('''
        <h1>Register</h1>
        <form method="POST">
            <input type="email" name="email" required>
            <input type="password" name="password" required>
            <button type="submit">Register</button>
        </form>
    ''')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# =============================================================================
# STARTUP
# =============================================================================
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
