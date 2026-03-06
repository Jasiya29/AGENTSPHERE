from flask import Flask, render_template, request, session, redirect, url_for, flash
import mysql.connector
import requests
import random

app = Flask(__name__)
app.secret_key = 'bank_of_india_secure_key_2026'

# The URL where your AI Agent (Orchestrator) is running
AI_AGENT_URL = "http://127.0.0.1:5001/analyze"

def get_session_ip():
    if 'current_ip' not in session:
        # Mocking an IP for the techathon demo environment
        session['current_ip'] = f"103.{random.randint(10, 99)}.{random.randint(100, 255)}.{random.randint(1, 255)}"
    return session['current_ip']

def get_db():
    return mysql.connector.connect(
        host="localhost", 
        user="root", 
        password="root", 
        database="techathon_bank", 
        autocommit=True
    )

# --- ROUTES ---

@app.route('/')
def home():
    if 'user_id' in session: 
        return redirect(url_for('dashboard'))
    return render_template('bank.html', view='login', ip=get_session_ip())

@app.route('/register_page')
def register_page():
    return render_template('bank.html', view='register')

@app.route('/register', methods=['POST'])
def register():
    u = request.form.get('username')
    p = request.form.get('password')
    acc = request.form.get('account_no')
    phone = request.form.get('phone')
    bal = request.form.get('balance', 10000)
    
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, account_number, phone, balance, status) VALUES (%s, %s, %s, %s, %s, 'active')", 
            (u, p, acc, phone, bal)
        )
        return redirect(url_for('home'))
    except Exception as e:
        return f"Registration Failed. Ensure database 'techathon_bank' and table 'users' exist. Error: {e}"

@app.route('/login', methods=['POST'])
def login():
    u = request.form.get('username')
    p = request.form.get('password')
    current_ip = get_session_ip() 
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (u,))
    user = cursor.fetchone()

    # Determine status for AI telemetry
    login_status = "Success" if (user and user['password'] == p) else "Failure"
    
    # 🚩 AGENT 1 & 2: Brute Force & Identity Analysis
    try:
        response = requests.post(AI_AGENT_URL, json={
            "user": u if u else "Unknown", 
            "ip": current_ip, 
            "activity": f"Login Attempt: {login_status}"
        }, timeout=1.5).json()
        
        # 🚩 LOGIC: If AI blocks the attempt, clear the IP to force a new one for the next session
        if response.get('decision') == 'Blocked' or (user and user['status'] == 'blocked'):
            session.pop('current_ip', None)  # <-- This triggers the automatic IP change for the next attempt
            reason = response.get('reason', 'Security Policy Violation')
            return render_template('bank.html', view='blocked', user=u, reason=reason)
            
    except Exception as e:
        print(f"AI Orchestrator Error: {e}")

    if user and user['password'] == p:
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['ip'] = current_ip
        # Optional: Reset failed attempts in DB on success
        return redirect(url_for('dashboard'))
    
    return "Invalid Credentials. <a href='/'>Try again</a>"

@app.route('/transfer', methods=['POST'])
def transfer():
    if 'user_id' not in session: return redirect(url_for('home'))
    
    # 🚩 AGENT 3: BOLA CHECK (Broken Object Level Authorization)
    # If the user tampered with the hidden 'sender_id' in HTML
    claimed_id = int(request.form.get('sender_id', 0))
    actual_id = session['user_id']
    is_bola_attack = (claimed_id != actual_id)
    
    amt = float(request.form.get('amount', 0))
    receiver = request.form.get('receiver', 'Unknown')
    location = request.form.get('location', 'India')
    
    # 🚩 AGENT 4 & 5: Geofencing & Frequency (Velocity)
    try:
        res = requests.post(AI_AGENT_URL, json={
            "user": session['username'], 
            "ip": session['ip'], 
            "activity": "Transfer",
            "amount": amt,
            "geo_block": True if location == "USA" else False,
            "bola_attack": is_bola_attack
        }).json()

        if res.get('decision') == 'Blocked':
            # Update DB to lock the user
            db = get_db(); cursor = db.cursor()
            cursor.execute("UPDATE users SET status='blocked' WHERE id=%s", (actual_id,))
            return render_template('bank.html', view='blocked')
    except:
        pass

    # Process Transaction if not blocked
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET balance = balance - %s WHERE id=%s AND balance >= %s", (amt, actual_id, amt))
    
    if cursor.rowcount > 0:
        cursor.execute("INSERT INTO transactions (sender, receiver, amount) VALUES (%s, %s, %s)", 
                       (session['username'], receiver, amt))
        return redirect(url_for('dashboard'))
    
    return "Insufficient balance or transfer error."

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('home'))
    db = get_db(); cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()
    
    # Fetch transactions for the statement view
    cursor.execute("SELECT * FROM transactions WHERE sender=%s ORDER BY id DESC", (session['username'],))
    txs = cursor.fetchall()
    
    return render_template('bank.html', view='dashboard', user=user, transactions=txs)

@app.route('/statement')
def statement():
    if 'user_id' not in session: return redirect(url_for('home'))
    db = get_db(); cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM transactions WHERE sender=%s ORDER BY id DESC", (session['username'],))
    txs = cursor.fetchall()
    return render_template('bank.html', view='statement', transactions=txs)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    print("🚀 Bank Portal running on http://127.0.0.1:5000")
    app.run(port=5000, debug=True)