from flask import Flask, render_template, request, session, redirect, url_for, flash
import mysql.connector
import requests
from datetime import datetime, timedelta
import random

app = Flask(__name__)
app.secret_key = 'bank_of_india_secure_key'

# --- IP Generation Feature ---
def generate_fake_ip(location="India"):
    if location == "USA":
        # Realistic USA IP range (e.g., 162.x.x.x)
        return f"162.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    # Realistic India IP range (e.g., 103.x.x.x)
    return f"103.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

# --- Database Helper ---
def get_db():
    return mysql.connector.connect(
        host="localhost", user="root", password="root", database="techathon_bank"
    )

# --- Routes ---
@app.route('/')
def home():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('bank.html', view='login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u, p = request.form['username'], request.form['password']
        acc, ph = request.form['acc_no'], request.form['phone']
        db = get_db(); cursor = db.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE username=%s OR account_number=%s", (u, acc))
        if cursor.fetchone():
            db.close()
            return "<h1>Account/Username already exists!</h1><a href='/register'>Try Again</a>"

        cursor.execute("INSERT INTO users (username, password, account_number, phone, balance) VALUES (%s,%s,%s,%s, 100000.00)", (u,p,acc,ph))
        db.commit(); db.close()
        return redirect(url_for('home'))
    return render_template('bank.html', view='register')

@app.route('/login', methods=['POST'])
def login():
    u, p = request.form['username'], request.form['password']
    
    # Keep IP Generation
    current_attempt_ip = generate_fake_ip() 
    
    db = get_db(); cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (u,))
    user = cursor.fetchone()

    if not user: return "User not found. <a href='/'>Retry</a>"

    # Keep Timed Lockout Logic
    now = datetime.now()
    if user['lockout_until'] and now < user['lockout_until']:
        remaining = int((user['lockout_until'] - now).total_seconds())
        return render_template('blocked.html', seconds=remaining)

    status = "Failure"
    activity = ""

    # Simple Credential Check (Multi-IP Logic Removed)
    if user['password'] == p:
        cursor.execute("UPDATE users SET failed_attempts=0, lockout_until=NULL, last_ip=%s WHERE id=%s", (current_attempt_ip, user['id']))
        session['user_id'], session['username'] = user['id'], user['username']
        status = "Success"
        activity = "Login Successful"
        db.commit()
    else:
        status = "Failure"
        new_attempts = user['failed_attempts'] + 1 # Standard increment
        activity = f"Failed Login Attempt {new_attempts}"

        if new_attempts >= 3:
            lock_time = datetime.now() + timedelta(minutes=1)
            # Added 'current_attempt_ip' to the tuple below
            cursor.execute(
                   "UPDATE users SET failed_attempts=%s, lockout_until=%s, last_ip=%s WHERE id=%s", 
                   (new_attempts, lock_time, current_attempt_ip, user['id'])
            )
            activity = "Account Locked: Too many failed attempts"
        else:
    # Ensure 3 placeholders match 3 variables
            cursor.execute(
                 "UPDATE users SET failed_attempts=%s, last_ip=%s WHERE id=%s", 
                 (new_attempts, current_attempt_ip, user['id'])
            )
        db.commit()

    # Notify Defense Agent
    try:
        requests.post('http://127.0.0.1:5001/analyze', json={
            "user": u, 
            "ip": current_attempt_ip, 
            "activity": activity, 
            "status": status
            # Multi-IP flag removed
        })
    except: pass

    db.close()

    if status == "Success": 
        return redirect(url_for('dashboard'))
    
    if user['failed_attempts'] + 1 >= 3:
        return render_template('blocked.html', seconds=60)
    
    return f"Invalid Login. (Attempt {new_attempts if 'new_attempts' in locals() else '1'}) <a href='/'>Retry</a>"

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: 
        return redirect(url_for('home'))
        
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()
    db.close()
    
    # NEW: If user is not found (e.g., deleted from DB but session remains)
    if not user:
        session.clear()
        return redirect(url_for('home'))
        
    return render_template('bank.html', view='dashboard', user=user)

@app.route('/transfer', methods=['POST'])
def transfer():
    if 'user_id' not in session: return redirect(url_for('home'))
    
    amt = float(request.form['amount'])
    desc = request.form['description']
    location = request.form.get('location') 
    username = session['username']
    
    # Keep IP Generation based on dropdown
    fake_ip = generate_fake_ip(location) 
    
    db = get_db(); cursor = db.cursor()

    # 1. Keep Geofencing Security
    if location == "USA":
        status = "Failure"
        activity = f"Critical Alert: International Access Attempt from {location}"
        
        requests.post('http://127.0.0.1:5001/analyze', json={
            "user": username, 
            "ip": fake_ip, 
            "activity": activity, 
            "status": status,
            "geo_block": True
        })
        
        db.close()
        session.clear() 
        flash("🚨 Account Locked: Unauthorized international access detected.", "danger")
        return render_template('blocked.html', seconds=60)

    # 2. Keep Transaction Limit Security
    if amt > 50000:
        status = "Failure"
        activity = f"Suspicious Transfer: ₹{amt} (Limit Exceeded)"
        
        requests.post('http://127.0.0.1:5001/analyze', json={
            "user": username, 
            "ip": fake_ip, # Use generated IP
            "activity": activity, 
            "status": status
        })
        
        db.close()
        return render_template('bank.html', view='dashboard', user={'username': username}, error="❌ Limit Exceeded.")

    # 3. Database Transaction Logic
    cursor.execute("UPDATE users SET balance = balance - %s WHERE id=%s AND balance >= %s", (amt, session['user_id'], amt))
    
    if cursor.rowcount > 0:
        cursor.execute("INSERT INTO transactions (user_id, amount, description, type) VALUES (%s,%s,%s,'DEBIT')", (session['user_id'], amt, desc))
        db.commit()
        status, activity = "Success", f"Transfer: ₹{amt} Allowed"
    else:
        status, activity = "Failure", f"Transfer: ₹{amt} Denied (Low Funds)"

    # 4. Notify Agent of Result
    requests.post('http://127.0.0.1:5001/analyze', json={
        "user": username, 
        "ip": fake_ip, 
        "activity": activity, 
        "status": status
    })
    
    db.close()
    return redirect(url_for('statement'))

@app.route('/statement')
def statement():
    if 'user_id' not in session: return redirect(url_for('home'))
    db = get_db(); cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM transactions WHERE user_id=%s ORDER BY timestamp DESC", (session['user_id'],))
    txs = cursor.fetchall(); db.close()
    return render_template('bank.html', view='statement', transactions=txs)

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(port=5000, debug=True)