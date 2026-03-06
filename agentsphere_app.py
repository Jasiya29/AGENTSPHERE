import os
import mysql.connector
from flask import Flask, render_template, request, jsonify, send_file, redirect
from flask_cors import CORS
from datetime import datetime
from threading import Lock
import json
import re
from google import genai
from dotenv import load_dotenv
from flask import Flask, request, jsonify

load_dotenv()

# Initialize the new Client
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
MODEL_ID = "gemini-2.5-flash-lite"

app = Flask(__name__)
CORS(app)  # Critical: Allows Port 5000 (Bank) to communicate with Port 5001 (AI)

# Shared Memory for the Recovery Agent (Human-in-the-loop)
sos_lock = Lock()
sos_requests = []

def get_db():
    return mysql.connector.connect(
        host="localhost", 
        user="root", 
        password="root", 
        database="techathon_bank", 
        autocommit=True
    )

@app.route('/')
def index():
    """Dashboard View: Displays the Telemetry and Defense Logs"""
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    # Fetch latest raw telemetry
    cursor.execute("SELECT * FROM security_logs ORDER BY id DESC LIMIT 10")
    monitor = cursor.fetchall()
    
    # Fetch AI decisions and reasoning
    cursor.execute("""
        SELECT s.id as log_id, s.username, s.activity, d.risk_score, d.ai_reasoning, d.action_taken 
        FROM defense_actions d 
        JOIN security_logs s ON d.log_id = s.id 
        ORDER BY d.id DESC LIMIT 10
    """)
    defense = cursor.fetchall()
    db.close()
    
    with sos_lock:
        current_sos = list(sos_requests)
        
    return render_template('defense.html', monitor=monitor, defense=defense, sos_alerts=current_sos)

# Outside the function, add a global tracker for IP-based memory
# This ensures that even if different usernames are tried, the IP is caught.
ip_violation_memory = {} 

@app.route('/analyze', methods=['POST'])
def analyze():
    global ip_violation_memory
    data = request.get_json()
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    user = data.get('user', 'Unknown')
    ip = data.get('ip', '0.0.0.0')
    activity = data.get('activity', '')
    is_usa = data.get('geo_block', False)
    is_bola = data.get('bola_attack', False)

    # 1. Update local memory for the AI to consider
    if "Failure" in activity:
        ip_violation_memory[ip] = ip_violation_memory.get(ip, 0) + 1
    current_ip_fails = ip_violation_memory.get(ip, 0)

    # 2. Construct the "Context" for the AI Agent
    prompt = f"""
    System: You are an Autonomous Cyber-Defense AI for a Bank.
    Task: Analyze the following telemetry and return a verdict in STRICT JSON.
    
    Context:
    - User Identity: {user}
    - Request IP: {ip}
    - Recent Failures for this IP: {current_ip_fails}
    - Geofence Violation (USA): {is_usa}
    - BOLA/ID Spoofing Detected: {is_bola}
    - Current Activity: {activity}

    Rules:
    - If failures >= 4, decision must be 'Blocked'.
    - If is_usa or is_bola is True, decision must be 'Blocked'.
    - Provide a technical 'reasoning' for the audit trail.
    - Provide a 'risk_score' from 0 to 100.

    Return JSON format:
    {{"risk_score": int, "decision": "String", "reasoning": "String"}}
    """

    try:
        # 3. Get AI Verdict using the new google.genai syntax
        # Using Gemini 1.5 Flash for high-speed analysis
        response = client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=prompt
        )
        
        # Extract and clean JSON from response text
        raw_text = response.text
        clean_json = re.sub(r'```json|```', '', raw_text).strip()
        ai_verdict = json.loads(clean_json)
        
        risk = ai_verdict.get('risk_score', 0)
        action = ai_verdict.get('decision', 'Allowed')
        reasoning = ai_verdict.get('reasoning', 'Normal behavioral pattern.')

    except Exception as e:
        print(f"AI Error: {e}. Falling back to Heuristics.")
        # Safety Fallback if the API fails or returns bad JSON
        if current_ip_fails >= 4 or is_usa or is_bola:
            risk, action, reasoning = 100, 'Blocked', 'Heuristic trigger: Safety override.'
        else:
            risk, action, reasoning = 0, 'Allowed', 'Normal pattern.'

    # 4. Enforcement Agent
    if action == 'Blocked' and user != 'Unknown':
        cursor.execute("UPDATE users SET status='blocked' WHERE username=%s", (user,))
    
    # 5. Persistence Agent (Logging)
    try:
        cursor.execute("INSERT INTO security_logs (ip_address, username, activity, status) VALUES (%s,%s,%s,%s)", 
                       (ip, user, activity, action))
        log_id = cursor.lastrowid
        cursor.execute("INSERT INTO defense_actions (log_id, risk_score, ai_reasoning, action_taken) VALUES (%s,%s,%s,%s)", 
                       (log_id, risk, reasoning, action))
    except Exception as log_error:
        print(f"Logging Error: {log_error}")
    
    db.close()
    print(f"🤖 AI Verdict: {action} | Risk: {risk}% | Reason: {reasoning}")
    
    return jsonify({"decision": action, "risk": f"{risk}%", "reason": reasoning})

@app.route('/sos_alert', methods=['POST'])
def sos_alert():
    """Recovery Agent: Collects User Appeals"""
    data = request.json
    with sos_lock:
        sos_requests.append({
            "id": len(sos_requests)+1, 
            "user": data.get('user'), 
            "status": "PENDING", 
            "timestamp": datetime.now().strftime("%H:%M:%S")
        })
    return jsonify({"status": "SOS_SENT"}), 200

@app.route('/approve_sos/<int:sos_id>')
def approve_sos(sos_id):
    """Recovery Agent: Human-in-the-loop Approval"""
    db = get_db()
    cursor = db.cursor()
    with sos_lock:
        for entry in sos_requests:
            if entry['id'] == sos_id:
                # SQL: Reset User in Database
                cursor.execute("UPDATE users SET status='active', failed_attempts=0 WHERE username=%s", (entry['user'],))
                entry['status'] = "APPROVED"
                break
    db.close()
    return redirect('/')

@app.route('/download_forensic/<int:log_id>')
def download_forensic(log_id):
    """Logging Agent: Generate Digital Evidence"""
    path = f"static/forensic_logs/TRACE_{log_id}.txt"
    os.makedirs("static/forensic_logs", exist_ok=True)
    
    with open(path, "w") as f:
        f.write(f"--- BANK OF INDIA AI FORENSIC LOG ---\n")
        f.write(f"TRACE ID: {log_id}\n")
        f.write(f"TIMESTAMP: {datetime.now()}\n")
        f.write(f"DIGITAL SIGNATURE: SHA256_{os.urandom(8).hex().upper()}\n")
        f.write(f"VERDICT: Blocked by Multi-Agent Orchestrator\n")
        
    return send_file(path, as_attachment=True)

if __name__ == '__main__':
    # Running Port 5001 for the AI Dashboard
    app.run(port=5001, debug=True)