from flask import Flask, render_template, request, jsonify
import mysql.connector
from agents.defender import evaluate_threat
import os

app = Flask(__name__)

# Helper function to connect to the Techathon Bank Database
def get_db():
    return mysql.connector.connect(
        host="localhost", 
        user="root", 
        password="root", 
        database="techathon_bank"
    )

@app.route('/')
def index():
    """The Dashboard UI: Shows raw traffic at the top and AI analysis below."""
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    try:
        # Fetch latest 10 Monitoring Logs
        cursor.execute("SELECT * FROM security_logs ORDER BY id DESC LIMIT 10")
        monitor_logs = cursor.fetchall()
        
        # Fetch latest 10 Defense Actions
        cursor.execute("""
            SELECT s.username, s.activity, d.risk_score, d.ai_reasoning, d.action_taken, s.timestamp 
            FROM defense_actions d 
            JOIN security_logs s ON d.log_id = s.id 
            ORDER BY d.id DESC LIMIT 10
        """)
        defense_logs = cursor.fetchall()
    except Exception as e:
        print(f"Database Fetch Error: {e}")
        monitor_logs, defense_logs = [], []
    finally:
        db.close()
        
    return render_template('defense.html', monitor=monitor_logs, defense=defense_logs)

@app.route('/analyze', methods=['POST'])
def analyze():
    """AI Decision Engine: Handles Geofencing and Transaction Limits."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data received"}), 400

    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    try:
        # 1. FETCH FAILURE HISTORY
        cursor.execute("""
            SELECT COUNT(*) as total_fails FROM security_logs 
            WHERE username = %s 
            AND status = 'Failure' 
            AND timestamp > NOW() - INTERVAL 10 MINUTE
        """, (data['user'],))
        
        row = cursor.fetchone()
        previous_failures = row['total_fails'] if row else 0

        # 2. CALCULATE RISK & ACTION (Simplified)
        if data['status'] == 'Success':
            risk = 10
            action = 'Allowed'
        
        else:
            # CASE A: GEOFENCING VIOLATION (100% Risk)
            if data.get('geo_block') == True:
                risk = 100
                action = 'Blocked'
            
            # CASE B: TRANSACTION LIMIT VIOLATION
            elif "Limit Exceeded" in data['activity']:
                risk = 90  
                action = 'Suspicious' 
            
            # CASE C: STANDARD LOGIN FAILURE (Incremental Risk)
            else:
                current_attempt = previous_failures + 1
                risk = current_attempt * 20 
                
                if risk >= 60:
                    action = 'Blocked'
                else:
                    action = 'Suspicious'

        # 3. CALL AI AGENT (GEMINI)
        # Simplified context without Multi-IP
        context = f"{data['activity']} (History: {previous_failures} fails)"
        reasoning = evaluate_threat(data['user'], context, data['ip'])
        
        # 4. LOG THE MONITORING DATA
        cursor.execute(
            "INSERT INTO security_logs (ip_address, username, activity, status) VALUES (%s,%s,%s,%s)",
            (data['ip'], data['user'], data['activity'], data['status'])
        )
        log_id = cursor.lastrowid
        
        # 5. SAVE THE AI DEFENSE ACTION
        cursor.execute(
            "INSERT INTO defense_actions (log_id, risk_score, ai_reasoning, action_taken) VALUES (%s,%s,%s,%s)",
            (log_id, risk, reasoning, action)
        )
        
        # 6. ENFORCEMENT
        if action == 'Blocked':
            cursor.execute("UPDATE users SET status='blocked' WHERE username=%s", (data['user'],))
        
        db.commit()
        
        print(f"🛡️ [AGENT] User: {data['user']} | Risk: {risk}% | Decision: {action}")
        
        return jsonify({
            "status": "Success", 
            "decision": action, 
            "risk": risk,
            "reason": reasoning
        }), 200

    except Exception as e:
        print(f"❌ [AGENT ERROR]: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

if __name__ == "__main__":
    print("🚀 AgentSphere Security Hub starting on http://127.0.0.1:5001")
    app.run(port=5001, debug=True)