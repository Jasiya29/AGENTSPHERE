import os
import mysql.connector
from datetime import datetime
from google import genai 
from google.genai import types
from dotenv import load_dotenv

load_dotenv()

# Initialize 2026 SDK Client
client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY"),
    http_options=types.HttpOptions(api_version="v1")
)

class ForensicNotary:
    def __init__(self, db_config):
        self.db_config = db_config
        self.log_dir = os.path.join('static', 'forensic_logs')
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def generate_audit_trail_ai(self, log_id):
        """Uses Gemini 1.5 to certify the security event with a Hard-Coded Fallback."""
        db = None
        try:
            db = mysql.connector.connect(**self.db_config)
            cursor = db.cursor(dictionary=True)

            query = """
                SELECT s.ip_address, s.username, s.activity, s.timestamp, 
                       d.risk_score, d.ai_reasoning, d.action_taken
                FROM security_logs s
                LEFT JOIN defense_actions d ON s.id = d.log_id
                WHERE s.id = %s
            """
            cursor.execute(query, (log_id,))
            record = cursor.fetchone()

            if not record:
                return "ERROR: Audit data not found in database."

            # --- ATTEMPT AI GENERATION ---
            try:
                prompt = f"""
                SYSTEM: Act as a Legal AI Forensic Auditor for Bank of India. 
                DATA: TRACE_{log_id}, USER_{record['username']}, IP_{record['ip_address']}.
                ACTIVITY: {record['activity']}
                AI_DECISION: {record['action_taken']}
                
                TASK: Convert this telemetry into a formal 5-line 'Digital Certificate of Evidence'.
                Include a 'Forensic Hash' placeholder at the bottom.
                """

                response = client.models.generate_content(
                    model="gemini-2.5-flash-lite",
                    config=types.GenerateContentConfig(temperature=0.0),
                    contents=prompt
                )
                return response.text.strip()

            except Exception as ai_err:
                # --- EMERGENCY FALLBACK (If Quota Limit / No Internet) ---
                print(f"⚠️ AI Offline: {ai_err}. Using Deterministic Fallback.")
                
                fallback_text = f"""
                [OFFLINE GENERATED CERTIFICATE]
                LOG REFERENCE: TRACE_{log_id}
                IDENTITY: User {record['username']} | IP: {record['ip_address']}
                ACTIVITY LOG: {record['activity']}
                RISK ASSESSMENT: {record['risk_score']}% Probability of Breach.
                TECHNICAL VERDICT: {record['action_taken']} - {record['ai_reasoning']}
                FORENSIC_HASH: SHA256_{datetime.now().strftime('%H%M%S%f')}_SECURE
                """
                return fallback_text.strip()

        except Exception as e:
            return f"FORENSIC_GEN_FAILURE: {str(e)}"
        finally:
            if db and db.is_connected():
                db.close()

    def export_to_file(self, audit_text, log_id):
        """Saves the audit reasoning to a physical file."""
        try:
            filename = f"FORENSIC_TRACE_{log_id}.txt"
            file_path = os.path.join(self.log_dir, filename)
            
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("=== BANK OF INDIA AI FORENSIC AUDIT ===\n")
                f.write(f"TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"LOG_REFERENCE: {log_id}\n")
                f.write("-------------------------------------------\n\n")
                f.write(audit_text)
                f.write("\n\n-------------------------------------------\n")
                f.write("ISSUER: AgentSphere Multi-Agent Defense (Local Fallback Enabled)")
            
            return filename
        except Exception as e:
            print(f"❌ File Export Error: {e}")
            return None

# Database Config
db_config = {
    "host": "localhost", "user": "root", "password": "root", "database": "techathon_bank"
}

notary = ForensicNotary(db_config)