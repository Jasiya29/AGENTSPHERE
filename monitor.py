import mysql.connector
from datetime import datetime

class MonitoringAgent:
    def __init__(self, db_config):
        self.db_config = db_config

    def log_event(self, ip_address, username, activity, status):
        """
        Records specific event status (Allowed, Blocked, Failed) into 'security_logs'.
        This history allows the AI to see patterns of behavior.
        """
        try:
            db = mysql.connector.connect(**self.db_config)
            cursor = db.cursor()
            
            # Using 'timestamp' to match your database schema perfectly
            query = """
                INSERT INTO security_logs (ip_address, username, activity, status) 
                VALUES (%s, %s, %s, %s)
            """
            # Status values will now be: 'Allowed', 'Blocked', 'Failure', 'Success'
            values = (ip_address, username, activity, status)
            
            cursor.execute(query, values)
            db.commit()
            
            log_id = cursor.lastrowid
            cursor.close()
            db.close()
            
            print(f"🕵️ [MONITOR] Event Logged | {username} | {activity} | Status: {status}")
            return log_id
            
        except Exception as e:
            print(f"❌ [MONITOR ERROR]: {e}")
            return None

# Database Configuration
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "root", 
    "database": "techathon_bank"
}

# Global instance for your Bank App to import
sentry = MonitoringAgent(db_config)