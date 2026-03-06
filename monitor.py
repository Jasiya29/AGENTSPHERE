import mysql.connector
from datetime import datetime

class MonitoringAgent:
    def __init__(self, db_config):
        self.db_config = db_config

    def log_event(self, ip_address, username, activity, status):
        """
        Records event status. 
        TIP: Use status 'Pending' for start of actions and 'Success/Blocked' for ends.
        """
        db = None
        try:
            db = mysql.connector.connect(**self.db_config)
            cursor = db.cursor()
            
            # Use MySQL's NOW() for database consistency, or Python's for display
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            query = """
                INSERT INTO security_logs (ip_address, username, activity, status, timestamp) 
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query, (ip_address, username, activity, status, current_time))
            db.commit()
            
            log_id = cursor.lastrowid
            
            # Console Icons for visibility
            icons = {"Success": "✅", "Blocked": "🚫", "Pending": "⏳", "Failure": "❌", "BOLA": "🕵️"}
            icon = icons.get(status, "ℹ️")
            
            print(f"{icon} [MONITOR] {username} | {activity} | {status}")
            return log_id
            
        except Exception as e:
            print(f"❌ [MONITOR ERROR]: {e}")
            return None
        finally:
            if db and db.is_connected():
                db.close()

    def get_live_stats(self):
        """Helper for the Dashboard to see total blocks vs total logins."""
        db = mysql.connector.connect(**self.db_config)
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT status, COUNT(*) as count FROM security_logs GROUP BY status")
        stats = cursor.fetchall()
        db.close()
        return stats

# Global instance
db_config = {"host": "localhost", "user": "root", "password": "root", "database": "techathon_bank"}
sentry = MonitoringAgent(db_config)