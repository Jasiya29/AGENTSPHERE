import os
import mysql.connector
from datetime import datetime
from google import genai  # <--- Modern 2026 SDK
from google.genai import types
from dotenv import load_dotenv

load_dotenv()

# 1. Initialize the 2026 Client
client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY"),
    http_options=types.HttpOptions(api_version="v1")
)

class LearningAgent:
    def __init__(self, db_config):
        self.db_config = db_config

    def learn_from_override(self, user, original_reason, manual_action):
        """
        AI analyzes the human override and updates the 'agent_knowledge' table.
        This closes the feedback loop between the Human Admin and the AI Brain.
        """
        prompt = f"""
        SYSTEM: You are the 'Agentic Learning & Adaptation Engine'.
        
        FEEDBACK LOOP DATA:
        - User Identity: {user}
        - AI Decision: Blocked (Flagged as Suspicious)
        - AI Reasoning: {original_reason}
        - Human Admin Decision: APPROVED (Override requested via SOS)

        TASK:
        1. Analyze why the original AI reasoning was a 'False Positive'.
        2. Create a 1-sentence 'Knowledge Rule' to prevent this specific false positive in the future.
        
        OUTPUT FORMAT (STRICT):
        ADAPTATION: [Short rule here]
        """

        db = None
        try:
            # 2. Updated AI Generation Call
            response = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3, # Slightly higher for "creative" learning
                    max_output_tokens=100
                )
            )
            
            adaptation_rule = response.text.strip()
            
            # Clean up the output to ensure it only stores the "ADAPTATION:" part
            if "ADAPTATION:" in adaptation_rule:
                adaptation_rule = adaptation_rule.split("ADAPTATION:")[1].strip()

            # 3. Update Database (Reinforcement Learning Storage)
            db = mysql.connector.connect(**self.db_config)
            cursor = db.cursor()
            
            query = """
                INSERT INTO agent_knowledge (user_context, lesson_learned, timestamp) 
                VALUES (%s, %s, %s)
            """
            cursor.execute(query, (user, adaptation_rule, datetime.now()))
            
            db.commit()
            print(f"🧠 [LEARNING AGENT] Knowledge Updated for {user}: {adaptation_rule}")
            return adaptation_rule

        except Exception as e:
            print(f"❌ [LEARNING ERROR]: {e}")
            return "Local Policy Update: Human SOS override recorded."
        finally:
            if db and db.is_connected():
                db.close()

# Database Config (Ensure your password matches your local setup)
db_config = {
    "host": "localhost", 
    "user": "root", 
    "password": "root", 
    "database": "techathon_bank"
}

# The 'learner' instance imported by agentsphere_app.py
learner = LearningAgent(db_config)