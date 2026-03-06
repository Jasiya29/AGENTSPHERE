import os
from google import genai
from google.genai import types

class StrategyCoordinator:
    def __init__(self):
        # Using the stable v1 SDK as discussed
        self.client = genai.Client(
            api_key=os.getenv("GEMINI_API_KEY"),
            http_options=types.HttpOptions(api_version="v1")
        )

    def determine_playbook(self, risk_score, activity, user_history):
        """
        Orchestrates the response based on the threat level.
        Returns a 'Playbook' and 'Execution Priority'.
        """
        prompt = f"""
        ROLE: Bank of India Strategy Orchestrator.
        INPUT: Risk {risk_score}%, Activity: {activity}, History: {user_history}.
        
        DECIDE ONE PLAYBOOK:
        1. [IGNORE]: Low risk, routine.
        2. [CHALLENGE]: Medium risk, requires 2FA or SOS.
        3. [ISOLATE]: High risk, lock account + notify ForensicNotary.
        4. [DECEIVE]: BOLA/Tampering detected, show fake data to attacker.

        OUTPUT FORMAT: 
        PLAYBOOK: [Name]
        STRATEGY: [1-sentence military-style command]
        """
        
        try:
            response = self.client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt
            )
            return response.text.strip()
        except:
            # Fallback strategy if AI is 429/404
            if risk_score > 80: return "PLAYBOOK: ISOLATE\nSTRATEGY: Emergency lockdown."
            return "PLAYBOOK: IGNORE\nSTRATEGY: Proceed with monitoring."

coordinator = StrategyCoordinator()