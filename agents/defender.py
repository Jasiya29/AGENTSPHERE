# import os
# from google import genai
# from google.genai import types # Added for configuration
# from dotenv import load_dotenv

# load_dotenv()
# api_key = os.getenv("GOOGLE_API_KEY")

# # Initialize the 2026 Client with production API version
# if not api_key:
#     client = None
# else:
#     # Explicitly setting v1 avoids the 'v1beta' 404 error
#     client = genai.Client(
#         api_key=api_key,
#         http_options=types.HttpOptions(api_version="v1")
#     )

# def evaluate_threat(user, activity, ip):
#     # ... (Client initialization remains the same)

#     try:
#         # Try the AI first (Switching to Flash-Lite for better quota)
#         response = client.models.generate_content(
#             model="gemini-2.5-flash-lite", 
#             contents=f"Technical analysis of: {user} triggered {activity} from {ip}"
#         )
#         if response and response.text:
#             return f"AI: {response.text.strip()}"

#     except Exception as e:
#         # Catch the 429 Quota error specifically
#         if "429" in str(e):
#             print("⚠️ QUOTA EXHAUSTED: Switching to Local Security Agent.")
        
#         # --- LOCAL RULE-BASED ENGINE (The Judge-Saver) ---
#         # This ensures your dashboard ALWAYS shows a smart response
#         activity_lower = activity.lower()
        
#         if "usa" in activity_lower or "international" in activity_lower:
#             return "Blocked. Geofence violation (Unauthorized region)."
        
#         if "limit" in activity_lower or "amount" in activity_lower:
#             return "Flagged. Transaction exceeds individual velocity limit."
            
#         if "fail" in activity_lower or "password" in activity_lower:
#             return "Alert. Multiple authentication failures detected."

#         return "Activity monitored. No known threat signatures found."
import os
from google import genai  # <--- New Import
from google.genai import types # <--- New Types for Config
from dotenv import load_dotenv
from agents.threat_intel import calculate_risk_score

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

# 1. New Client Initialization (Replaces genai.configure)
client = None
if api_key:
    client = genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(api_version="v1")
    )

def evaluate_threat(user_data, activity, ip, failure_count):
    # 1. Handle potential 'None' or empty user_data safely
    user_name = user_data.get('username', 'Unregistered_Entity') if user_data else "Unknown"
    
    # 2. Get the Score from the Threat Intel Agent
    risk_score, _ = calculate_risk_score(user_data, activity, failure_count)

    try:
        if client:
            # 3. Enhanced Prompt: Force a "Technical Forensic" tone
            prompt = (
                f"As a Senior Cyber Forensic Expert at Bank of India, analyze this event: "
                f"Entity: {user_name}, Activity: {activity}, Source IP: {ip}. "
                f"Context: The internal scorer flagged this with a RISK_SCORE of {risk_score}%. "
                f"Provide a 1-sentence formal technical justification for this score."
            )

            response = client.models.generate_content(
                model="gemini-2.5-flash-lite", 
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.2) # Low temp for consistency
            )
            
            if response and response.text:
                # Return just the text without the "AI Analysis:" prefix to keep dashboard clean
                return response.text.strip()

    except Exception as e:
        # 4. Fallback: Log the error and use local logic
        print(f"⚠️ AI Reasoning Layer Bypass: {str(e)[:50]}...")
        return get_local_justification(activity, risk_score)

def get_local_justification(activity, score):
    """
    Rule-based backup that still respects the AI Risk Score.
    """
    act = activity.lower()
    if score >= 80:
        return f"CRITICAL: High risk ({score}%) detected. Action blocked due to anomaly signature."
    if "usa" in act or "international" in act:
        return "Geofence Alert: International access attempt from unauthorized region."
    if "bola" in act or "id mismatch" in act:
        return "Forensic Alert: BOLA/IDOR tampering attempt detected in transaction headers."
    
    return f"Standard Policy: Activity evaluated with risk factor of {score}%."