from google import genai
from google.genai.errors import APIError
from django.conf import settings
import json


def analyse_with_gemini(url: str) -> dict:
    api_key = settings.GEMINI_API_KEY

    if not api_key:
        return {
            "status": "SKIPPED",
            "score": 0,
            "note": "Gemini API key not configured",
            "analysis": None,
        }

    try:
        client = genai.Client(api_key=api_key)

        prompt = f"""
You are a cybersecurity expert specialising in phishing detection for Nigerian internet users.

Analyse this URL for phishing indicators: {url}

IMPORTANT RULES:
- Only mark is_suspicious as true if the URL is ACTIVELY impersonating a known brand or has clear credential harvesting patterns
- Do NOT mark legitimate websites as suspicious simply because they are unfamiliar or not Nigerian
- A website being unknown is NOT a reason to flag it as suspicious
- Only flag if there is clear evidence of deception or impersonation

Focus specifically on:
1. Is the domain actively impersonating a known Nigerian bank, fintech, or government service?
   (OPay, GTBank, Zenith Bank, Access Bank, First Bank, Kuda, Moniepoint, PalmPay, JAMB, FIRS, NIN, WAEC)
2. Are there clear credential harvesting patterns — fake login pages, urgent account warnings?
3. Is the URL deliberately misleading — typosquatting, lookalike domains?

If none of the above apply — mark is_suspicious as false.

Respond in this exact JSON format with no additional text:
{{
    "is_suspicious": true or false,
    "confidence": "HIGH", "MEDIUM", or "LOW",
    "impersonates": "name of brand being impersonated or null",
    "summary": "One sentence plain English explanation suitable for a non-technical Nigerian user"
}}
"""

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        text = response.text.strip()

        # Clean response
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        text = text.strip()

        result = json.loads(text)

        is_suspicious = result.get("is_suspicious", False)
        confidence = result.get("confidence", "LOW")
        impersonates = result.get("impersonates")
        summary = result.get("summary", "No analysis available")

        if is_suspicious and confidence == "HIGH":
            status = "FAILED"
            score = 30
        elif is_suspicious and confidence == "MEDIUM":
            status = "WARNING"
            score = 15
        elif is_suspicious and confidence == "LOW":
            status = "WARNING"
            score = 8
        else:
            status = "PASSED"
            score = 0

        note = summary
        if impersonates:
            note = f"Appears to impersonate {impersonates}. {summary}"

        return {
            "status": status,
            "score": score,
            "note": note,
            "analysis": result,
        }

    except APIError as e:
        err_msg = str(e).lower()
        if e.code == 429 or "quota" in err_msg or "rate" in err_msg or "limit" in err_msg:
            note = "Gemini AI quota exceeded. Please check your API key's limits/billing or try again later."
        elif e.code in [400, 401, 403] or "api key" in err_msg or "invalid" in err_msg:
            note = "Gemini AI check failed — Invalid or unauthorized API key."
        else:
            note = f"Gemini AI API error: {e.message or str(e)}"
        return {
            "status": "ERROR",
            "score": 0,
            "note": note,
            "analysis": None,
        }
    except Exception as e:
        err_msg = str(e).lower()
        # Handle connection errors, DNS resolution failures, timeouts
        if any(x in err_msg for x in ["nameresolutionerror", "failed to resolve", "getaddrinfo failed", "connection", "timeout"]):
            note = "Gemini AI service is currently unreachable. Please check your internet connection."
        else:
            note = f"Gemini analysis failed: {str(e)}"
        return {
            "status": "ERROR",
            "score": 0,
            "note": note,
            "analysis": None,
        }


def analyse_email_with_gemini(email_content: str) -> dict:
    api_key = settings.GEMINI_API_KEY

    if not api_key:
        return {
            "status": "SKIPPED",
            "verdict": "Suspicious",
            "risk_score": 0,
            "flags": ["API Key Config Warning"],
            "summary": "Gemini API key not configured in backend environment.",
        }

    try:
        client = genai.Client(api_key=api_key)

        prompt = f"""
You are a cybersecurity expert specialising in email fraud and phishing detection for Nigerian internet users.

Analyse this raw email content:
---
{email_content}
---

Focus specifically on identifying:
1. Phishing indicators and sender spoofing patterns (e.g. claiming to be GTBank, OPay, JAMB, FIRS, etc. but using generic/incorrect domains).
2. Urgency language or manipulative language prompting immediate action (e.g. "account blocked", "immediate verification needed").
3. Suspicious links or credential harvesting forms inside the email.

Determine the risk score (from 0 to 100) and provide a list of flags and a concise, clear plain English explanation suitable for a non-technical Nigerian user.

Respond in this exact JSON format with no additional text:
{{
    "verdict": "Legitimate" or "Suspicious" or "Phishing Attempt",
    "risk_score": 0 to 100,
    "flags": [
        "list of threat indicators found"
    ],
    "summary": "One sentence plain English explanation suitable for a non-technical Nigerian user"
}}
"""

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        text = response.text.strip()

        # Clean response
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        text = text.strip()

        result = json.loads(text)
        return {
            "status": "SUCCESS",
            "verdict": result.get("verdict", "Suspicious"),
            "risk_score": result.get("risk_score", 50),
            "flags": result.get("flags", []),
            "summary": result.get("summary", "No summary analysis available."),
        }

    except Exception as e:
        return {
            "status": "ERROR",
            "verdict": "Suspicious",
            "risk_score": 0,
            "flags": ["Analysis Failed"],
            "summary": f"Could not perform email analysis: {str(e)}",
        }


