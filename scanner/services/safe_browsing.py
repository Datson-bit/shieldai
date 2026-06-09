import requests
from django.conf import settings


def check_safe_browsing(url: str) -> dict:
    api_key = settings.GOOGLE_SAFE_BROWSING_KEY

    if not api_key:
        return {
            "status": "SKIPPED",
            "score": 0,
            "note": "Google Safe Browsing API key not configured",
            "threat_type": None,
        }

    try:
        payload = {
            "client": {
                "clientId": "shieldai-phishguard",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload,
            timeout=10,
        )

        if response.status_code != 200:
            if response.status_code in [400, 403]:
                note = "Google Safe Browsing check failed — Invalid or unauthorized API key."
            elif response.status_code == 429:
                note = "Google Safe Browsing rate limit exceeded. Please try again later."
            else:
                note = f"Google Safe Browsing check failed — API error (status code: {response.status_code})."
            return {
                "status": "ERROR",
                "score": 0,
                "note": note,
                "threat_type": None,
            }

        data = response.json()
        matches = data.get("matches", [])

        if matches:
            threat_type = matches[0].get("threatType", "UNKNOWN")
            threat_labels = {
                "MALWARE": "Malware distribution site",
                "SOCIAL_ENGINEERING": "Phishing or social engineering site",
                "UNWANTED_SOFTWARE": "Unwanted software distribution",
                "POTENTIALLY_HARMFUL_APPLICATION": "Potentially harmful application",
            }
            threat_label = threat_labels.get(threat_type, threat_type)

            return {
                "status": "FAILED",
                "score": 40,
                "note": f"Google flagged this as: {threat_label}",
                "threat_type": threat_type,
            }

        return {
            "status": "PASSED",
            "score": 0,
            "note": "Not found in Google Safe Browsing database",
            "threat_type": None,
        }

    except requests.exceptions.Timeout:
        return {
            "status": "ERROR",
            "score": 0,
            "note": "Google Safe Browsing request timed out.",
            "threat_type": None,
        }
    except requests.exceptions.ConnectionError:
        return {
            "status": "ERROR",
            "score": 0,
            "note": "Google Safe Browsing is currently unreachable. Please check your internet connection.",
            "threat_type": None,
        }
    except Exception as e:
        err_msg = str(e).lower()
        if any(x in err_msg for x in ["nameresolutionerror", "failed to resolve", "getaddrinfo failed", "connection", "timeout"]):
            note = "Google Safe Browsing is currently unreachable. Please check your internet connection."
        else:
            note = f"Safe Browsing check failed: {str(e)}"
        return {
            "status": "ERROR",
            "score": 0,
            "note": note,
            "threat_type": None,
        }
