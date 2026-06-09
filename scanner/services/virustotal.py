import requests
import base64
from django.conf import settings


def check_virustotal(url: str) -> dict:
    api_key = settings.VIRUSTOTAL_API_KEY

    if not api_key:
        return {
            "status": "SKIPPED",
            "score": 0,
            "note": "VirusTotal API key not configured",
            "malicious_count": 0,
            "total_vendors": 0,
        }

    try:
        # Encode URL to base64 for VirusTotal v3 API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        headers = {"x-apikey": api_key}

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10,
        )

        if response.status_code == 404:
            # URL not in VT database — submit it first
            submit_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10,
            )
            if submit_response.status_code == 200:
                return {
                    "status": "PENDING",
                    "score": 0,
                    "note": "URL submitted for analysis — not yet in database",
                    "malicious_count": 0,
                    "total_vendors": 0,
                }

        if response.status_code != 200:
            if response.status_code in [401, 403]:
                note = "VirusTotal check failed — Invalid or unauthorized API key."
            elif response.status_code == 429:
                note = "VirusTotal rate limit exceeded. Please try again later."
            else:
                note = f"VirusTotal check failed — API error (status code: {response.status_code})."
            return {
                "status": "ERROR",
                "score": 0,
                "note": note,
                "malicious_count": 0,
                "total_vendors": 0,
            }

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        combined_flags = malicious + suspicious

        if combined_flags >= 3:
            status = "FAILED"
            score = min(40 + (combined_flags * 5), 100)
            note = f"Flagged as malicious by {combined_flags} out of {total} security vendors"
        elif combined_flags >= 1:
            status = "WARNING"
            score = 20
            note = f"Flagged by {combined_flags} security vendor(s) — treat with caution"
        else:
            status = "PASSED"
            score = 0
            note = f"No threats detected across {total} security vendors"

        return {
            "status": status,
            "score": score,
            "note": note,
            "malicious_count": combined_flags,
            "total_vendors": total,
        }

    except requests.exceptions.Timeout:
        return {
            "status": "ERROR",
            "score": 0,
            "note": "VirusTotal request timed out.",
            "malicious_count": 0,
            "total_vendors": 0,
        }
    except requests.exceptions.ConnectionError:
        return {
            "status": "ERROR",
            "score": 0,
            "note": "VirusTotal is currently unreachable. Please check your internet connection.",
            "malicious_count": 0,
            "total_vendors": 0,
        }
    except Exception as e:
        err_msg = str(e).lower()
        if any(x in err_msg for x in ["nameresolutionerror", "failed to resolve", "getaddrinfo failed", "connection", "timeout"]):
            note = "VirusTotal is currently unreachable. Please check your internet connection."
        else:
            note = f"VirusTotal check failed: {str(e)}"
        return {
            "status": "ERROR",
            "score": 0,
            "note": note,
            "malicious_count": 0,
            "total_vendors": 0,
        }
