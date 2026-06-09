import whois
from urllib.parse import urlparse
from datetime import datetime, timezone


def check_domain_age(url: str) -> dict:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if domain.startswith("www."):
            domain = domain[4:]
        domain = domain.split(":")[0]

        w = whois.whois(domain)

        creation_date = w.creation_date

        # Sometimes returns a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {
                "status": "WARNING",
                "score": 10,
                "note": "Domain creation date could not be determined",
                "domain_age_days": None,
            }

        # Make timezone aware
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days

        if age_days < 30:
            status = "FAILED"
            score = 35
            note = f"Domain is only {age_days} day(s) old — extremely suspicious"
        elif age_days < 180:
            status = "WARNING"
            score = 15
            note = f"Domain is {age_days} days old — relatively new"
        else:
            status = "PASSED"
            score = 0
            age_years = age_days // 365
            note = f"Domain is {age_days} days old ({age_years} year(s)) — established"

        return {
            "status": status,
            "score": score,
            "note": note,
            "domain_age_days": age_days,
        }

    except Exception as e:
        err_msg = str(e).lower()
        if any(x in err_msg for x in ["gaierror", "getaddrinfo", "connection", "timeout", "unreachable", "reset by peer"]):
            note = "Domain age service (Whois) is currently unreachable. Please check your internet connection."
        else:
            note = f"Domain age check failed: {str(e)}"
        return {
            "status": "ERROR",
            "score": 0,
            "note": note,
            "domain_age_days": None,
        }
