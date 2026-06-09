def calculate_risk(url_analysis, virustotal, domain_age, safe_browsing, gemini) -> dict:

    # Weighted scoring
    url_score       = url_analysis.get("score", 0) * 0.20
    vt_score        = virustotal.get("score", 0)   * 0.30
    domain_score    = domain_age.get("score", 0)   * 0.20
    sb_score        = safe_browsing.get("score", 0)* 0.20
    gemini_score    = gemini.get("score", 0)        * 0.10

    total_score = int(url_score + vt_score + domain_score + sb_score + gemini_score)
    total_score = min(total_score, 100)

    # Instant dangerous overrides
    if safe_browsing.get("status") == "FAILED":
        total_score = max(total_score, 75)

    if virustotal.get("malicious_count", 0) >= 5:
        total_score = max(total_score, 80)

    # Overrides for high-risk findings (impersonation, multi-layer flags)
    gemini_analysis = gemini.get("analysis") or {}

    # 1. Impersonation of a bank/brand is highly dangerous
    if gemini_analysis.get("is_suspicious") and gemini_analysis.get("impersonates"):
        total_score = max(total_score, 85)
    # 2. High confidence AI phishing classification
    elif gemini.get("status") == "FAILED":
        total_score = max(total_score, 75)
    # 3. Medium confidence AI phishing classification
    elif gemini.get("status") == "WARNING" and gemini_analysis.get("confidence") == "MEDIUM":
        total_score = max(total_score, 50)

    # 4. Multi-layer threat: URL structure FAILED and VirusTotal flags it
    if url_analysis.get("status") == "FAILED" and virustotal.get("malicious_count", 0) >= 1:
        total_score = max(total_score, 65)

    # Override: if key security checks cannot fully determine or analyze the URL, mark it as SUSPICIOUS (score >= 30)
    incomplete_checks = []
    if virustotal.get("status") in ["PENDING", "ERROR"]:
        incomplete_checks.append("VirusTotal")
    if gemini.get("status") == "ERROR":
        incomplete_checks.append("Gemini AI")
    if domain_age.get("status") == "ERROR" or (domain_age.get("status") == "WARNING" and "determine" in str(domain_age.get("note", "")).lower()):
        incomplete_checks.append("Domain Age")

    if incomplete_checks:
        total_score = max(total_score, 30)

    # Determine verdict
    if total_score >= 60:
        verdict = "DANGEROUS"
        color = "red"
        message = "This link is dangerous. Do not click or enter any personal information."
        icon = "danger"
    elif total_score >= 30:
        verdict = "SUSPICIOUS"
        color = "amber"
        message = "This link shows suspicious characteristics. Proceed with extreme caution."
        icon = "warning"
    else:
        verdict = "SAFE"
        color = "green"
        message = "This link appears to be safe. No significant threats detected."
        icon = "safe"

    # Build plain English explanation
    active_flags = []

    if virustotal.get("status") == "FAILED":
        active_flags.append(virustotal.get("note", "Flagged by security vendors"))
    if safe_browsing.get("status") == "FAILED":
        active_flags.append(safe_browsing.get("note", "Flagged by Google Safe Browsing"))
    if domain_age.get("status") == "FAILED":
        active_flags.append(domain_age.get("note", "Domain is very new"))
    if url_analysis.get("status") == "FAILED":
        active_flags.append(url_analysis.get("note", "Suspicious URL structure"))
    if gemini.get("status") in ["FAILED", "WARNING"]:
        active_flags.append(gemini.get("note", "AI detected suspicious content"))
    if incomplete_checks:
        active_flags.append(f"Could not fully analyze link via: {', '.join(incomplete_checks)}")

    return {
        "verdict": verdict,
        "risk_score": total_score,
        "color": color,
        "icon": icon,
        "message": message,
        "active_flags": active_flags,
        "breakdown": {
            "url_structure": {
                "status": url_analysis.get("status"),
                "note": url_analysis.get("note"),
                "flags": url_analysis.get("flags", []),
            },
            "virustotal": {
                "status": virustotal.get("status"),
                "note": virustotal.get("note"),
                "malicious_count": virustotal.get("malicious_count", 0),
                "total_vendors": virustotal.get("total_vendors", 0),
            },
            "domain_age": {
                "status": domain_age.get("status"),
                "note": domain_age.get("note"),
                "age_days": domain_age.get("domain_age_days"),
            },
            "safe_browsing": {
                "status": safe_browsing.get("status"),
                "note": safe_browsing.get("note"),
                "threat_type": safe_browsing.get("threat_type"),
            },
            "gemini_ai": {
                "status": gemini.get("status"),
                "note": gemini.get("note"),
            },
        },
    }
