def calculate_risk(url_analysis, virustotal, domain_age, safe_browsing, gemini) -> dict:

    # Weighted scoring
    url_score    = url_analysis.get("score", 0) * 0.20
    vt_score     = virustotal.get("score", 0)   * 0.25
    domain_score = domain_age.get("score", 0)   * 0.15
    sb_score     = safe_browsing.get("score", 0)* 0.20
    gemini_score = gemini.get("score", 0)       * 0.20

    # Zero out checks with no data — missing data is not a threat signal
    if virustotal.get("status") in ["PENDING", "ERROR", "SKIPPED"]:
        vt_score = 0
    if domain_age.get("status") in ["ERROR", "SKIPPED"]:
        domain_score = 0
    if gemini.get("status") in ["ERROR", "SKIPPED"]:
        gemini_score = 0

    total_score = int(url_score + vt_score + domain_score + sb_score + gemini_score)
    total_score = min(total_score, 100)

    # ── Hard overrides ───────────────────────────────────────────────

    # Google confirmed threat — always dangerous
    if safe_browsing.get("status") == "FAILED":
        total_score = max(total_score, 75)

    # VirusTotal many vendors — always dangerous
    if virustotal.get("malicious_count", 0) >= 5:
        total_score = max(total_score, 80)

    # VirusTotal WARNING — at least suspicious
    if virustotal.get("status") == "WARNING":
        total_score = max(total_score, 25)

    # URL structure failed — at least suspicious
    if url_analysis.get("status") == "FAILED":
        total_score = max(total_score, 20)

    # URL structure failed + VirusTotal flagged — serious
    if url_analysis.get("status") == "FAILED" and virustotal.get("malicious_count", 0) >= 2:
        total_score = max(total_score, 60)
    elif url_analysis.get("status") == "FAILED" and virustotal.get("malicious_count", 0) >= 1:
        total_score = max(total_score, 40)

    # ── Gemini overrides ─────────────────────────────────────────────
    gemini_analysis = gemini.get("analysis") or {}
    gemini_suspicious = gemini_analysis.get("is_suspicious", False)
    gemini_impersonates = gemini_analysis.get("impersonates")
    gemini_confidence = gemini_analysis.get("confidence", "LOW")

    # Count confirmed flags from other checks
    other_flags = sum([
        1 if url_analysis.get("status") == "FAILED" else 0,
        1 if virustotal.get("status") in ["FAILED", "WARNING"] else 0,
        1 if domain_age.get("status") == "FAILED" else 0,
        1 if safe_browsing.get("status") == "FAILED" else 0,
    ])

    if gemini_suspicious and gemini_impersonates and gemini_confidence == "HIGH" and other_flags >= 1:
        total_score = max(total_score, 75)
    elif gemini_suspicious and gemini_impersonates and gemini_confidence == "HIGH":
        total_score = max(total_score, 50)
    elif gemini_suspicious and gemini_impersonates and gemini_confidence == "MEDIUM":
        total_score = max(total_score, 40)
    elif gemini_suspicious and gemini_confidence == "HIGH" and other_flags >= 1:
        total_score = max(total_score, 45)
    elif gemini_suspicious and gemini_confidence == "MEDIUM" and other_flags >= 1:
        total_score = max(total_score, 30)
    elif gemini_suspicious and other_flags == 0:
        total_score = max(total_score, 15)

    # ── Incomplete checks — missing data is not a threat ─────────────
    incomplete_checks = []
    if virustotal.get("status") in ["PENDING", "ERROR"]:
        incomplete_checks.append("VirusTotal")
    if gemini.get("status") == "ERROR":
        incomplete_checks.append("Gemini AI")
    if domain_age.get("status") == "ERROR":
        incomplete_checks.append("Domain Age")

    if incomplete_checks:
        total_score = max(total_score, 8)

    total_score = min(total_score, 100)

    # ── Verdict ──────────────────────────────────────────────────────
    if total_score >= 60:
        verdict = "DANGEROUS"
        color = "red"
        message = "This link is dangerous. Do not click or enter any personal information."
        icon = "danger"
    elif total_score >= 25:
        verdict = "SUSPICIOUS"
        color = "amber"
        message = "This link shows suspicious characteristics. Proceed with extreme caution."
        icon = "warning"
    else:
        verdict = "SAFE"
        color = "green"
        message = "This link appears to be safe. No significant threats detected."
        icon = "safe"

    # ── Active flags ─────────────────────────────────────────────────
    active_flags = []

    if virustotal.get("status") in ["FAILED", "WARNING"]:
        active_flags.append(virustotal.get("note", "Flagged by security vendors"))
    if safe_browsing.get("status") == "FAILED":
        active_flags.append(safe_browsing.get("note", "Flagged by Google Safe Browsing"))
    if domain_age.get("status") == "FAILED":
        active_flags.append(domain_age.get("note", "Domain is very new"))
    if url_analysis.get("status") == "FAILED":
        active_flags.append(url_analysis.get("note", "Suspicious URL structure"))
    if gemini.get("status") in ["FAILED", "WARNING", "MALICIOUS"]:
        active_flags.append(gemini.get("note", "AI detected suspicious content"))
    if gemini_impersonates and gemini_suspicious:
        active_flags.append(f"Impersonation detected: {gemini_impersonates}")
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