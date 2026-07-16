import re


def _detect_target_type(target: str) -> str:
    if "@" in target and "." in target.split("@")[-1]:
        return "email"
    cleaned = re.sub(r"[\s\-().]+", "", target)
    if re.match(r"^\+?\d{7,15}$", cleaned):
        return "phone"
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        return "ip"
    if "." in target:
        return "domain"
    return "username"


def score(result: dict) -> dict:
    points     = 0
    breakdown  = []
    target     = result.get("target", "")
    target_type = _detect_target_type(target)

    # ─────────────────────────────────────────────
    # DERIVE signals from actual scan result data
    # ─────────────────────────────────────────────

    username_list = result.get("username") or []
    same_username = len(username_list) > 0

    whois = result.get("whois") or {}
    emp   = result.get("employee") or {}
    same_name = bool(
        (isinstance(whois, dict) and whois.get("name") and whois["name"] != "—") or
        (isinstance(emp,   dict) and emp.get("company_name"))
    )

    same_image = any(
        isinstance(u, dict) and u.get("image")
        for u in username_list
    )

    email_osint = result.get("email_osint") or {}
    same_email = bool(
        "@" in target or
        (isinstance(email_osint, dict) and email_osint.get("valid_format"))
    )

    phone = result.get("phone") or {}
    same_phone = bool(
        isinstance(phone, dict) and phone.get("valid")
    )

    geo = result.get("geo") or {}
    same_country = bool(
        isinstance(geo, dict) and geo.get("country") and not geo.get("error")
    )

    ip = result.get("ip", "")
    same_ip = bool(ip and ip != "Not found")

    same_isp = bool(
        isinstance(geo, dict) and geo.get("isp")
    )

    # ─────────────────────────────────────────────
    # 1. CORE IDENTITY SIGNALS           (max 40)
    #    Applies to all target types
    # ─────────────────────────────────────────────

    if same_username:
        pts = 20
        points += pts
        breakdown.append({
            "field":    "same_username",
            "label":    "Username Match",
            "points":   pts,
            "category": "Identity",
            "note":     f"{len(username_list)} platform(s) matched via username.py",
        })

    if same_name:
        pts = 10
        points += pts
        breakdown.append({
            "field":    "same_name",
            "label":    "Name Match",
            "points":   pts,
            "category": "Identity",
            "note":     "Real name found via WHOIS / employee lookup",
        })

    if same_image:
        pts = 10
        points += pts
        breakdown.append({
            "field":    "same_image",
            "label":    "Profile Image Match",
            "points":   pts,
            "category": "Identity",
            "note":     "Profile image found across platforms",
        })

    # ─────────────────────────────────────────────
    # 2. CONTACT SIGNALS                 (max 10)
    #    Applies to all target types
    # ─────────────────────────────────────────────

    if same_email:
        pts = 6
        points += pts
        breakdown.append({
            "field":    "same_email",
            "label":    "Email Match",
            "points":   pts,
            "category": "Contact",
            "note":     "Email resolved via email.py",
        })

    if same_phone:
        pts = 4
        points += pts
        breakdown.append({
            "field":    "same_phone",
            "label":    "Phone Match",
            "points":   pts,
            "category": "Contact",
            "note":     "Valid phone number via phone_lookup.py",
        })

    # ─────────────────────────────────────────────
    # 3. LOCATION & INFRASTRUCTURE       (max 20)
    #    Domain / IP / email targets only — a phone number
    #    resolving to a country via carrier metadata is not the
    #    same signal class as an IP/geo resolution, so this whole
    #    block is skipped for target_type == "phone" to avoid
    #    misleading "IP Resolved" / "ISP" cards on a phone report.
    # ─────────────────────────────────────────────

    if target_type in ("domain", "ip", "email"):
        if same_country:
            pts = 8
            points += pts
            breakdown.append({
                "field":    "same_country",
                "label":    f"Country: {geo.get('country', '?')}",
                "points":   pts,
                "category": "Geo",
                "note":     f"City: {geo.get('city','?')} · ISP: {geo.get('isp','?')}",
            })

        if same_ip:
            pts = 7
            points += pts
            breakdown.append({
                "field":    "same_ip",
                "label":    f"IP Resolved: {ip}",
                "points":   pts,
                "category": "Geo",
                "note":     "Resolved via reverse_ip.py",
            })

        if same_isp:
            pts = 5
            points += pts
            breakdown.append({
                "field":    "same_isp",
                "label":    f"ISP: {geo.get('isp','?')}",
                "points":   pts,
                "category": "Geo",
                "note":     "ISP-level data from geo.py",
            })

    # ─────────────────────────────────────────────
    # 3b. PHONE-SPECIFIC GEO/CARRIER SIGNALS
    #     Replaces the domain-style Geo block above when the
    #     target is a phone number.
    # ─────────────────────────────────────────────

    if target_type == "phone" and isinstance(phone, dict) and phone.get("valid"):
        if phone.get("country_name"):
            pts = 6
            points += pts
            breakdown.append({
                "field":    "phone_country",
                "label":    f"Country: {phone.get('country_name')}",
                "points":   pts,
                "category": "Geo",
                "note":     f"Region: {phone.get('region','?')}",
            })
        if phone.get("carrier_name"):
            pts = 5
            points += pts
            breakdown.append({
                "field":    "phone_carrier",
                "label":    f"Carrier: {phone.get('carrier_name')}",
                "points":   pts,
                "category": "Geo",
                "note":     "Carrier resolved via phonenumbers",
            })
        voip = phone.get("voip") or {}
        if isinstance(voip, dict) and voip.get("available") and voip.get("is_voip"):
            pts = 4
            points += pts
            breakdown.append({
                "field":    "phone_voip",
                "label":    "VOIP / Virtual Number",
                "points":   pts,
                "category": "Geo",
                "note":     voip.get("note", ""),
            })

    # ─────────────────────────────────────────────
    # 4. BREACH & LEAK CORRELATION       (max 20)
    #    Applies to all target types
    # ─────────────────────────────────────────────

    breach_list = result.get("breach") or []
    if breach_list:
        pts = min(10, len(breach_list) * 3)
        points += pts
        breakdown.append({
            "field":    "breach",
            "label":    "Breach Hits",
            "points":   pts,
            "category": "Exposure",
            "note":     f"{len(breach_list)} breach(es) from leak_checker.py",
        })

    leak = result.get("leak") or {}
    if isinstance(leak, dict):
        total_leaks = leak.get("total_leaks", 0)
        if total_leaks > 0:
            pts = min(10, total_leaks * 2)
            points += pts
            breakdown.append({
                "field":    "leak",
                "label":    "Leak Database Hits",
                "points":   pts,
                "category": "Exposure",
                "note":     f"{total_leaks} record(s) from leak_checker.check_all()",
            })

    # ─────────────────────────────────────────────
    # 5. DARK WEB & PASTE EXPOSURE       (max 10)
    #    Applies to all target types
    # ─────────────────────────────────────────────

    dark = result.get("dark") or {}
    if isinstance(dark, dict) and dark.get("flagged"):
        pts = 5
        points += pts
        breakdown.append({
            "field":    "dark",
            "label":    "Dark Web Flagged",
            "points":   pts,
            "category": "Exposure",
            "note":     "Target flagged by dark_monitor.py",
        })

    paste = result.get("paste_monitor") or {}
    if isinstance(paste, dict):
        total_paste = paste.get("total_found", 0)
        if total_paste > 0:
            pts = min(5, total_paste * 2)
            points += pts
            breakdown.append({
                "field":    "paste_monitor",
                "label":    "Paste Monitor Hits",
                "points":   pts,
                "category": "Exposure",
                "note":     f"{total_paste} mention(s) from paste_monitor.py",
            })

    # ─────────────────────────────────────────────
    # 6. THREAT INTELLIGENCE BONUS
    #    Applies to all target types
    # ─────────────────────────────────────────────

    threat_score = dark.get("threat_score", 0) if isinstance(dark, dict) else 0
    if threat_score >= 60:
        pts = 5
        points += pts
        breakdown.append({
            "field":    "threat_score",
            "label":    f"High Threat Score ({threat_score}/100)",
            "points":   pts,
            "category": "Threat",
            "note":     "Threat score from dark_monitor.py",
        })

    # ─────────────────────────────────────────────
    # 6b. PHONE-SPECIFIC THREAT BONUS
    # ─────────────────────────────────────────────

    if target_type == "phone" and isinstance(phone, dict):
        scam = phone.get("scam") or {}
        if isinstance(scam, dict) and scam.get("available"):
            if scam.get("fraud_score") == "High":
                pts = 8
                points += pts
                breakdown.append({
                    "field":    "phone_fraud_score",
                    "label":    "High Fraud Score",
                    "points":   pts,
                    "category": "Threat",
                    "note":     scam.get("note", ""),
                })
            elif scam.get("fraud_score") == "Medium":
                pts = 4
                points += pts
                breakdown.append({
                    "field":    "phone_fraud_score",
                    "label":    "Medium Fraud Score",
                    "points":   pts,
                    "category": "Threat",
                    "note":     scam.get("note", ""),
                })

    # ─────────────────────────────────────────────
    # 7. FINALISE
    # ─────────────────────────────────────────────

    total = min(points, 100)

    if total >= 80:
        confidence, color = "HIGH",    "red"
    elif total >= 50:
        confidence, color = "MEDIUM",  "yellow"
    elif total >= 25:
        confidence, color = "LOW",     "blue"
    else:
        confidence, color = "MINIMAL", "green"

    return {
        "total":       total,
        "confidence":  confidence,
        "color":       color,
        "breakdown":   breakdown,
        "target_type": target_type,
        "signals": {
            "identity": sum(b["points"] for b in breakdown if b["category"] == "Identity"),
            "contact":  sum(b["points"] for b in breakdown if b["category"] == "Contact"),
            "geo":      sum(b["points"] for b in breakdown if b["category"] == "Geo"),
            "exposure": sum(b["points"] for b in breakdown if b["category"] == "Exposure"),
            "threat":   sum(b["points"] for b in breakdown if b["category"] == "Threat"),
        },
    }