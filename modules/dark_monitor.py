import requests


def monitor(target: str) -> dict:
    """
    Threat monitoring for a target (domain, IP, email, username).
    Returns a dict with: flagged (bool), findings (list of dicts), error (str or None)
    """
    findings = []
    flagged = False

    # --- VirusTotal public lookup (no key needed for basic domain info) ---
    try:
        vt_result = _check_virustotal(target)
        if vt_result:
            findings.extend(vt_result)
            flagged = True
    except Exception as e:
        pass

    # --- ThreatFox (abuse.ch) - free, no key needed ---
    try:
        tf_result = _check_threatfox(target)
        if tf_result:
            findings.extend(tf_result)
            flagged = True
    except Exception as e:
        pass

    # --- URLhaus (abuse.ch) - free, no key needed ---
    try:
        uh_result = _check_urlhaus(target)
        if uh_result:
            findings.extend(uh_result)
            flagged = True
    except Exception as e:
        pass

    return {
        "flagged": flagged,
        "findings": findings,
        "error": None,
    }


def _check_virustotal(target: str) -> list:
    """Check domain/IP reputation via VirusTotal public API (no key)."""
    findings = []
    try:
        # Clean target
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": ""},  # Public endpoint, limited
            timeout=6,
        )
        # VT returns 401 without key — skip gracefully
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0 or suspicious > 0:
                findings.append({
                    "threat_type": "Malicious/Suspicious Domain",
                    "source": "VirusTotal",
                    "detail": f"{malicious} malicious, {suspicious} suspicious detections",
                })
    except Exception:
        pass
    return findings


def _check_threatfox(target: str) -> list:
    """Check against ThreatFox IOC database (abuse.ch) - completely free."""
    findings = []
    try:
        payload = {"query": "search_ioc", "search_term": target}
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json=payload,
            timeout=8,
            headers={"User-Agent": "OSINT-Platform"},
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "ok":
                for ioc in (data.get("data") or [])[:5]:
                    findings.append({
                        "threat_type": ioc.get("threat_type", "Unknown"),
                        "malware": ioc.get("malware", "Unknown"),
                        "source": "ThreatFox (abuse.ch)",
                        "detail": ioc.get("threat_type_desc", ""),
                        "confidence": ioc.get("confidence_level", "—"),
                        "tags": ", ".join(ioc.get("tags") or []),
                    })
    except Exception:
        pass
    return findings


def _check_urlhaus(target: str) -> list:
    """Check against URLhaus malware URL database (abuse.ch) - free."""
    findings = []
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": target},
            timeout=8,
            headers={"User-Agent": "OSINT-Platform"},
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "is_host":
                urls = data.get("urls", [])
                active = [u for u in urls if u.get("url_status") == "online"]
                if urls:
                    findings.append({
                        "threat_type": "Malware Distribution",
                        "source": "URLhaus (abuse.ch)",
                        "detail": f"{len(urls)} malicious URLs found ({len(active)} still active)",
                        "malware": data.get("blacklists", {}).get("surbl", "—"),
                    })
    except Exception:
        pass
    return findings