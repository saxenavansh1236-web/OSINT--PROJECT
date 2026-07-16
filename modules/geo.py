import socket
import requests


def resolve_ip(target: str) -> str:
    """Resolve domain/hostname to IP address."""
    try:
        # If it already looks like an IP, return as-is
        parts = target.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return target
        return socket.gethostbyname(target)
    except Exception:
        return None


def locate(ip_or_domain: str) -> dict:
    """
    Get geolocation for an IP or domain using ip-api.com (free, no key needed).
    Automatically resolves domains to IPs.
    """
    if not ip_or_domain or ip_or_domain in ("Not found", "Not Found", ""):
        return {}

    # Resolve domain to IP if needed
    ip = resolve_ip(ip_or_domain)
    if not ip:
        return {"error": f"Could not resolve {ip_or_domain} to an IP address"}

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=6,
            params={
                "fields": "status,message,country,regionName,city,isp,org,lat,lon,query,as"
            },
        )
        data = r.json()

        if data.get("status") == "success":
            return {
                "ip":         data.get("query", ip),
                "country":    data.get("country", "—"),
                "regionName": data.get("regionName", "—"),
                "city":       data.get("city", "—"),
                "isp":        data.get("isp", "—"),
                "org":        data.get("org", "—"),
                "as":         data.get("as", "—"),
                "lat":        data.get("lat", ""),
                "lon":        data.get("lon", ""),
            }
        else:
            return {"error": data.get("message", "Geolocation lookup failed")}

    except requests.exceptions.Timeout:
        return {"error": "Geolocation request timed out"}
    except Exception as e:
        return {"error": str(e)}