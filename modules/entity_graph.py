"""
entity_graph.py — Builds a nodes/links entity-relationship graph from a
completed scan result. Pure aggregation, no external calls.

Output shape matches what your existing /graph endpoint and graph.js
already expect:
    {"nodes": [{"id": ..., "type": ...}, ...], "links": [{"source": ..., "target": ...}, ...]}

This is a superset of the existing /graph route — it additionally pulls in
phone metadata, related_entities (emails/domains/usernames), and IOC tags
so the whole entity picture is in one graph.
"""

from __future__ import annotations


def _add_node(nodes: list, seen: set, node_id: str, node_type: str):
    if not node_id or node_id in seen:
        return
    seen.add(node_id)
    nodes.append({"id": node_id, "type": node_type})


def _add_link(links: list, source: str, target: str):
    if source and target:
        links.append({"source": source, "target": target})


def build_entity_graph(target: str, result: dict) -> dict:
    nodes: list = []
    links: list = []
    seen: set = set()

    _add_node(nodes, seen, target, "target")

    # ── IP / Geo ──────────────────────────────────────────────────────
    ip = result.get("ip")
    if ip and ip != "Not found":
        _add_node(nodes, seen, ip, "ip")
        _add_link(links, target, ip)
        geo = result.get("geo") or {}
        if isinstance(geo, dict):
            geo_label = geo.get("city") or geo.get("country") or ""
            if geo_label:
                _add_node(nodes, seen, geo_label, "geo")
                _add_link(links, ip, geo_label)

    # ── Subdomains ────────────────────────────────────────────────────
    for s in (result.get("subs") or [])[:30]:
        host = s.get("host", str(s)) if isinstance(s, dict) else s
        _add_node(nodes, seen, host, "subdomain")
        _add_link(links, target, host)

    # ── Breaches ──────────────────────────────────────────────────────
    for b in (result.get("breach") or [])[:10]:
        b_id = (b.get("name") or b.get("breach_name") or "Unknown breach") if isinstance(b, dict) else str(b)
        _add_node(nodes, seen, b_id, "breach")
        _add_link(links, target, b_id)

    # ── Usernames ─────────────────────────────────────────────────────
    for u in (result.get("username") or [])[:15]:
        u_id = (u.get("name") or u.get("url") or str(u)) if isinstance(u, dict) else str(u)
        _add_node(nodes, seen, u_id, "username")
        _add_link(links, target, u_id)

    # ── Phone metadata ────────────────────────────────────────────────
    phone = result.get("phone") or {}
    if isinstance(phone, dict) and phone.get("valid"):
        ph_label = phone.get("international") or phone.get("e164") or "Phone"
        _add_node(nodes, seen, ph_label, "phone")
        _add_link(links, target, ph_label)

        if phone.get("carrier_name"):
            _add_node(nodes, seen, phone["carrier_name"], "carrier")
            _add_link(links, ph_label, phone["carrier_name"])

        if phone.get("region"):
            _add_node(nodes, seen, phone["region"], "geo")
            _add_link(links, ph_label, phone["region"])

        corr = phone.get("correlation") or {}
        for u in (corr.get("usernames") or [])[:10]:
            u_id = u.get("name") if isinstance(u, dict) else u
            if u_id:
                _add_node(nodes, seen, u_id, "username")
                _add_link(links, ph_label, u_id)
        for lk in (corr.get("leaks") or [])[:10]:
            lk_id = (lk.get("breach_name") or lk.get("name")) if isinstance(lk, dict) else lk
            if lk_id:
                _add_node(nodes, seen, lk_id, "breach")
                _add_link(links, ph_label, lk_id)

    # ── Related entities (emails / domains / usernames / cases) ─────────
    rel = result.get("related_entities") or {}
    if isinstance(rel, dict):
        for e in rel.get("emails") or []:
            _add_node(nodes, seen, e, "email")
            _add_link(links, target, e)
        for d in rel.get("domains") or []:
            _add_node(nodes, seen, d, "domain")
            _add_link(links, target, d)
        for c in rel.get("previous_cases") or []:
            label = f"Case #{c.get('id')}" if isinstance(c, dict) else str(c)
            _add_node(nodes, seen, label, "case")
            _add_link(links, target, label)

    # ── DNS ───────────────────────────────────────────────────────────
    dns = result.get("dns") or {}
    if isinstance(dns, dict):
        for ns in (dns.get("ns") or [])[:5]:
            _add_node(nodes, seen, ns, "dns_ns")
            _add_link(links, target, ns)
        for mx in (dns.get("mx") or [])[:3]:
            mx_host = mx.get("host", str(mx)) if isinstance(mx, dict) else str(mx)
            _add_node(nodes, seen, mx_host, "dns_mx")
            _add_link(links, target, mx_host)

    # ── Tech / Cloud ──────────────────────────────────────────────────
    tech = result.get("tech") or {}
    if isinstance(tech, dict):
        for cat in ("cms", "cdn", "framework"):
            for item in (tech.get(cat) or [])[:2]:
                _add_node(nodes, seen, item, "tech")
                _add_link(links, target, item)

    cloud = result.get("cloud") or {}
    if isinstance(cloud, dict) and cloud.get("primary_provider") and \
            cloud["primary_provider"] != "Unknown / Self-hosted":
        _add_node(nodes, seen, cloud["primary_provider"], "tech")
        _add_link(links, target, cloud["primary_provider"])

    # ── SSL ───────────────────────────────────────────────────────────
    ssl = result.get("ssl") or {}
    if isinstance(ssl, dict) and ssl.get("issuer_o"):
        _add_node(nodes, seen, ssl["issuer_o"], "ssl")
        _add_link(links, target, ssl["issuer_o"])

    # ── Threats (VT / OTX / dark monitor) ────────────────────────────
    dark = result.get("dark") or {}
    if isinstance(dark, dict):
        for f in (dark.get("findings") or [])[:5]:
            if isinstance(f, dict):
                label = f.get("malware") or f.get("threat_type") or f.get("threat") or ""
                if label and "error" not in f:
                    node_id = f"⚠ {label}"
                    _add_node(nodes, seen, node_id, "threat")
                    _add_link(links, target, node_id)

    vt = result.get("virustotal") or {}
    if isinstance(vt, dict) and vt.get("malicious", 0) > 0:
        for name in (vt.get("threat_names") or [])[:3]:
            node_id = f"🦠 {name}"
            _add_node(nodes, seen, node_id, "threat")
            _add_link(links, target, node_id)

    otx = result.get("otx") or {}
    if isinstance(otx, dict) and otx.get("pulse_count", 0) > 0:
        for mf in (otx.get("malware_families") or [])[:3]:
            node_id = f"⚡ {mf}"
            _add_node(nodes, seen, node_id, "threat")
            _add_link(links, target, node_id)

    # ── IOC tags ──────────────────────────────────────────────────────
    ioc = result.get("ioc") or {}
    if isinstance(ioc, dict):
        for tag in (ioc.get("tags") or [])[:5]:
            node_id = f"🏷 {tag}"
            _add_node(nodes, seen, node_id, "tag")
            _add_link(links, target, node_id)

    return {"nodes": nodes, "links": links, "target": target}