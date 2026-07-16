"""
modules/investigation/entity_correlation.py

Entity Correlation Engine — Phase 4.

Takes a scan_data blob (the same dict run_osint_scan() produces, and what's
stored on Case.scan_data as JSON) and derives a directed graph connecting
every entity discovered during the scan:

    Email  →  Username  →  GitHub/Platform  →  Domain  →  IP  →  Geo

Not every scan produces every link — the graph only includes edges backed
by actual data found in the scan. Output is a {nodes, links} structure
compatible with the existing static/graph.js force-directed renderer, plus
a plain-text chain representation for display/export:

    Email
      ↓
    Username
      ↓
    GitHub
      ↓
    Domain
"""

import re
import json
from datetime import datetime


# ---------------------------------------------------------------------------
# Node type -> display metadata (color/shape hints consumed by graph.js)
# ---------------------------------------------------------------------------
NODE_TYPES = {
    "target":     {"color": "#00ff6a", "group": 0, "label": "Target"},
    "email":      {"color": "#44aaff", "group": 1, "label": "Email"},
    "username":   {"color": "#b388ff", "group": 2, "label": "Username"},
    "platform":   {"color": "#ffaa00", "group": 3, "label": "Platform"},
    "domain":     {"color": "#00ff6a", "group": 4, "label": "Domain"},
    "subdomain":  {"color": "#00c94f", "group": 5, "label": "Subdomain"},
    "ip":         {"color": "#ff7700", "group": 6, "label": "IP Address"},
    "geo":        {"color": "#44aaff", "group": 7, "label": "Location"},
    "phone":      {"color": "#b388ff", "group": 8, "label": "Phone"},
    "breach":     {"color": "#ff4444", "group": 9, "label": "Breach"},
    "threat":     {"color": "#ff4444", "group": 10, "label": "Threat"},
    "dns":        {"color": "#44aaff", "group": 11, "label": "DNS Record"},
    "ssl":        {"color": "#ffaa00", "group": 12, "label": "SSL/TLS"},
    "tech":       {"color": "#b388ff", "group": 13, "label": "Technology"},
}


def _node_meta(node_type: str) -> dict:
    return NODE_TYPES.get(node_type, {"color": "#5a6b5a", "group": 99, "label": "Other"})


def _is_email(value: str) -> bool:
    return bool(value) and "@" in value and "." in value.split("@")[-1]


def _is_domain(value: str) -> bool:
    return bool(value) and "." in value and not _is_email(value)


def _is_ip(value: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value or ""))


class EntityGraph:
    """Accumulates unique nodes/links while building the correlation chain."""

    def __init__(self):
        self._nodes = {}   # id -> node dict (dedup by id)
        self._links = []   # list of {source, target, relation}
        self._chain = []   # ordered list of (label, node_id) for the text chain view

    def add_node(self, node_id: str, node_type: str, extra: dict = None):
        node_id = str(node_id).strip()
        if not node_id or node_id in self._nodes:
            return node_id
        meta = _node_meta(node_type)
        self._nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "label": meta["label"],
            "color": meta["color"],
            "group": meta["group"],
            **(extra or {}),
        }
        return node_id

    def add_link(self, source_id: str, target_id: str, relation: str = ""):
        if not source_id or not target_id or source_id == target_id:
            return
        pair = (source_id, target_id)
        if any((l["source"], l["target"]) == pair for l in self._links):
            return
        self._links.append({"source": source_id, "target": target_id, "relation": relation})

    def add_chain_step(self, label: str, node_id: str):
        self._chain.append((label, node_id))

    def to_dict(self) -> dict:
        return {
            "nodes": list(self._nodes.values()),
            "links": self._links,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def to_text_chain(self) -> str:
        if not self._chain:
            return "(no correlated entities found)"
        lines = []
        for i, (label, _node_id) in enumerate(self._chain):
            lines.append(label)
            if i < len(self._chain) - 1:
                lines.append("  ↓")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------
def build_entity_graph(scan_data: dict) -> dict:
    """
    Correlates all entities found in a single scan_data dict into a directed
    graph. Returns {"nodes": [...], "links": [...], "chain_text": "..."}.
    """
    g = EntityGraph()

    if not scan_data or not isinstance(scan_data, dict):
        return {"nodes": [], "links": [], "chain_text": "(no scan data available)"}

    target = scan_data.get("target", "")
    target_id = g.add_node(target, "target")
    if target:
        g.add_chain_step(f"Target: {target}", target_id)

    # ---- Determine entry point type and set up the primary chain -----------
    if _is_email(target):
        # Email -> Username -> Platform -> Domain -> IP
        email_id = g.add_node(target, "email")
        g.add_link(target_id, email_id, "is")

        domain_part = target.split("@")[-1]

        # Email -> Username(s) discovered
        usernames = scan_data.get("username") or []
        first_username_id = None
        for u in usernames[:15]:
            uname = u.get("name") if isinstance(u, dict) else str(u)
            platform = u.get("category") or u.get("platform") if isinstance(u, dict) else None
            url = u.get("url") if isinstance(u, dict) else None
            if not uname:
                continue
            uname_id = g.add_node(uname, "username", {"url": url or ""})
            g.add_link(email_id, uname_id, "linked_to")
            if first_username_id is None:
                first_username_id = uname_id
                g.add_chain_step(f"Username: {uname}", uname_id)
            if platform:
                plat_id = g.add_node(platform, "platform")
                g.add_link(uname_id, plat_id, "found_on")
                if len(g._chain) < 3:
                    g.add_chain_step(f"Platform: {platform}", plat_id)

        # Email's domain part
        dom_id = g.add_node(domain_part, "domain")
        g.add_link(email_id, dom_id, "domain_of")
        g.add_chain_step(f"Domain: {domain_part}", dom_id)

        ip = scan_data.get("ip")
        if ip and ip != "Not found":
            ip_id = g.add_node(ip, "ip")
            g.add_link(dom_id, ip_id, "resolves_to")
            g.add_chain_step(f"IP: {ip}", ip_id)

    elif _is_domain(target):
        # Domain -> IP -> Geo, plus Domain -> Subdomains, Domain -> Employees(usernames)
        dom_id = g.add_node(target, "domain")

        ip = scan_data.get("ip")
        if ip and ip != "Not found":
            ip_id = g.add_node(ip, "ip")
            g.add_link(dom_id, ip_id, "resolves_to")
            g.add_chain_step(f"IP: {ip}", ip_id)

            geo = scan_data.get("geo") or {}
            if isinstance(geo, dict):
                geo_label = geo.get("city") or geo.get("country")
                if geo_label:
                    geo_id = g.add_node(geo_label, "geo")
                    g.add_link(ip_id, geo_id, "located_in")
                    g.add_chain_step(f"Location: {geo_label}", geo_id)

        for sub in (scan_data.get("subs") or [])[:20]:
            sub_id_val = sub if isinstance(sub, str) else sub.get("host", str(sub))
            sub_id = g.add_node(sub_id_val, "subdomain")
            g.add_link(dom_id, sub_id, "subdomain_of")

        usernames = scan_data.get("username") or scan_data.get("employee", {}).get("usernames", [])
        for u in (usernames or [])[:10]:
            uname = u.get("name") if isinstance(u, dict) else str(u)
            if uname:
                uname_id = g.add_node(uname, "username")
                g.add_link(dom_id, uname_id, "associated_with")

    elif _is_ip(target):
        ip_id = g.add_node(target, "ip")
        geo = scan_data.get("geo") or {}
        if isinstance(geo, dict):
            geo_label = geo.get("city") or geo.get("country")
            if geo_label:
                geo_id = g.add_node(geo_label, "geo")
                g.add_link(ip_id, geo_id, "located_in")
                g.add_chain_step(f"Location: {geo_label}", geo_id)

    else:
        # Treat as a bare username: Username -> Platforms -> (any domains found)
        uname_id = g.add_node(target, "username")
        for u in (scan_data.get("username") or [])[:15]:
            uname = u.get("name") if isinstance(u, dict) else str(u)
            platform = u.get("category") if isinstance(u, dict) else None
            url = u.get("url") if isinstance(u, dict) else None
            if uname and uname.lower() != str(target).lower():
                other_id = g.add_node(uname, "username", {"url": url or ""})
                g.add_link(uname_id, other_id, "also_known_as")
            elif platform:
                plat_id = g.add_node(platform, "platform")
                g.add_link(uname_id, plat_id, "found_on")
                if len(g._chain) < 3:
                    g.add_chain_step(f"Platform: {platform}", plat_id)

    # ---- Cross-cutting correlations added regardless of entry type ---------
    for b in (scan_data.get("breach") or [])[:10]:
        b_label = b.get("name") if isinstance(b, dict) else str(b)
        if b_label:
            b_id = g.add_node(b_label, "breach")
            g.add_link(target_id, b_id, "exposed_in")

    dark = scan_data.get("dark") or {}
    if isinstance(dark, dict) and dark.get("flagged"):
        for f in (dark.get("findings") or [])[:5]:
            label = f.get("malware") or f.get("threat_type") or f.get("threat") if isinstance(f, dict) else str(f)
            if label:
                t_id = g.add_node(f"⚠ {label}", "threat")
                g.add_link(target_id, t_id, "flagged_for")

    tech = scan_data.get("tech") or {}
    if isinstance(tech, dict):
        for cat in ("cms", "cdn", "framework"):
            for item in (tech.get(cat) or [])[:3]:
                tech_id = g.add_node(item, "tech")
                g.add_link(target_id, tech_id, "uses")

    result = g.to_dict()
    result["chain_text"] = g.to_text_chain()
    return result


def correlate_case(case) -> dict:
    """
    Convenience wrapper: takes a Case row (or dict with a 'scan_data' key,
    either as a JSON string or already-parsed dict) and returns the
    entity correlation graph for it.
    """
    scan_data = {}
    raw = None
    if hasattr(case, "scan_data"):
        raw = case.scan_data
    elif isinstance(case, dict):
        raw = case.get("scan_data")

    if isinstance(raw, str):
        try:
            scan_data = json.loads(raw or "{}")
        except (TypeError, ValueError):
            scan_data = {}
    elif isinstance(raw, dict):
        scan_data = raw

    return build_entity_graph(scan_data)