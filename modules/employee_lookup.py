"""
employee_lookup.py — Employee enumeration and public company footprint
Sources: LinkedIn public search, GitHub org members, Hunter.io pattern detection,
         email pattern generation, company social profiles
"""

import urllib.request
import urllib.parse
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Employee:
    name: str = ""
    title: str = ""
    linkedin_url: str = ""
    github_username: str = ""
    email_guess: str = ""
    source: str = ""


@dataclass
class EmailPattern:
    pattern: str = ""           # e.g. "firstname.lastname@domain.com"
    example: str = ""
    confidence: str = ""        # high / medium / low


@dataclass
class EmployeeLookup:
    domain: str
    company_name: str = ""
    employees: list = field(default_factory=list)       # Employee dicts
    email_patterns: list = field(default_factory=list)  # EmailPattern dicts
    email_guesses: list = field(default_factory=list)
    github_org_members: list = field(default_factory=list)
    social_profiles: dict = field(default_factory=dict)
    tech_emails: list = field(default_factory=list)     # generic: info@, admin@, etc.
    total_found: int = 0
    sources_checked: list = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self):
        return asdict(self)


# ── Common generic email prefixes ─────────────────────────────────────────
GENERIC_EMAILS = [
    "admin", "info", "contact", "support", "security", "abuse",
    "noc", "webmaster", "postmaster", "help", "hr", "jobs",
    "careers", "sales", "marketing", "legal", "privacy",
]

# ── Common email format patterns ──────────────────────────────────────────
EMAIL_PATTERNS = [
    ("{first}.{last}@{domain}",       "John.Smith@domain.com",   "high"),
    ("{first}{last}@{domain}",        "JohnSmith@domain.com",    "medium"),
    ("{first}@{domain}",              "john@domain.com",         "medium"),
    ("{f}{last}@{domain}",            "jsmith@domain.com",       "high"),
    ("{first}.{l}@{domain}",          "john.s@domain.com",       "low"),
    ("{last}.{first}@{domain}",       "smith.john@domain.com",   "low"),
    ("{first}_{last}@{domain}",       "john_smith@domain.com",   "low"),
]


def _fetch(url: str, timeout: int = 8) -> str:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/120 Safari/537.36"
                )
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _fetch_json(url: str, timeout: int = 8) -> Optional[dict]:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "OSINT-Research/1.0",
                          "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _extract_company_name(domain: str) -> str:
    """Best-guess company name from domain."""
    name = domain.split(".")[0]
    return name.replace("-", " ").replace("_", " ").title()


def _github_org_members(org_name: str) -> list:
    """Fetch public members of a GitHub organisation."""
    members = []
    data = _fetch_json(f"https://api.github.com/orgs/{org_name}/members?per_page=30")
    if isinstance(data, list):
        for m in data[:30]:
            members.append({
                "github_username": m.get("login", ""),
                "github_url": m.get("html_url", ""),
                "avatar": m.get("avatar_url", ""),
            })
    return members


def _generate_tech_emails(domain: str) -> list:
    """Generate standard generic/tech email addresses."""
    return [f"{prefix}@{domain}" for prefix in GENERIC_EMAILS]


def _generate_email_patterns(domain: str) -> list:
    """Return email format pattern objects for the domain."""
    patterns = []
    for fmt, example_tpl, confidence in EMAIL_PATTERNS:
        example = (
            example_tpl.replace("domain.com", domain)
            .replace("Domain.Com", domain)
        )
        pattern_str = fmt.replace("{domain}", domain)
        patterns.append(EmailPattern(
            pattern=pattern_str,
            example=example,
            confidence=confidence,
        ))
    return patterns


def _guess_emails_from_names(names: list, domain: str) -> list:
    """
    Given a list of full names, generate likely email addresses
    using the most common patterns.
    """
    guesses = []
    for full_name in names[:20]:
        parts = full_name.strip().lower().split()
        if len(parts) < 2:
            continue
        first, last = parts[0], parts[-1]
        f = first[0] if first else ""
        l = last[0] if last else ""
        candidates = [
            f"{first}.{last}@{domain}",
            f"{f}{last}@{domain}",
            f"{first}@{domain}",
            f"{first}{last}@{domain}",
        ]
        guesses.extend(candidates)
    return guesses


def _certspotter_names(domain: str) -> list:
    """
    Extract potential employee names from certificate SAN entries.
    (crt.sh is a public CT log)
    """
    names = []
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        data = _fetch_json(url)
        if isinstance(data, list):
            for entry in data[:50]:
                cn = entry.get("common_name", "")
                # Extract human-readable names from cert CNs (e.g. "John Smith")
                if cn and not cn.startswith("*") and "." not in cn.split(" ")[0]:
                    if re.match(r"^[A-Za-z]+ [A-Za-z]+$", cn.strip()):
                        names.append(cn.strip())
    except Exception:
        pass
    return list(set(names))[:20]


def lookup(domain: str, github_org: Optional[str] = None) -> EmployeeLookup:
    """
    Main entry point.

    Args:
        domain:     Target domain (e.g. 'company.com')
        github_org: Optional GitHub org name if different from domain stem
    """
    domain = domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]
    result = EmployeeLookup(domain=domain)
    result.company_name = _extract_company_name(domain)

    # ── Generic tech emails ────────────────────────────────────────────────
    result.tech_emails = _generate_tech_emails(domain)
    result.sources_checked.append("Generated generic emails")

    # ── Email format patterns ──────────────────────────────────────────────
    result.email_patterns = [asdict(p) for p in _generate_email_patterns(domain)]

    # ── GitHub org members ─────────────────────────────────────────────────
    org = github_org or domain.split(".")[0]
    members = _github_org_members(org)
    if members:
        result.github_org_members = members
        result.sources_checked.append(f"GitHub Org: {org}")

        # Convert GH members to Employee entries
        for m in members:
            result.employees.append(asdict(Employee(
                github_username=m["github_username"],
                source="GitHub",
            )))

    # ── Name extraction from CT logs ───────────────────────────────────────
    names_from_certs = _certspotter_names(domain)
    if names_from_certs:
        result.sources_checked.append("Certificate Transparency Logs")
        for name in names_from_certs:
            # Check if not already in employees
            existing = {e.get("name") for e in result.employees}
            if name not in existing:
                result.employees.append(asdict(Employee(name=name, source="CT Logs")))

        # Generate email guesses from extracted names
        result.email_guesses = _guess_emails_from_names(names_from_certs, domain)

    # ── Social profiles ────────────────────────────────────────────────────
    stem = domain.split(".")[0]
    result.social_profiles = {
        "linkedin":  f"https://www.linkedin.com/company/{stem}",
        "twitter":   f"https://twitter.com/{stem}",
        "github":    f"https://github.com/{org}",
        "facebook":  f"https://facebook.com/{stem}",
        "instagram": f"https://instagram.com/{stem}",
    }
    result.sources_checked.append("Social profile URLs generated")

    result.total_found = len(result.employees)
    return result