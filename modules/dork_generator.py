"""
dork_generator.py
Generates Google dork queries for a target (domain, email, phone, username).
No API key needed — generates query strings ready to use in Google Search.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DorkResult:
    target:      str  = ""
    target_type: str  = ""
    dorks:       list = field(default_factory=list)   # list of {category, query, description, url}
    total:       int  = 0
    error:       Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _google_url(query: str) -> str:
    import urllib.parse
    return f"https://www.google.com/search?q={urllib.parse.quote(query)}"


def _detect_type(target: str) -> str:
    if "@" in target and "." in target.split("@")[-1]:
        return "email"
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, target):
        return "ip"
    cleaned = re.sub(r"[\s\-().]+", "", target)
    if re.match(r"^\+?\d{7,15}$", cleaned):
        return "phone"
    if "." in target:
        return "domain"
    return "username"


def _domain_dorks(domain: str) -> list:
    base = domain.rstrip("/").replace("https://", "").replace("http://", "")
    dorks = [
        # Information Gathering
        {
            "category":    "Info Gathering",
            "query":       f"site:{base}",
            "description": "All indexed pages on the domain",
        },
        {
            "category":    "Info Gathering",
            "query":       f"site:{base} -www",
            "description": "Indexed pages excluding www subdomain",
        },
        {
            "category":    "Info Gathering",
            "query":       f"info:{base}",
            "description": "Google's cached info about the domain",
        },
        {
            "category":    "Info Gathering",
            "query":       f"link:{base}",
            "description": "Pages that link to this domain",
        },
        {
            "category":    "Info Gathering",
            "query":       f"related:{base}",
            "description": "Similar/related websites",
        },
        # Subdomains
        {
            "category":    "Subdomains",
            "query":       f"site:*.{base}",
            "description": "All subdomains indexed by Google",
        },
        {
            "category":    "Subdomains",
            "query":       f"site:*.{base} -www",
            "description": "Subdomains excluding www",
        },
        # Sensitive Files
        {
            "category":    "Sensitive Files",
            "query":       f"site:{base} filetype:pdf",
            "description": "PDF documents on the domain",
        },
        {
            "category":    "Sensitive Files",
            "query":       f"site:{base} filetype:sql",
            "description": "SQL database files",
        },
        {
            "category":    "Sensitive Files",
            "query":       f"site:{base} filetype:xls OR filetype:xlsx",
            "description": "Excel spreadsheets",
        },
        {
            "category":    "Sensitive Files",
            "query":       f"site:{base} filetype:doc OR filetype:docx",
            "description": "Word documents",
        },
        {
            "category":    "Sensitive Files",
            "query":       f"site:{base} filetype:env OR filetype:config",
            "description": "Config and environment files",
        },
        {
            "category":    "Sensitive Files",
            "query":       f"site:{base} filetype:log",
            "description": "Log files",
        },
        {
            "category":    "Sensitive Files",
            "query":       f"site:{base} filetype:bak OR filetype:backup",
            "description": "Backup files",
        },
        # Login & Admin
        {
            "category":    "Login / Admin",
            "query":       f'site:{base} inurl:admin',
            "description": "Admin panel pages",
        },
        {
            "category":    "Login / Admin",
            "query":       f'site:{base} inurl:login',
            "description": "Login pages",
        },
        {
            "category":    "Login / Admin",
            "query":       f'site:{base} inurl:dashboard',
            "description": "Dashboard pages",
        },
        {
            "category":    "Login / Admin",
            "query":       f'site:{base} inurl:wp-admin',
            "description": "WordPress admin pages",
        },
        {
            "category":    "Login / Admin",
            "query":       f'site:{base} inurl:phpmyadmin',
            "description": "phpMyAdmin installations",
        },
        # Sensitive Content
        {
            "category":    "Sensitive Content",
            "query":       f'site:{base} intext:password',
            "description": "Pages containing the word password",
        },
        {
            "category":    "Sensitive Content",
            "query":       f'site:{base} intext:"username" intext:"password"',
            "description": "Pages with username and password fields",
        },
        {
            "category":    "Sensitive Content",
            "query":       f'site:{base} intext:"api_key" OR intext:"api key" OR intext:"apikey"',
            "description": "Exposed API keys",
        },
        {
            "category":    "Sensitive Content",
            "query":       f'site:{base} intext:"secret_key" OR intext:"secret key"',
            "description": "Exposed secret keys",
        },
        {
            "category":    "Sensitive Content",
            "query":       f'site:{base} intext:"private key"',
            "description": "Pages mentioning private keys",
        },
        # Directories
        {
            "category":    "Directories",
            "query":       f'site:{base} intitle:"index of"',
            "description": "Open directory listings",
        },
        {
            "category":    "Directories",
            "query":       f'site:{base} intitle:"index of" "parent directory"',
            "description": "Open parent directory listings",
        },
        # Mentions
        {
            "category":    "Mentions",
            "query":       f'"{base}" -site:{base}',
            "description": "Mentions of the domain on other sites",
        },
        {
            "category":    "Mentions",
            "query":       f'"{base}" site:github.com',
            "description": "Domain mentioned on GitHub",
        },
        {
            "category":    "Mentions",
            "query":       f'"{base}" site:pastebin.com',
            "description": "Domain mentioned on Pastebin",
        },
        {
            "category":    "Mentions",
            "query":       f'"{base}" site:reddit.com',
            "description": "Domain mentioned on Reddit",
        },
        # Tech Stack
        {
            "category":    "Tech Stack",
            "query":       f'site:{base} inurl:wp-content',
            "description": "WordPress content URLs",
        },
        {
            "category":    "Tech Stack",
            "query":       f'site:{base} inurl:".php"',
            "description": "PHP pages",
        },
        {
            "category":    "Tech Stack",
            "query":       f'site:{base} inurl:".asp" OR inurl:".aspx"',
            "description": "ASP.NET pages",
        },
        # Error Pages
        {
            "category":    "Error Pages",
            "query":       f'site:{base} intext:"sql syntax" OR intext:"mysql error"',
            "description": "SQL error messages (possible SQLi)",
        },
        {
            "category":    "Error Pages",
            "query":       f'site:{base} intitle:"500 internal server error"',
            "description": "Internal server error pages",
        },
        {
            "category":    "Error Pages",
            "query":       f'site:{base} intitle:"error" intext:"stack trace"',
            "description": "Stack trace error pages",
        },
        # Caches
        {
            "category":    "Cache / Archive",
            "query":       f"cache:{base}",
            "description": "Google's cached version of the site",
        },
    ]
    return dorks


def _email_dorks(email: str) -> list:
    return [
        {
            "category":    "Identity",
            "query":       f'"{email}"',
            "description": "All mentions of this email address",
        },
        {
            "category":    "Identity",
            "query":       f'"{email}" site:linkedin.com',
            "description": "LinkedIn profile with this email",
        },
        {
            "category":    "Identity",
            "query":       f'"{email}" site:github.com',
            "description": "GitHub profile or commits with this email",
        },
        {
            "category":    "Leaks",
            "query":       f'"{email}" site:pastebin.com',
            "description": "Email mentioned on Pastebin (possible leak)",
        },
        {
            "category":    "Leaks",
            "query":       f'"{email}" "password" OR "pwd" OR "pass"',
            "description": "Email mentioned near passwords",
        },
        {
            "category":    "Leaks",
            "query":       f'"{email}" filetype:sql',
            "description": "Email in SQL database dumps",
        },
        {
            "category":    "Leaks",
            "query":       f'"{email}" filetype:csv OR filetype:txt',
            "description": "Email in CSV or text dumps",
        },
        {
            "category":    "Social",
            "query":       f'"{email}" site:reddit.com',
            "description": "Reddit mentions",
        },
        {
            "category":    "Social",
            "query":       f'"{email}" site:twitter.com OR site:x.com',
            "description": "Twitter/X mentions",
        },
        {
            "category":    "Social",
            "query":       f'"{email}" site:facebook.com',
            "description": "Facebook mentions",
        },
        {
            "category":    "Professional",
            "query":       f'"{email}" site:slideshare.net',
            "description": "SlideShare presentations",
        },
        {
            "category":    "Professional",
            "query":       f'"{email}" filetype:pdf',
            "description": "PDFs containing this email",
        },
    ]


def _phone_dorks(phone: str) -> list:
    # Generate variants of the phone number
    digits_only = re.sub(r"\D", "", phone)
    formatted   = f"+{digits_only}" if not phone.startswith("+") else phone

    variants = list({phone, formatted, digits_only})

    dorks = []
    for variant in variants:
        dorks += [
            {
                "category":    "Identity",
                "query":       f'"{variant}"',
                "description": f"All mentions of {variant}",
            },
            {
                "category":    "Social",
                "query":       f'"{variant}" site:linkedin.com',
                "description": "LinkedIn profile with this number",
            },
            {
                "category":    "Leaks",
                "query":       f'"{variant}" site:pastebin.com',
                "description": "Phone on Pastebin",
            },
            {
                "category":    "Leaks",
                "query":       f'"{variant}" "name" OR "email" OR "address"',
                "description": "Phone mentioned with PII",
            },
        ]
    return dorks


def _username_dorks(username: str) -> list:
    return [
        {
            "category":    "Social Media",
            "query":       f'"{username}" site:twitter.com OR site:x.com',
            "description": "Twitter/X profile",
        },
        {
            "category":    "Social Media",
            "query":       f'"{username}" site:instagram.com',
            "description": "Instagram profile",
        },
        {
            "category":    "Social Media",
            "query":       f'"{username}" site:reddit.com',
            "description": "Reddit user profile",
        },
        {
            "category":    "Social Media",
            "query":       f'"{username}" site:tiktok.com',
            "description": "TikTok profile",
        },
        {
            "category":    "Social Media",
            "query":       f'"{username}" site:youtube.com',
            "description": "YouTube channel",
        },
        {
            "category":    "Dev",
            "query":       f'"{username}" site:github.com',
            "description": "GitHub profile",
        },
        {
            "category":    "Dev",
            "query":       f'"{username}" site:gitlab.com',
            "description": "GitLab profile",
        },
        {
            "category":    "Dev",
            "query":       f'"{username}" site:stackoverflow.com',
            "description": "Stack Overflow profile",
        },
        {
            "category":    "Professional",
            "query":       f'"{username}" site:linkedin.com',
            "description": "LinkedIn profile",
        },
        {
            "category":    "General",
            "query":       f'intitle:"{username}"',
            "description": "Pages with username in title",
        },
        {
            "category":    "General",
            "query":       f'"{username}" site:pastebin.com',
            "description": "Username on Pastebin",
        },
        {
            "category":    "Gaming",
            "query":       f'"{username}" site:twitch.tv',
            "description": "Twitch streamer profile",
        },
        {
            "category":    "Gaming",
            "query":       f'"{username}" site:steamcommunity.com',
            "description": "Steam profile",
        },
    ]


def generate(target: str) -> DorkResult:
    """Generate Google dork queries for any target type."""
    result = DorkResult(target=target)
    target_type = _detect_type(target)
    result.target_type = target_type

    if target_type == "domain":
        dorks = _domain_dorks(target)
    elif target_type == "email":
        dorks = _email_dorks(target)
    elif target_type == "phone":
        dorks = _phone_dorks(target)
    else:
        dorks = _username_dorks(target)

    # Add Google search URLs to each dork
    for d in dorks:
        d["url"] = _google_url(d["query"])

    result.dorks = dorks
    result.total = len(dorks)
    return result