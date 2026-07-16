"""
social_search_links.py — Generates labeled SEARCH SUGGESTION links for a
phone number, email, or username across social platforms and public-record
sites. These are NOT verified findings — every entry is explicitly labeled
"search suggestion" and the UI must never render them as confirmed matches.

This complements (does not replace) modules.username.search_username,
which performs *actual* verified profile checks (404/error-string based).
Use this module only for platforms where automated verification isn't
feasible (e.g. Facebook/Instagram/LinkedIn/Telegram/Skype people-search,
which require login or block scraping entirely).
"""

from __future__ import annotations
from urllib.parse import quote_plus
from dataclasses import dataclass, field


@dataclass
class SearchSuggestion:
    platform: str
    url: str
    label: str = "search suggestion"   # never "found" / "verified"
    category: str = "Social"

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "url": self.url,
            "label": self.label,
            "category": self.category,
        }


def _social_people_search(query: str) -> list[SearchSuggestion]:
    q = quote_plus(query)
    return [
        SearchSuggestion("Facebook",  f"https://www.facebook.com/search/people/?q={q}"),
        SearchSuggestion("Instagram", f"https://www.google.com/search?q=site:instagram.com+%22{q}%22"),
        SearchSuggestion("LinkedIn",  f"https://www.linkedin.com/search/results/people/?keywords={q}"),
        SearchSuggestion("Telegram",  f"https://www.google.com/search?q=site:t.me+%22{q}%22"),
        SearchSuggestion("Skype",     f"https://www.google.com/search?q=%22{q}%22+skype"),
        SearchSuggestion("GitHub",    f"https://github.com/search?q={q}&type=users"),
    ]


def _public_mentions(query: str) -> list[SearchSuggestion]:
    q = quote_plus(query)
    categories = [
        ("PDF Documents",       f"https://www.google.com/search?q=%22{q}%22+filetype:pdf",             "Mentions"),
        ("Forum Posts",         f"https://www.google.com/search?q=%22{q}%22+forum",                     "Mentions"),
        ("Resumes/CVs",         f"https://www.google.com/search?q=%22{q}%22+resume+OR+cv+filetype:pdf", "Mentions"),
        ("GitHub Code/Issues",  f"https://github.com/search?q=%22{q}%22&type=code",                     "Dev"),
        ("Company Websites",    f"https://www.google.com/search?q=%22{q}%22+site:*.com+-site:facebook.com", "Mentions"),
        ("Government Documents",f"https://www.google.com/search?q=%22{q}%22+site:gov+OR+site:gov.in",   "Mentions"),
        ("Public Datasets",     f"https://www.google.com/search?q=%22{q}%22+dataset+filetype:csv+OR+filetype:json", "Mentions"),
    ]
    return [SearchSuggestion(name, url, category=cat) for name, url, cat in categories]


def build_social_and_mentions(query: str) -> dict:
    """
    Returns a dict with two clearly-separated, clearly-labeled lists.
    Every entry is a *search suggestion*, never a confirmed profile.
    """
    if not query or not query.strip():
        return {"social_profiles": [], "public_mentions": []}

    query = query.strip()
    return {
        "social_profiles": [s.to_dict() for s in _social_people_search(query)],
        "public_mentions": [s.to_dict() for s in _public_mentions(query)],
        "disclaimer": (
            "These are search suggestions only. No account existence has been "
            "verified — click through and confirm manually before treating any "
            "result as a real finding."
        ),
    }