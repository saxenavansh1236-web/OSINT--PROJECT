"""
tech_stack.py — Website technology fingerprinter.

Detects
-------
* CMS         (WordPress, Drupal, Joomla, Ghost, Webflow, Squarespace …)
* Server      (Nginx, Apache, Caddy, LiteSpeed, IIS …)
* Framework   (Laravel, Rails, Django, Next.js, Nuxt, Express …)
* CDN         (Cloudflare, Fastly, Akamai, CloudFront, BunnyCDN …)
* Analytics   (GA4, GTM, Mixpanel, Plausible, Hotjar, Heap …)
* JS libs     (React, Vue, Angular, jQuery, Alpine.js …)
* E-commerce  (WooCommerce, Shopify, Magento, PrestaShop …)
* Security    (WAF, HSTS, CSP, X-Frame-Options …)
* Hosting     (Vercel, Netlify, AWS, GCP, Heroku …)
* Email SaaS  (Mailchimp, Klaviyo, HubSpot, Intercom …)
* Fonts       (Google Fonts, Adobe Fonts, Bunny Fonts …)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict, field
from typing import Optional
import ssl
import socket

import requests

_TIMEOUT = 12
_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
})


# ─────────────────────────────────────────────
# Signature database
# ─────────────────────────────────────────────

# Each entry: (category, name, match_type, targets, pattern/string)
# targets: "html" | "headers" | "header:X-Powered-By" | "cookie"
# match_type: "contains" | "regex" | "header_key"

_SIGNATURES: list[tuple] = [
    # ── CMS ─────────────────────────────────────────────────────────────────
    ("cms", "WordPress",     "contains",   "html",                "/wp-content/"),
    ("cms", "WordPress",     "contains",   "html",                "/wp-includes/"),
    ("cms", "Drupal",        "contains",   "html",                "/sites/default/files/"),
    ("cms", "Drupal",        "contains",   "html",                "Drupal.settings"),
    ("cms", "Joomla",        "contains",   "html",                "/media/jui/"),
    ("cms", "Joomla",        "contains",   "html",                "Joomla!"),
    ("cms", "Ghost",         "contains",   "html",                "content=\"Ghost "),
    ("cms", "Webflow",       "contains",   "html",                "data-wf-site"),
    ("cms", "Squarespace",   "contains",   "html",                "squarespace.com"),
    ("cms", "Wix",           "contains",   "html",                "wix.com/"),
    ("cms", "HubSpot CMS",   "contains",   "html",                "hs-scripts.com"),
    ("cms", "Contentful",    "contains",   "html",                "ctf"),
    ("cms", "Sanity",        "contains",   "html",                "sanity.io"),
    ("cms", "Strapi",        "header_key", "headers",             "x-strapi-version"),
    # ── Server ───────────────────────────────────────────────────────────────
    ("server", "Nginx",      "regex",      "header:server",       r"nginx"),
    ("server", "Apache",     "regex",      "header:server",       r"apache"),
    ("server", "IIS",        "regex",      "header:server",       r"microsoft-iis"),
    ("server", "Caddy",      "regex",      "header:server",       r"caddy"),
    ("server", "LiteSpeed",  "regex",      "header:server",       r"litespeed"),
    ("server", "OpenResty",  "regex",      "header:server",       r"openresty"),
    ("server", "Gunicorn",   "regex",      "header:server",       r"gunicorn"),
    ("server", "Kestrel",    "regex",      "header:server",       r"kestrel"),
    ("server", "Cloudflare", "header_key", "headers",             "cf-ray"),
    # ── Framework ────────────────────────────────────────────────────────────
    ("framework", "Next.js",    "contains", "html",              "__NEXT_DATA__"),
    ("framework", "Nuxt.js",    "contains", "html",              "__nuxt"),
    ("framework", "Laravel",    "contains", "html",              "laravel"),
    ("framework", "Laravel",    "regex",    "header:set-cookie",  r"laravel_session"),
    ("framework", "Django",     "regex",    "header:set-cookie",  r"csrftoken"),
    ("framework", "Rails",      "regex",    "header:set-cookie",  r"_session_id"),
    ("framework", "ASP.NET",    "header_key","headers",           "x-aspnet-version"),
    ("framework", "ASP.NET",    "regex",    "header:set-cookie",  r"asp\.net"),
    ("framework", "Express",    "regex",    "header:x-powered-by",r"express"),
    ("framework", "Symfony",    "contains", "html",               "Symfony"),
    ("framework", "FastAPI",    "regex",    "header:server",      r"fastapi|uvicorn"),
    ("framework", "Gatsby",     "contains", "html",               "___gatsby"),
    ("framework", "Remix",      "contains", "html",               "__remixContext"),
    ("framework", "SvelteKit",  "contains", "html",               "__svelte"),
    ("framework", "Astro",      "contains", "html",               "data-astro"),
    # ── CDN ──────────────────────────────────────────────────────────────────
    ("cdn", "Cloudflare",   "header_key", "headers",             "cf-ray"),
    ("cdn", "Fastly",       "header_key", "headers",             "x-fastly-request-id"),
    ("cdn", "Akamai",       "header_key", "headers",             "x-check-cacheable"),
    ("cdn", "CloudFront",   "regex",      "header:x-amz-cf-id",  r".+"),
    ("cdn", "BunnyCDN",     "header_key", "headers",             "cdn-requestid"),
    ("cdn", "Vercel",       "header_key", "headers",             "x-vercel-id"),
    ("cdn", "Netlify",      "header_key", "headers",             "x-nf-request-id"),
    ("cdn", "Sucuri",       "header_key", "headers",             "x-sucuri-id"),
    ("cdn", "KeyCDN",       "header_key", "headers",             "x-cache"),
    # ── Analytics ────────────────────────────────────────────────────────────
    ("analytics", "Google Analytics 4", "regex",    "html", r"G-[A-Z0-9]+"),
    ("analytics", "GTM",                "regex",    "html", r"GTM-[A-Z0-9]+"),
    ("analytics", "Plausible",          "contains", "html", "plausible.io/js"),
    ("analytics", "Matomo",             "contains", "html", "matomo.js"),
    ("analytics", "Mixpanel",           "contains", "html", "mixpanel.com"),
    ("analytics", "Hotjar",             "contains", "html", "static.hotjar.com"),
    ("analytics", "Heap",               "contains", "html", "heapanalytics.com"),
    ("analytics", "Segment",            "contains", "html", "cdn.segment.com"),
    ("analytics", "Amplitude",          "contains", "html", "amplitude.com/libs"),
    ("analytics", "Posthog",            "contains", "html", "posthog.com"),
    ("analytics", "Clarity",            "contains", "html", "clarity.ms"),
    # ── JavaScript frameworks/libs ───────────────────────────────────────────
    ("js_lib", "React",     "contains", "html", "react.js"),
    ("js_lib", "React",     "contains", "html", "react.min.js"),
    ("js_lib", "React",     "contains", "html", "react-dom"),
    ("js_lib", "Vue.js",    "contains", "html", "vue.min.js"),
    ("js_lib", "Vue.js",    "contains", "html", "vue@"),
    ("js_lib", "Angular",   "contains", "html", "angular/core"),
    ("js_lib", "jQuery",    "regex",    "html", r"jquery[.-]\d"),
    ("js_lib", "Alpine.js", "contains", "html", "alpinejs"),
    ("js_lib", "HTMX",      "contains", "html", "htmx.org"),
    ("js_lib", "Lodash",    "contains", "html", "lodash"),
    # ── E-commerce ───────────────────────────────────────────────────────────
    ("ecommerce", "WooCommerce",  "contains", "html", "woocommerce"),
    ("ecommerce", "Shopify",      "contains", "html", "shopify.com/s/files"),
    ("ecommerce", "Magento",      "contains", "html", "Mage."),
    ("ecommerce", "PrestaShop",   "contains", "html", "prestashop"),
    ("ecommerce", "BigCommerce",  "contains", "html", "bigcommerce.com"),
    ("ecommerce", "OpenCart",     "contains", "html", "route=common/home"),
    # ── Hosting ──────────────────────────────────────────────────────────────
    ("hosting", "Vercel",    "header_key", "headers", "x-vercel-id"),
    ("hosting", "Netlify",   "header_key", "headers", "x-nf-request-id"),
    ("hosting", "GitHub Pages", "regex",   "header:server", r"github"),
    ("hosting", "AWS",       "header_key", "headers", "x-amzn-requestid"),
    ("hosting", "Heroku",    "header_key", "headers", "x-heroku-router"),
    ("hosting", "Render",    "header_key", "headers", "x-render-origin-server"),
    ("hosting", "Fly.io",    "header_key", "headers", "fly-request-id"),
    # ── Email / Marketing SaaS ───────────────────────────────────────────────
    ("marketing", "HubSpot",    "contains", "html", "js.hs-scripts.com"),
    ("marketing", "Intercom",   "contains", "html", "intercomcdn.com"),
    ("marketing", "Drift",      "contains", "html", "js.driftt.com"),
    ("marketing", "Crisp",      "contains", "html", "client.crisp.chat"),
    ("marketing", "Mailchimp",  "contains", "html", "chimpstatic.com"),
    ("marketing", "Klaviyo",    "contains", "html", "klaviyo.com/media"),
    # ── Fonts ────────────────────────────────────────────────────────────────
    ("fonts", "Google Fonts",  "contains", "html", "fonts.googleapis.com"),
    ("fonts", "Adobe Fonts",   "contains", "html", "use.typekit.net"),
    ("fonts", "Bunny Fonts",   "contains", "html", "fonts.bunny.net"),
]


# ─────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────

@dataclass
class TechResult:
    url: str
    final_url: str
    status_code: int
    cms:        list[str] = field(default_factory=list)
    server:     list[str] = field(default_factory=list)
    framework:  list[str] = field(default_factory=list)
    cdn:        list[str] = field(default_factory=list)
    analytics:  list[str] = field(default_factory=list)
    js_libs:    list[str] = field(default_factory=list)
    ecommerce:  list[str] = field(default_factory=list)
    hosting:    list[str] = field(default_factory=list)
    marketing:  list[str] = field(default_factory=list)
    fonts:      list[str] = field(default_factory=list)
    security_headers: dict = field(default_factory=dict)
    cookies:    list[dict] = field(default_factory=list)
    response_headers: dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def summary(self) -> dict:
        return {k: getattr(self, k) for k in
                ("cms", "server", "framework", "cdn", "analytics",
                 "js_libs", "ecommerce", "hosting", "marketing", "fonts")}


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def detect(url: str) -> TechResult:
    """
    Fingerprint the technology stack at *url*.
    Accepts bare domain, http://, or https:// prefix.
    """
    url = _normalize_url(url)
    try:
        resp = _SESSION.get(url, timeout=_TIMEOUT, allow_redirects=True)
    except Exception as exc:
        return TechResult(url=url, final_url=url, status_code=0, error=str(exc))

    html    = resp.text
    headers = {k.lower(): v for k, v in resp.headers.items()}
    cookies = [{"name": c.name, "domain": c.domain, "secure": c.secure, "httponly": c.has_nonstandard_attr("httponly")}
               for c in resp.cookies]

    result = TechResult(
        url=url,
        final_url=resp.url,
        status_code=resp.status_code,
        response_headers=dict(headers),
        cookies=cookies,
        security_headers=_security_headers(headers),
    )

    # Run signature matching
    matched: dict[str, set[str]] = {
        "cms": set(), "server": set(), "framework": set(), "cdn": set(),
        "analytics": set(), "js_lib": set(), "ecommerce": set(),
        "hosting": set(), "marketing": set(), "fonts": set(),
    }

    for cat, name, mtype, target, pattern in _SIGNATURES:
        if _match(mtype, target, pattern, html, headers):
            matched.setdefault(cat, set()).add(name)

    result.cms       = sorted(matched.get("cms", set()))
    result.server    = sorted(matched.get("server", set()))
    result.framework = sorted(matched.get("framework", set()))
    result.cdn       = sorted(matched.get("cdn", set()))
    result.analytics = sorted(matched.get("analytics", set()))
    result.js_libs   = sorted(matched.get("js_lib", set()))
    result.ecommerce = sorted(matched.get("ecommerce", set()))
    result.hosting   = sorted(matched.get("hosting", set()))
    result.marketing = sorted(matched.get("marketing", set()))
    result.fonts     = sorted(matched.get("fonts", set()))

    return result


# ─────────────────────────────────────────────
# Matching engine
# ─────────────────────────────────────────────

def _match(mtype: str, target: str, pattern: str, html: str, headers: dict) -> bool:
    corpus = _get_corpus(target, html, headers)
    if corpus is None:
        return False

    if mtype == "contains":
        return pattern.lower() in corpus.lower()
    if mtype == "regex":
        return bool(re.search(pattern, corpus, re.IGNORECASE))
    if mtype == "header_key":
        return pattern.lower() in headers
    return False


def _get_corpus(target: str, html: str, headers: dict) -> Optional[str]:
    if target == "html":
        return html
    if target == "headers":
        return " ".join(headers.keys())   # for header_key checks
    if target.startswith("header:"):
        key = target[7:]
        return headers.get(key, "")
    if target == "cookie":
        return str(headers.get("set-cookie", ""))
    return None


# ─────────────────────────────────────────────
# Security headers analysis
# ─────────────────────────────────────────────

def _security_headers(headers: dict) -> dict:
    return {
        "strict_transport_security": headers.get("strict-transport-security", ""),
        "content_security_policy":   headers.get("content-security-policy", ""),
        "x_frame_options":           headers.get("x-frame-options", ""),
        "x_content_type_options":    headers.get("x-content-type-options", ""),
        "referrer_policy":           headers.get("referrer-policy", ""),
        "permissions_policy":        headers.get("permissions-policy", ""),
        "x_xss_protection":          headers.get("x-xss-protection", ""),
        "hsts":                      bool(headers.get("strict-transport-security")),
        "csp":                       bool(headers.get("content-security-policy")),
        "x_frame":                   bool(headers.get("x-frame-options")),
    }


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url