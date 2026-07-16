import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}

# ══════════════════════════════════════════════════════════════
# WHY THIS FILE LOOKS DIFFERENT FROM A SIMPLE "check for 404" SCRAPER
# ══════════════════════════════════════════════════════════════
#
# Bare "status 200 = found" checking is unreliable across almost every
# platform here today, for two independent reasons:
#
#   1. Bot/challenge protection (Cloudflare, PerimeterX, Akamai) returns
#      HTTP 200 with a CAPTCHA/"checking your browser" page for ANY
#      request that looks automated -- including requests for profiles
#      that don't exist. A plain requests.get() with no JS engine can't
#      pass these, so it silently gets a "blocked" 200 instead of a
#      real 404, and a naive checker reports that as "found".
#
#   2. Client-rendered (SPA) sites -- Instagram, TikTok, Facebook,
#      Pinterest, Twitter/X and others -- serve the same generic HTML
#      shell with HTTP 200 whether the profile exists or not; the
#      actual "not found" message is injected by JavaScript after load,
#      which requests.get() never executes.
#
# Fix applied here:
#   - Every response is first screened for known blocker/challenge
#     markers. If found, the result is DISCARDED (returns None) rather
#     than trusted either way.
#   - Every site config requires a POSITIVE signal to count as "found":
#     either a real 404 (mode: not_found_404), a body substring that
#     only appears on a real profile page (mode: must_contain), a body
#     substring only present when the profile does NOT exist
#     (mode: error_msg), or a <title> tag substring only present for a
#     real profile (mode: title_must_contain). No site falls back to
#     "assume any 200 is a hit."
#   - Purely numeric strings under 5 digits are skipped outright --
#     these are phone-number fragments, never real usernames.
#
# CAVEAT: the exact error/title strings below are believed accurate as
# of this writing but sites change their markup without notice. Spot
# check any platform you rely on heavily by viewing page source (not
# devtools' rendered DOM) for one known-real and one known-fake profile
# before trusting it in production. Treat "found" results here as a
# strong lead to manually confirm, not as absolute proof.

BLOCKER_MARKERS = [
    "checking your browser",
    "cf-browser-verification",
    "attention required",
    "unusual traffic",
    "please verify you are a human",
    "please verify you're a human",
    "access denied",
    "just a moment",
    "enable javascript and cookies",
    "captcha",
    "request unsuccessful",
    "distil_r_captcha",
    "you have been blocked",
]


def _looks_blocked(html: str) -> bool:
    low = html.lower()
    return any(marker in low for marker in BLOCKER_MARKERS)


def _extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip().lower()


SITES = [

    {"name": "Twitter/X",     "category": "Social",  "url": "https://x.com/{}",
     "mode": "title_must_contain", "marker": "(@", "min_len": 4},

    {"name": "Instagram",     "category": "Social",  "url": "https://www.instagram.com/{}/",
     "mode": "title_must_contain", "marker": "instagram photos and videos", "min_len": 4},

    {"name": "Facebook",      "category": "Social",  "url": "https://www.facebook.com/{}",
     "mode": "title_must_contain", "marker": "facebook", "min_len": 4},

    {"name": "TikTok",        "category": "Social",  "url": "https://www.tiktok.com/@{}",
     "mode": "error_msg", "marker": "couldn't find this account", "min_len": 4},

    {"name": "Snapchat",      "category": "Social",  "url": "https://www.snapchat.com/add/{}",
     "mode": "error_msg", "marker": "sorry, we couldn't find", "min_len": 4},

    {"name": "LinkedIn",      "category": "Social",  "url": "https://www.linkedin.com/in/{}",
     "mode": "error_msg", "marker": "page not found", "min_len": 4},

    {"name": "Pinterest",     "category": "Social",  "url": "https://www.pinterest.com/{}/",
     "mode": "title_must_contain", "marker": "on pinterest", "min_len": 4},

    {"name": "Reddit",        "category": "Social",  "url": "https://www.reddit.com/user/{}/about.json",
     "mode": "must_contain", "marker": '"is_suspended"', "min_len": 4},

    {"name": "Tumblr",        "category": "Social",  "url": "https://{}.tumblr.com",
     "mode": "error_msg", "marker": "there's nothing here", "min_len": 4},

    {"name": "Mastodon",      "category": "Social",  "url": "https://mastodon.social/@{}",
     "mode": "not_found_404", "min_len": 4},

    {"name": "Bluesky",       "category": "Social",  "url": "https://bsky.app/profile/{}",
     "mode": "title_must_contain", "marker": "@", "min_len": 6},

    {"name": "YouTube",       "category": "Video",   "url": "https://www.youtube.com/@{}",
     "mode": "title_must_contain", "marker": "youtube", "min_len": 4},

    {"name": "Twitch",        "category": "Video",   "url": "https://www.twitch.tv/{}",
     "mode": "title_must_contain", "marker": "twitch", "min_len": 4},

    {"name": "Vimeo",         "category": "Video",   "url": "https://vimeo.com/{}",
     "mode": "title_must_contain", "marker": "on vimeo", "min_len": 4},

    {"name": "Dailymotion",   "category": "Video",   "url": "https://www.dailymotion.com/{}",
     "mode": "title_must_contain", "marker": "dailymotion", "min_len": 4},

    {"name": "GitHub",        "category": "Dev",     "url": "https://github.com/{}",
     "mode": "not_found_404", "min_len": 3},
    {"name": "GitLab",        "category": "Dev",     "url": "https://gitlab.com/{}",
     "mode": "not_found_404", "min_len": 3},
    {"name": "Bitbucket",     "category": "Dev",     "url": "https://bitbucket.org/{}",
     "mode": "not_found_404", "min_len": 3},
    {"name": "Stack Overflow","category": "Dev",     "url": "https://stackoverflow.com/users/{}",
     "mode": "not_found_404", "min_len": 3},
    {"name": "Dev.to",        "category": "Dev",     "url": "https://dev.to/{}",
     "mode": "not_found_404", "min_len": 3},
    {"name": "Replit",        "category": "Dev",     "url": "https://replit.com/@{}",
     "mode": "title_must_contain", "marker": "replit", "min_len": 3},
    {"name": "CodePen",       "category": "Dev",     "url": "https://codepen.io/{}",
     "mode": "not_found_404", "min_len": 3},
    {"name": "HackerRank",    "category": "Dev",     "url": "https://www.hackerrank.com/{}",
     "mode": "title_must_contain", "marker": "hackerrank profile", "min_len": 3},
    {"name": "LeetCode",      "category": "Dev",     "url": "https://leetcode.com/u/{}",
     "mode": "error_msg", "marker": "user does not exist", "min_len": 3},
    {"name": "Kaggle",        "category": "Dev",     "url": "https://www.kaggle.com/{}",
     "mode": "title_must_contain", "marker": "kaggle", "min_len": 3},
    {"name": "PyPI",          "category": "Dev",     "url": "https://pypi.org/user/{}/",
     "mode": "not_found_404", "require_username_in_title": True, "min_len": 3},
    {"name": "npm",           "category": "Dev",     "url": "https://www.npmjs.com/~{}",
     "mode": "must_contain", "marker": "profile-info", "min_len": 3},
    {"name": "Docker Hub",    "category": "Dev",     "url": "https://hub.docker.com/u/{}/",
     "mode": "not_found_404", "min_len": 3},
    {"name": "Hackernews",    "category": "Dev",     "url": "https://news.ycombinator.com/user?id={}",
     "mode": "error_msg", "marker": "no such user", "min_len": 3},

    {"name": "Steam",         "category": "Gaming",  "url": "https://steamcommunity.com/id/{}",
     "mode": "error_msg", "marker": "the specified profile could not be found", "min_len": 4},
    {"name": "Speedrun.com",  "category": "Gaming",  "url": "https://www.speedrun.com/user/{}",
     "mode": "not_found_404", "min_len": 4},

    {"name": "Medium",        "category": "Creative","url": "https://medium.com/@{}",
     "mode": "title_must_contain", "marker": "medium", "min_len": 4},
    {"name": "Behance",       "category": "Creative","url": "https://www.behance.net/{}",
     "mode": "not_found_404", "min_len": 4},
    {"name": "Dribbble",      "category": "Creative","url": "https://dribbble.com/{}",
     "mode": "not_found_404", "min_len": 4},
    {"name": "DeviantArt",    "category": "Creative","url": "https://www.deviantart.com/{}",
     "mode": "not_found_404", "min_len": 4},
    {"name": "SoundCloud",    "category": "Creative","url": "https://soundcloud.com/{}",
     "mode": "not_found_404", "min_len": 4},
    # Bandcamp intentionally excluded from auto-verification: unclaimed
    # subdomains do not reliably expose a scrapable "not found" signal on
    # the public page (Bandcamp's own API distinguishes this internally via
    # a structured field not present in the HTML). Rather than keep
    # guessing at markers and risking false positives, this platform is
    # left out of SITES entirely. If you want a Bandcamp lead surfaced,
    # generate the URL and label it "unverified" in the UI instead of
    # reporting it as a confirmed match.
    {"name": "Flickr",        "category": "Creative","url": "https://www.flickr.com/people/{}",
     "mode": "not_found_404", "min_len": 4},
    {"name": "Wattpad",       "category": "Creative","url": "https://www.wattpad.com/user/{}",
     "mode": "not_found_404", "min_len": 4},
    {"name": "Mixcloud",      "category": "Creative","url": "https://www.mixcloud.com/{}/",
     "mode": "title_must_contain", "marker": "mixcloud", "require_username_in_title": True, "min_len": 4},

    {"name": "Gravatar",      "category": "Professional","url": "https://en.gravatar.com/{}.json",
     "mode": "must_contain", "marker": '"entry"', "min_len": 4},
    {"name": "About.me",      "category": "Professional","url": "https://about.me/{}",
     "mode": "not_found_404", "min_len": 4},
    {"name": "ProductHunt",   "category": "Professional","url": "https://www.producthunt.com/@{}",
     "mode": "not_found_404", "min_len": 4},
    {"name": "Keybase",       "category": "Professional","url": "https://keybase.io/{}",
     "mode": "not_found_404", "min_len": 3},

    {"name": "Disqus",        "category": "Forums",  "url": "https://disqus.com/by/{}/",
     "mode": "not_found_404", "min_len": 4},
    {"name": "Pastebin",      "category": "Forums",  "url": "https://pastebin.com/u/{}",
     "mode": "not_found_404", "min_len": 4},
    {"name": "Instructables", "category": "Forums",  "url": "https://www.instructables.com/member/{}/",
     "mode": "not_found_404", "min_len": 4},
]


def _check_site(site: dict, username: str) -> dict | None:
    if len(username) < site.get("min_len", 1):
        return None

    if username.isdigit() and len(username) < 5:
        return None

    url = site["url"].format(username)
    mode = site.get("mode", "not_found_404")

    try:
        r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
    except Exception:
        return None

    body = r.text if r.text else ""

    if body and _looks_blocked(body):
        return None

    def _hit():
        return {
            "name":     site["name"],
            "category": site.get("category", "Other"),
            "url":      url,
            "status":   "found",
        }

    def _title_has_username(html: str) -> bool:
        """Extra guard against generic/homepage titles: require the searched
        username itself to appear somewhere in the title. A real profile
        page's title virtually always includes the handle; a 404/homepage
        shell that merely contains the site's brand name does not."""
        title = _extract_title(html)
        return username.lower() in title

    if mode == "not_found_404":
        if r.status_code != 200:
            return None
        if site.get("require_username_in_title") and not _title_has_username(body):
            return None
        return _hit()

    if mode == "must_contain":
        if r.status_code != 200:
            return None
        if site["marker"].lower() in body.lower():
            return _hit()
        return None

    if mode == "error_msg":
        if r.status_code != 200:
            return None
        if site["marker"].lower() in body.lower():
            return None
        return _hit()

    if mode == "title_must_contain":
        if r.status_code != 200:
            return None
        title = _extract_title(body)
        if site["marker"].lower() not in title:
            return None
        if site.get("require_username_in_title") and username.lower() not in title:
            return None
        return _hit()

    if mode == "any_of_contains":
        if r.status_code != 200:
            return None
        low = body.lower()
        if any(marker.lower() in low for marker in site.get("markers", [])):
            return _hit()
        return None

    if mode == "subdomain_redirect_check":
        final_host = re.sub(r"^https?://", "", r.url).split("/")[0].lower()
        expected_host = re.sub(r"^https?://", "", url).split("/")[0].lower()
        if final_host != expected_host:
            return None
        if r.status_code != 200:
            return None
        return _hit()

    return None


def _get_variations(raw: str) -> list[str]:
    raw = raw.strip().lower()

    digits_only = re.sub(r"[^\d]", "", raw)
    looks_like_phone = raw.startswith("+") or (
        digits_only and len(digits_only) >= 7 and len(digits_only) / max(len(raw), 1) > 0.6
    )
    if looks_like_phone:
        return [digits_only] if digits_only else []

    parts = raw.split()
    if len(parts) == 1:
        return [raw]

    variations = []
    seen = set()
    candidates = [
        "".join(parts),
        ".".join(parts),
        "_".join(parts),
        parts[0][0] + parts[-1],
        parts[0] + parts[-1][0],
        parts[0],
        parts[-1],
    ]
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            variations.append(c)
    return variations


def search_username(raw: str) -> list[dict]:
    raw = raw.strip()
    if not raw:
        return []

    variations = _get_variations(raw)
    if not variations:
        return []

    tasks = [(site, variation) for variation in variations for site in SITES]

    found_urls = set()
    found = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(_check_site, site, uname): (site, uname)
            for site, uname in tasks
        }
        for future in as_completed(futures):
            result = future.result()
            if result and result["url"] not in found_urls:
                found_urls.add(result["url"])
                found.append(result)

    category_order = ["Social", "Video", "Dev", "Gaming", "Creative", "Professional", "Forums"]
    found.sort(key=lambda x: (
        category_order.index(x["category"]) if x["category"] in category_order else 99,
        x["name"].lower()
    ))
    return found