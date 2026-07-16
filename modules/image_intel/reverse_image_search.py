"""
Reverse Image Search — generates "search by this image" links for Google
Lens, Bing Visual Search, Yandex Images, and TinEye.

Honesty note (same evidentiary standard as social_search_links.py):
none of these engines will actually search FOR you server-side without
either a paid API or a publicly reachable URL for the image. Since this
platform deletes uploaded images immediately after metadata extraction
(no persistent public hosting), we cannot silently claim we "searched"
anywhere. Two modes:

  1. PUBLIC_IMAGE_URL is available (e.g. you've wired up a short-lived
     public share link elsewhere in your app) -> we build direct
     "search by this exact image" URLs.
  2. No public URL -> we return "search suggestion" links to each
     engine's manual upload page, clearly labeled, so the investigator
     can drag-and-drop the file themselves.

Every entry is tagged with its mode so the UI can render an accurate
disclaimer, consistent with the platform's "never claim a verified
result you didn't actually get" rule.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote


@dataclass
class ReverseSearchLink:
    engine: str
    url: str
    mode: str  # "direct_by_url" | "manual_upload"

    def to_dict(self):
        return {"engine": self.engine, "url": self.url, "mode": self.mode}


@dataclass
class ReverseImageSearchResult:
    mode: str  # "direct_by_url" | "manual_upload"
    links: list = field(default_factory=list)
    disclaimer: str = ""

    def to_dict(self):
        return {
            "mode": self.mode,
            "links": [l.to_dict() for l in self.links],
            "disclaimer": self.disclaimer,
        }


def build_links(public_image_url: Optional[str] = None) -> ReverseImageSearchResult:
    if public_image_url:
        encoded = quote(public_image_url, safe="")
        links = [
            ReverseSearchLink("Google Lens", f"https://lens.google.com/uploadbyurl?url={encoded}", "direct_by_url"),
            ReverseSearchLink("Bing Visual Search", f"https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&sbisrc=UrlPaste&q=imgurl:{encoded}", "direct_by_url"),
            ReverseSearchLink("Yandex Images", f"https://yandex.com/images/search?rpt=imageview&url={encoded}", "direct_by_url"),
            ReverseSearchLink("TinEye", f"https://tineye.com/search?url={encoded}", "direct_by_url"),
        ]
        disclaimer = (
            "These links search each engine using the image's temporary public URL. "
            "Results are third-party matches — verify manually before treating any hit as confirmed."
        )
        mode = "direct_by_url"
    else:
        links = [
            ReverseSearchLink("Google Lens", "https://lens.google.com/", "manual_upload"),
            ReverseSearchLink("Bing Visual Search", "https://www.bing.com/visualsearch", "manual_upload"),
            ReverseSearchLink("Yandex Images", "https://yandex.com/images/", "manual_upload"),
            ReverseSearchLink("TinEye", "https://tineye.com/", "manual_upload"),
        ]
        disclaimer = (
            "No public URL was available for this image (it's deleted from the server "
            "immediately after scanning), so these are manual-upload links only — "
            "download the image and drag it into each engine yourself."
        )
        mode = "manual_upload"

    return ReverseImageSearchResult(mode=mode, links=links, disclaimer=disclaimer)