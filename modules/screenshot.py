"""
screenshot.py — Website screenshot capture for evidence collection.

Features
--------
* Full-page screenshot via Playwright (headless Chromium)
* Viewport screenshot (above-the-fold)
* Metadata capture: title, final URL, HTTP status, timestamp
* Evidence packaging: adds watermark + metadata strip to image
* PDF export of full page
* Storage to evidence directory with deterministic filenames
* PIL-based overlay (timestamp + URL watermark)
"""

from __future__ import annotations

import hashlib
import io
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    _PLAYWRIGHT_OK = True
except ImportError:
    _PLAYWRIGHT_OK = False

try:
    from PIL import Image, ImageDraw, ImageFont
    _PIL_OK = True
except ImportError:
    _PIL_OK = False

EVIDENCE_DIR = os.environ.get("OSINT_EVIDENCE_DIR", "/tmp/osint_evidence")


# ─────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────

@dataclass
class ScreenshotResult:
    url: str
    final_url: str
    title: str
    status_code: int
    timestamp: str
    screenshot_path: str          # path to PNG (with watermark)
    viewport_path: str            # viewport-only PNG
    pdf_path: str                 # "" if not exported
    url_hash: str                 # sha1 of final_url (for dedup)
    file_size_kb: float
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def capture(
    url: str,
    *,
    full_page: bool = True,
    export_pdf: bool = False,
    evidence_dir: str = EVIDENCE_DIR,
    watermark: bool = True,
) -> ScreenshotResult:
    """
    Capture a screenshot of *url*.

    Args:
        url:          Target URL (http:// or https://).
        full_page:    Capture full scrollable page (True) or viewport only (False).
        export_pdf:   Also save a PDF of the full page.
        evidence_dir: Directory to save files.
        watermark:    Stamp timestamp + URL onto the image.

    Returns ScreenshotResult with file paths and metadata.
    """
    if not _PLAYWRIGHT_OK:
        return ScreenshotResult(
            url=url, final_url=url, title="", status_code=0,
            timestamp="", screenshot_path="", viewport_path="",
            pdf_path="", url_hash="", file_size_kb=0,
            error="playwright not installed. Run: playwright install chromium",
        )

    url = _normalize(url)
    ts  = datetime.now(timezone.utc)
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    ts_file = ts.strftime("%Y%m%d_%H%M%S")

    Path(evidence_dir).mkdir(parents=True, exist_ok=True)
    url_hash = hashlib.sha1(url.encode()).hexdigest()[:12]

    base = Path(evidence_dir) / f"{ts_file}_{url_hash}"
    full_path     = str(base) + "_full.png"
    viewport_path = str(base) + "_viewport.png"
    pdf_path      = str(base) + ".pdf" if export_pdf else ""

    title = ""
    final_url = url
    status_code = 0
    error = ""

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage",
                      "--disable-blink-features=AutomationControlled"],
            )
            ctx = browser.new_context(
                viewport={"width": 1440, "height": 900},
                user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            )
            page = ctx.new_page()

            # Navigate
            try:
                resp = page.goto(url, wait_until="networkidle", timeout=25_000)
                status_code = resp.status if resp else 0
                final_url   = page.url
                title       = page.title()
            except PWTimeout:
                # Partial load — still take screenshot
                final_url = page.url
                title     = page.title()
                error     = "Page load timed out — partial screenshot captured"

            # Full-page screenshot
            page.screenshot(path=full_path, full_page=True, timeout=15_000)
            # Viewport screenshot
            page.screenshot(path=viewport_path, full_page=False, timeout=10_000)
            # PDF
            if export_pdf:
                page.pdf(path=pdf_path, format="A4", print_background=True)

            browser.close()

    except Exception as exc:
        error = str(exc)
        return ScreenshotResult(
            url=url, final_url=final_url, title=title,
            status_code=status_code, timestamp=ts_str,
            screenshot_path="", viewport_path="", pdf_path="",
            url_hash=url_hash, file_size_kb=0, error=error,
        )

    # ── Watermark ────────────────────────────────────────────────────────────
    if watermark and _PIL_OK and os.path.exists(full_path):
        _watermark(full_path, final_url, ts_str)

    file_size_kb = _kb(full_path)

    return ScreenshotResult(
        url=url,
        final_url=final_url,
        title=title,
        status_code=status_code,
        timestamp=ts_str,
        screenshot_path=full_path,
        viewport_path=viewport_path,
        pdf_path=pdf_path,
        url_hash=url_hash,
        file_size_kb=file_size_kb,
        error=error,
    )


def capture_many(urls: list[str], **kwargs) -> list[ScreenshotResult]:
    """Capture screenshots for a list of URLs sequentially."""
    return [capture(url, **kwargs) for url in urls]


# ─────────────────────────────────────────────
# Watermark
# ─────────────────────────────────────────────

def _watermark(path: str, url: str, timestamp: str) -> None:
    try:
        img = Image.open(path).convert("RGBA")
        w, h = img.size

        # Semi-transparent black strip at bottom
        strip_h = 36
        overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
        draw    = ImageDraw.Draw(overlay)
        draw.rectangle([(0, h - strip_h), (w, h)], fill=(0, 0, 0, 160))

        # Text
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
        except Exception:
            font = ImageFont.load_default()

        text = f"OSINT Evidence  |  {timestamp}  |  {url[:80]}"
        draw.text((10, h - strip_h + 10), text, fill=(255, 255, 255, 230), font=font)

        combined = Image.alpha_composite(img, overlay).convert("RGB")
        combined.save(path, "PNG")
    except Exception:
        pass    # watermark is best-effort


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _normalize(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "https://" + url.strip()
    return url.strip()


def _kb(path: str) -> float:
    try:
        return os.path.getsize(path) / 1024
    except Exception:
        return 0.0