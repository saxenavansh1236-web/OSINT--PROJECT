"""
modules/image_intel/color_palette.py
Dominant color extraction using Pillow's built-in adaptive palette
quantization (no external clustering library needed).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

try:
    from PIL import Image
    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False


@dataclass
class ColorEntry:
    hex: str
    rgb: tuple
    percentage: float

    def to_dict(self):
        return {"hex": self.hex, "rgb": list(self.rgb), "percentage": self.percentage}


@dataclass
class ColorPaletteResult:
    available: bool = True
    error: Optional[str] = None
    dominant_colors: list = field(default_factory=list)
    palette_swatch_hexes: list = field(default_factory=list)
    average_color: str = ""
    brightness: float = 0.0
    is_grayscale: bool = False

    def to_dict(self):
        return {
            "available": self.available, "error": self.error,
            "dominant_colors": [c.to_dict() for c in self.dominant_colors],
            "palette_swatch_hexes": self.palette_swatch_hexes,
            "average_color": self.average_color,
            "brightness": self.brightness,
            "is_grayscale": self.is_grayscale,
        }


def _rgb_to_hex(rgb):
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def extract(filepath: str, num_colors: int = 6) -> ColorPaletteResult:
    if not _DEPS_OK:
        return ColorPaletteResult(available=False, error="Pillow not installed. Run: pip install pillow")

    try:
        img = Image.open(filepath).convert("RGB")
        img_small = img.resize((150, 150))  # speed up quantization

        quantized = img_small.quantize(colors=num_colors, method=Image.MEDIANCUT)
        palette = quantized.getpalette()
        color_counts = sorted(quantized.getcolors(), reverse=True)
        total_pixels = sum(c for c, _ in color_counts)

        dominant_colors = []
        swatch_hexes = []
        for count, idx in color_counts[:num_colors]:
            r, g, b = palette[idx * 3: idx * 3 + 3]
            pct = round((count / total_pixels) * 100, 1)
            hex_val = _rgb_to_hex((r, g, b))
            dominant_colors.append(ColorEntry(hex=hex_val, rgb=(r, g, b), percentage=pct))
            swatch_hexes.append(hex_val)

        # Average color + grayscale check across the full-res image (downsampled for speed)
        small = img.resize((64, 64))
        pixels = list(small.getdata())
        avg_r = sum(p[0] for p in pixels) // len(pixels)
        avg_g = sum(p[1] for p in pixels) // len(pixels)
        avg_b = sum(p[2] for p in pixels) // len(pixels)
        brightness = round((avg_r + avg_g + avg_b) / 3, 1)

        # Grayscale heuristic: channels very close together across sampled pixels
        max_channel_spread = max(
            abs(p[0] - p[1]) + abs(p[1] - p[2]) + abs(p[0] - p[2]) for p in pixels[::10]
        )
        is_grayscale = max_channel_spread < 300  # loose heuristic across ~400 sampled pixels

        return ColorPaletteResult(
            dominant_colors=dominant_colors,
            palette_swatch_hexes=swatch_hexes,
            average_color=_rgb_to_hex((avg_r, avg_g, avg_b)),
            brightness=brightness,
            is_grayscale=is_grayscale,
        )
    except Exception as e:
        return ColorPaletteResult(available=False, error=str(e))