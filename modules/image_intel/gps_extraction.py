"""
modules/image_intel/gps_extraction.py
Extracts GPS coordinates from EXIF metadata (already parsed by exiftool)
and prepares them for map display.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import re


@dataclass
class GpsResult:
    available: bool = True
    error: Optional[str] = None
    has_gps: bool = False
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    direction: Optional[float] = None
    maps_url: Optional[str] = None
    raw_position: Optional[str] = None

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "has_gps": self.has_gps,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude": self.altitude,
            "direction": self.direction,
            "maps_url": self.maps_url,
            "raw_position": self.raw_position,
        }


def _parse_gps_position(value: str) -> Optional[tuple[float, float]]:
    """
    exiftool -j usually gives combined 'GPSPosition' like:
    '28 deg 36' 50.00" N, 77 deg 12' 32.00" E'
    or already-decimal 'GPSLatitude'/'GPSLongitude' fields.
    """
    if not value:
        return None
    pattern = r"(\d+)\s*deg\s*(\d+)'?\s*([\d.]+)\"?\s*([NSEW])"
    matches = re.findall(pattern, value)
    if len(matches) != 2:
        return None

    def dms_to_dd(deg, minute, sec, hemi):
        dd = float(deg) + float(minute) / 60 + float(sec) / 3600
        if hemi in ("S", "W"):
            dd = -dd
        return dd

    lat = dms_to_dd(*matches[0])
    lon = dms_to_dd(*matches[1])
    return lat, lon


def extract(metadata: dict) -> GpsResult:
    try:
        lat = metadata.get("GPSLatitude")
        lon = metadata.get("GPSLongitude")
        pos = metadata.get("GPSPosition")

        latitude = longitude = None

        # exiftool sometimes gives clean decimal values directly
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            latitude, longitude = float(lat), float(lon)
        elif isinstance(lat, str) and isinstance(lon, str):
            parsed_lat = _parse_gps_position(lat + ", " + "0 deg 0' 0\" N")
            # fallback: try parsing each field individually
            lat_match = re.search(r"(\d+)\s*deg\s*(\d+)'?\s*([\d.]+)\"?\s*([NS])", lat)
            lon_match = re.search(r"(\d+)\s*deg\s*(\d+)'?\s*([\d.]+)\"?\s*([EW])", lon)
            if lat_match and lon_match:
                def dms(m):
                    d, mi, s, h = m.groups()
                    dd = float(d) + float(mi)/60 + float(s)/3600
                    return -dd if h in ("S", "W") else dd
                latitude, longitude = dms(lat_match), dms(lon_match)
        elif isinstance(pos, str):
            parsed = _parse_gps_position(pos)
            if parsed:
                latitude, longitude = parsed

        if latitude is None or longitude is None:
            return GpsResult(has_gps=False)

        altitude = metadata.get("GPSAltitude")
        if isinstance(altitude, str):
            alt_match = re.search(r"([\d.]+)", altitude)
            altitude = float(alt_match.group(1)) if alt_match else None

        direction = metadata.get("GPSImgDirection")
        if isinstance(direction, str):
            dir_match = re.search(r"([\d.]+)", direction)
            direction = float(dir_match.group(1)) if dir_match else None

        return GpsResult(
            has_gps=True,
            latitude=round(latitude, 6),
            longitude=round(longitude, 6),
            altitude=altitude,
            direction=direction,
            maps_url=f"https://www.google.com/maps?q={latitude},{longitude}",
            raw_position=pos if isinstance(pos, str) else None,
        )
    except Exception as e:
        return GpsResult(available=False, error=str(e))