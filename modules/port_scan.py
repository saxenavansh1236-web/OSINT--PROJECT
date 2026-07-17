"""
port_scan.py — Open port discovery and service/banner detection
No external dependencies beyond stdlib. Uses TCP connect scanning.
"""

import socket
import concurrent.futures
import re
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Well-known port → service map ─────────────────────────────────────────
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Submission", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle-DB", 2049: "NFS",
    2375: "Docker-API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 6443: "K8s-API", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 9200: "Elasticsearch",
    27017: "MongoDB", 27018: "MongoDB-Alt",
}

# Risk flags for dangerous open ports
RISKY_PORTS = {
    21: "FTP often uses cleartext — check for anonymous login",
    23: "Telnet is unencrypted — replace with SSH",
    25: "Open SMTP relay may allow spam abuse",
    135: "MSRPC exposed — common attack vector on Windows",
    139: "NetBIOS exposed — legacy Windows vulnerability",
    445: "SMB exposed — EternalBlue/WannaCry attack surface",
    2375: "Docker API exposed without TLS — critical risk",
    3389: "RDP exposed — brute-force and BlueKeep risk",
    5900: "VNC exposed — usually unencrypted, brute-force risk",
    6379: "Redis exposed — often unauthenticated, RCE risk",
    9200: "Elasticsearch exposed — data exfiltration risk",
    27017: "MongoDB exposed — often unauthenticated",
}

# Common port lists
COMMON_PORTS = list(SERVICE_MAP.keys())
TOP_100_PORTS = sorted(list(set(COMMON_PORTS + [
    81, 82, 83, 84, 85, 88, 8000, 8008, 8081, 8082, 8083, 8084,
    8085, 8088, 8090, 8181, 8280, 8281, 8383, 8484, 8585, 8888,
    9000, 9001, 9090, 9091, 9092, 9093, 9094, 9095, 9100, 9999,
    10000, 10443, 11211, 15672, 61616,
])))

# Lowered from 80 -> 20. This is I/O-bound work (raw socket connects +
# banner grabs), so fewer concurrent threads only adds a modest amount of
# wall-clock time to the scan, but meaningfully reduces peak memory (each
# thread carries its own stack + socket overhead). This was contributing
# to OOM worker kills on memory-constrained hosts (e.g. Render free tier's
# 512MB).
DEFAULT_MAX_WORKERS = 20


@dataclass
class PortResult:
    port: int
    state: str          # "open" | "closed" | "filtered"
    service: str = ""
    banner: str = ""
    risk: str = ""


@dataclass
class PortScanResult:
    target: str
    ip: str = ""
    open_ports: list = field(default_factory=list)   # list of PortResult dicts
    total_scanned: int = 0
    scan_mode: str = "common"
    risky_ports: list = field(default_factory=list)
    summary: str = ""
    error: Optional[str] = None

    def to_dict(self):
        return asdict(self)


def _resolve(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target


def _grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """Attempt to grab a service banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # Send a probe for HTTP ports
        if port in (80, 8080, 8000, 8008, 8081, 8888):
            s.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
        else:
            s.send(b"\r\n")
        banner = s.recv(256).decode("utf-8", errors="replace").strip()
        s.close()
        # Clean up banner
        banner = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", banner)[:120]
        return banner
    except Exception:
        return ""


def _scan_port(ip: str, port: int, timeout: float = 1.2, grab_banners: bool = True) -> Optional[PortResult]:
    """Scan a single port. Returns PortResult if open, None if closed."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            service  = SERVICE_MAP.get(port, "unknown")
            banner   = _grab_banner(ip, port) if grab_banners else ""
            risk     = RISKY_PORTS.get(port, "")
            return PortResult(port=port, state="open", service=service,
                              banner=banner, risk=risk)
    except Exception:
        pass
    return None


def scan(
    target: str,
    mode: str = "common",          # "common" | "top100" | "full" | custom list
    ports: Optional[list] = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    timeout: float = 1.2,
    grab_banners: bool = True,
) -> PortScanResult:
    """
    Main entry point.

    Args:
        target:       Domain or IP to scan
        mode:         "common" (~30 ports), "top100", "full" (1-1024)
        ports:        Override with a specific list of port numbers
        max_workers:  Thread count for parallel scanning
        timeout:      Per-port connection timeout (seconds)
        grab_banners: Attempt banner grabbing on open ports
    """
    target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    result = PortScanResult(target=target, scan_mode=mode)

    # ── Resolve IP ────────────────────────────────────────────────────────
    result.ip = _resolve(target)

    # ── Choose port list ──────────────────────────────────────────────────
    if ports:
        port_list = sorted(ports)
        result.scan_mode = "custom"
    elif mode == "full":
        port_list = list(range(1, 1025))
    elif mode == "top100":
        port_list = TOP_100_PORTS
    else:
        port_list = COMMON_PORTS

    result.total_scanned = len(port_list)

    # ── Parallel scan ─────────────────────────────────────────────────────
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_scan_port, result.ip, p, timeout, grab_banners): p
            for p in port_list
        }
        for future in concurrent.futures.as_completed(futures):
            pr = future.result()
            if pr:
                open_ports.append(pr)

    # Sort by port number
    open_ports.sort(key=lambda x: x.port)
    result.open_ports = [asdict(p) for p in open_ports]
    result.risky_ports = [p for p in result.open_ports if p.get("risk")]

    # ── Summary ───────────────────────────────────────────────────────────
    n_open  = len(result.open_ports)
    n_risky = len(result.risky_ports)
    result.summary = (
        f"{n_open} open port(s) found out of {result.total_scanned} scanned. "
        f"{n_risky} port(s) flagged as risky."
    )

    return result
