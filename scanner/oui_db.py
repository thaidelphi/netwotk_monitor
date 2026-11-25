"""Offline IEEE OUI MAC Address Vendor lookup database (45,000+ prefixes) and randomized MAC detector."""

from __future__ import annotations

import json
from pathlib import Path

# Built-in fallback prefixes (6-char uppercase hex 'AABBCC') if external OUI file is absent
_FALLBACK_OUI: dict[str, str] = {
    "000569": "VMware",
    "000C29": "VMware",
    "005056": "VMware",
    "00155D": "Microsoft Hyper-V",
    "080027": "Oracle VirtualBox",
    "525400": "QEMU / KVM / Proxmox",
    "BC2411": "Proxmox Server Solutions",
    "00E04C": "Realtek Semiconductor",
    "000C42": "MikroTik",
    "18FD74": "MikroTik",
    "48A98A": "MikroTik",
    "D401C3": "MikroTik",
    "245A4C": "Ubiquiti",
    "7483C2": "Ubiquiti",
    "FCECDA": "Ubiquiti",
    "001BA9": "Brother Industries",
    "000048": "Seiko Epson",
    "001E8F": "Canon",
    "001132": "Synology",
    "245EBE": "QNAP Systems",
    "B827EB": "Raspberry Pi",
    "D83ADD": "Raspberry Pi",
    "240AC4": "Espressif",
}

_OUI_MAP: dict[str, str] = {}
_LOADED = False


def _ensure_oui_loaded() -> None:
    """Lazy-load 45,000+ IEEE OUI prefixes from oui_prefixes.txt and optional oui_custom.json."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    _OUI_MAP.update(_FALLBACK_OUI)

    base_dir = Path(__file__).parent
    prefixes_file = base_dir / "oui_prefixes.txt"
    if prefixes_file.is_file():
        try:
            with prefixes_file.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if not line or line[0] == "#":
                        continue
                    parts = line.strip().split(None, 1)
                    if len(parts) == 2 and len(parts[0]) == 6:
                        _OUI_MAP[parts[0].upper()] = parts[1].strip()
        except OSError:
            pass

    custom_path = base_dir / "oui_custom.json"
    if custom_path.is_file():
        try:
            data = json.loads(custom_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for k, v in data.items():
                    hex6 = "".join(ch for ch in str(k).upper() if ch in "0123456789ABCDEF")[:6]
                    if len(hex6) == 6:
                        _OUI_MAP[hex6] = str(v)
        except Exception:
            pass


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to uppercase XX:XX:XX:XX:XX:XX format."""
    cleaned = "".join(ch for ch in mac.upper() if ch in "0123456789ABCDEF")
    if len(cleaned) != 12:
        return mac.strip().upper()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def lookup_mac_vendor(mac: str) -> str:
    """Return manufacturer / vendor name from a MAC address."""
    if not mac or mac == "-":
        return "-"
    _ensure_oui_loaded()

    hex12 = "".join(ch for ch in mac.upper() if ch in "0123456789ABCDEF")
    if len(hex12) < 6:
        return "-"
    if hex12 == "FFFFFFFFFFFF":
        return "Broadcast"

    prefix6 = hex12[:6]
    vendor = _OUI_MAP.get(prefix6)
    if vendor:
        return vendor

    # Check locally administered bit (bit 1 of first octet): x2, x6, xA, xE
    try:
        first_octet = int(hex12[:2], 16)
        if first_octet & 0x01:
            return "Multicast Address"
        if first_octet & 0x02:
            return "Private / Randomized MAC"
    except ValueError:
        pass

    return "ไม่ทราบยี่ห้อ (Unknown OUI)"
