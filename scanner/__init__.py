"""LAN Scanner package for Windows network discovery and port scanning."""

from .engine import HostScanResult, LanScannerEngine, ScanConfig
from .network_utils import (
    COMMON_PORTS,
    PORT_PRESETS,
    NetworkInterface,
    detect_network_interfaces,
    ip_to_int,
    parse_ip_range,
    parse_ports,
)
from .oui_db import lookup_mac_vendor

__all__ = [
    "COMMON_PORTS",
    "PORT_PRESETS",
    "HostScanResult",
    "LanScannerEngine",
    "NetworkInterface",
    "ScanConfig",
    "detect_network_interfaces",
    "ip_to_int",
    "lookup_mac_vendor",
    "parse_ip_range",
    "parse_ports",
]
