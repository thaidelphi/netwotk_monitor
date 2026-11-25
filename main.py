"""Entry point for the Windows LAN IP & Port Scanner Desktop Application."""

from __future__ import annotations

import argparse
import sys

from scanner import LanScannerEngine, ScanConfig, detect_network_interfaces, parse_ip_range, parse_ports


def _run_cli_scan(range_start: str, range_end: str, ports_str: str) -> int:
    """Optional headless CLI test mode (`python main.py --cli 192.168.1.1 192.168.1.20`)."""
    interfaces = detect_network_interfaces()
    ips = parse_ip_range(range_start, range_end)
    ports = parse_ports(ports_str) if ports_str else []
    cfg = ScanConfig(
        target_ips=ips,
        scan_ports=bool(ports),
        ports=ports,
        local_interfaces=interfaces,
    )
    engine = LanScannerEngine()
    print(f"Scanning {len(ips)} IP(s): {ips[0]} -> {ips[-1]} ...")
    results = engine.run_scan(cfg)
    online = [r for r in results if r.online]
    online.sort(key=lambda r: tuple(int(x) for x in r.ip.split(".")))
    print(f"Found {len(online)} online host(s):")
    for r in online:
        print(
            f"  [ONLINE] {r.ip:<15} | {r.latency_text:<10} | {r.mac:<17} | "
            f"{r.vendor:<24} | Host: {r.hostname} | Ports: {r.ports_display}"
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="LAN IP Range & Port Scanner (Windows Desktop GUI)")
    parser.add_argument(
        "--cli",
        nargs="+",
        metavar=("START_IP", "END_IP"),
        help="Run a quick terminal scan instead of opening GUI (e.g. --cli 192.168.1.1 192.168.1.50)",
    )
    parser.add_argument(
        "--ports",
        default="22,80,139,443,445,3389,8080,9100",
        help="Comma-separated TCP ports for --cli mode",
    )
    args = parser.parse_args()

    if args.cli:
        start_ip = args.cli[0]
        end_ip = args.cli[1] if len(args.cli) > 1 else ""
        return _run_cli_scan(start_ip, end_ip, args.ports)

    from ui import launch_app

    launch_app()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
