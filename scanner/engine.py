"""High-speed Windows LAN Scanner Engine using Win32 ICMP + SendARP + NetBIOS + mDNS + TCP."""

from __future__ import annotations

import ctypes
import ipaddress
import random
import socket
import struct
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .network_utils import COMMON_PORTS, NetworkInterface
from .os_fingerprint import collect_host_banners, detect_os
from .oui_db import lookup_mac_vendor, normalize_mac

# Win32 iphlpapi function bindings (64-bit safe)
_iphlpapi = ctypes.windll.iphlpapi

_IcmpCreateFile = _iphlpapi.IcmpCreateFile
_IcmpCreateFile.argtypes = []
_IcmpCreateFile.restype = ctypes.c_void_p

_IcmpCloseHandle = _iphlpapi.IcmpCloseHandle
_IcmpCloseHandle.argtypes = [ctypes.c_void_p]
_IcmpCloseHandle.restype = ctypes.c_bool

_IcmpSendEcho = _iphlpapi.IcmpSendEcho
_IcmpSendEcho.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.c_ushort,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
_IcmpSendEcho.restype = ctypes.c_ulong

_SendARP = _iphlpapi.SendARP
_SendARP.argtypes = [
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ulong),
]
_SendARP.restype = ctypes.c_ulong

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_ICMP_PAYLOAD = b"LANMON26"


@dataclass(slots=True)
class ScanConfig:
    target_ips: list[str]
    scan_ports: bool = True
    ports: list[int] = field(default_factory=lambda: [22, 80, 139, 443, 445, 3389, 8080, 9100])
    ping_timeout_ms: int = 600
    port_timeout_sec: float = 0.35
    max_workers: int = 96
    resolve_hostname: bool = True
    deep_inspect: bool = False
    local_interfaces: list[NetworkInterface] = field(default_factory=list)


@dataclass(slots=True)
class HostScanResult:
    ip: str
    online: bool
    hostname: str = "-"
    workgroup: str = ""
    latency_ms: int | None = None
    latency_text: str = "-"
    mac: str = "-"
    vendor: str = "-"
    device_type: str = "-"
    os_name: str = "-"
    os_confidence: str = "-"
    os_evidence: str = "-"
    open_ports: list[int] = field(default_factory=list)
    port_banners: dict[int, str] = field(default_factory=dict)
    smb_info: dict[str, str] = field(default_factory=dict)
    smb_shares: list[str] = field(default_factory=list)
    ssl_certs: list[dict[str, str]] = field(default_factory=list)
    snmp_info: dict[str, str] = field(default_factory=dict)
    upnp_info: dict[str, str] = field(default_factory=dict)
    discovery_method: str = "-"
    ttl: int | None = None
    deep_inspected: bool = False

    @property
    def ports_display(self) -> str:
        if not self.open_ports:
            return "-"
        items = []
        for p in self.open_ports:
            svc = COMMON_PORTS.get(p)
            items.append(f"{p} ({svc})" if svc else str(p))
        return ", ".join(items)


def win32_icmp_ping(ip_str: str, timeout_ms: int = 600) -> tuple[bool, int | None, int | None]:
    """
    Send ICMP Echo Request via iphlpapi.IcmpSendEcho.
    Returns (is_alive, rtt_ms, ttl).
    Verifies both Status == 0 (IP_SUCCESS) and Reply Address == target IP.
    """
    try:
        dest_uint32 = struct.unpack("=I", socket.inet_aton(ip_str))[0]
    except OSError:
        return False, None, None

    handle = _IcmpCreateFile()
    if not handle or handle == INVALID_HANDLE_VALUE:
        return False, None, None

    try:
        reply_buf = ctypes.create_string_buffer(256)
        for attempt in range(2):
            cur_timeout = timeout_ms if attempt == 0 else max(350, timeout_ms // 2)
            count = _IcmpSendEcho(
                handle,
                dest_uint32,
                _ICMP_PAYLOAD,
                len(_ICMP_PAYLOAD),
                None,
                reply_buf,
                ctypes.sizeof(reply_buf),
                cur_timeout,
            )
            if count > 0:
                reply_addr, status, rtt = struct.unpack_from("=III", reply_buf.raw, 0)
                if status == 0 and reply_addr == dest_uint32:
                    # Extract TTL from IP_OPTION_INFORMATION offset:
                    # 64-bit: 4+4+4+2+2 + 8(Data ptr) = offset 24
                    # 32-bit: 4+4+4+2+2 + 4(Data ptr) = offset 20
                    ptr_size = ctypes.sizeof(ctypes.c_void_p)
                    ttl_offset = 16 + ptr_size
                    ttl_val = reply_buf.raw[ttl_offset]
                    return True, int(rtt), int(ttl_val)
        return False, None, None
    finally:
        _IcmpCloseHandle(handle)


def win32_send_arp(ip_str: str, src_ip_str: str = "") -> str | None:
    """
    Send ARP request on local L2 segment via iphlpapi.SendARP.
    Returns formatted MAC address 'AA:BB:CC:DD:EE:FF' if host answers ARP, else None.
    """
    try:
        dest_uint32 = struct.unpack("=I", socket.inet_aton(ip_str))[0]
        src_uint32 = struct.unpack("=I", socket.inet_aton(src_ip_str))[0] if src_ip_str else 0
    except OSError:
        return None

    mac_buf = (ctypes.c_ubyte * 8)()
    mac_len = ctypes.c_ulong(6)
    res = _SendARP(dest_uint32, src_uint32, ctypes.byref(mac_buf), ctypes.byref(mac_len))
    if res == 0 and mac_len.value >= 6:
        raw_bytes = bytes(mac_buf[:6])
        if any(raw_bytes) and raw_bytes != b"\xff\xff\xff\xff\xff\xff":
            return normalize_mac(":".join(f"{b:02X}" for b in raw_bytes))
    return None


def query_netbios_info(ip_str: str, timeout: float = 0.35) -> tuple[str, str, str]:
    """
    Send UDP 137 NetBIOS Node Status Request (NBSTAT).
    Returns (hostname, workgroup, unit_mac) directly from Windows / Samba / Printer hosts.
    """
    tx_id = random.randint(1, 0xFFFF)
    # Standard NBSTAT wildcard '*' query packet (50 bytes)
    packet = (
        struct.pack(">HHHHHH", tx_id, 0x0000, 1, 0, 0, 0)
        + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        + struct.pack(">HH", 0x0021, 0x0001)
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (ip_str, 137))
            data, _ = sock.recvfrom(1024)
    except OSError:
        return "", "", ""

    if len(data) < 57:
        return "", "", ""

    # Locate answer section after the query name + QTYPE/QCLASS + RR header
    # Header(12) + Name(34) + Type(2) + Class(2) + TTL(4) + RDLENGTH(2) = 56; byte 56 is num_names
    idx = 56
    if idx >= len(data):
        return "", "", ""
    num_names = data[idx]
    idx += 1

    computer_name = ""
    workgroup = ""
    for _ in range(num_names):
        if idx + 18 > len(data):
            break
        raw_name = data[idx : idx + 15]
        suffix = data[idx + 15]
        flags = struct.unpack(">H", data[idx + 16 : idx + 18])[0]
        idx += 18

        is_group = bool(flags & 0x8000)
        try:
            decoded = raw_name.decode("cp874", errors="ignore").strip()
        except Exception:
            decoded = raw_name.decode("latin-1", errors="ignore").strip()
        # Strip non-printable control bytes
        decoded = "".join(ch for ch in decoded if ch.isprintable()).strip()
        if not decoded:
            continue

        if suffix == 0x00 and not is_group and not computer_name:
            computer_name = decoded
        elif suffix == 0x20 and not is_group and not computer_name:
            computer_name = decoded
        elif suffix == 0x00 and is_group and not workgroup:
            workgroup = decoded

    unit_mac = ""
    if idx + 6 <= len(data):
        mac_bytes = data[idx : idx + 6]
        if any(mac_bytes) and mac_bytes != b"\xff\xff\xff\xff\xff\xff":
            unit_mac = normalize_mac(":".join(f"{b:02X}" for b in mac_bytes))

    return computer_name, workgroup, unit_mac


def _parse_dns_ptr_response(resp: bytes, query_len: int) -> str:
    """Extract PTR domain name from a raw DNS/mDNS UDP response packet."""
    if len(resp) <= query_len + 12:
        return ""

    def _read_dns_name(buf: bytes, offset: int) -> tuple[str, int]:
        labels: list[str] = []
        jumped = False
        orig_next = offset
        hops = 0
        while offset < len(buf) and hops < 24:
            hops += 1
            length = buf[offset]
            if length == 0:
                if not jumped:
                    orig_next = offset + 1
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(buf):
                    break
                ptr = ((length & 0x3F) << 8) | buf[offset + 1]
                if not jumped:
                    orig_next = offset + 2
                    jumped = True
                offset = ptr
            else:
                end = offset + 1 + length
                if end > len(buf):
                    break
                labels.append(buf[offset + 1 : end].decode("utf-8", errors="ignore"))
                offset = end
        return ".".join(labels), orig_next

    try:
        ancount = struct.unpack(">H", resp[6:8])[0]
        if ancount == 0:
            return ""
        pos = query_len
        for _ in range(ancount):
            _, pos = _read_dns_name(resp, pos)
            if pos + 10 > len(resp):
                break
            rtype, _, _, rdlen = struct.unpack(">HHIH", resp[pos : pos + 10])
            pos += 10
            if rtype == 12:  # PTR
                name, _ = _read_dns_name(resp, pos)
                if name:
                    return name.rstrip(".")
            pos += rdlen
    except Exception:
        pass
    return ""


def _build_ptr_query(ip_str: str) -> bytes:
    reversed_octets = list(reversed(ip_str.split("."))) + ["in-addr", "arpa"]
    qname = b"".join(bytes([len(lbl)]) + lbl.encode("ascii") for lbl in reversed_octets) + b"\x00"
    tx_id = random.randint(1, 0xFFFF)
    return struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)


def get_system_dns_servers() -> list[str]:
    """Read configured IPv4 DNS servers from Windows registry / iphlpapi without spawning subprocesses."""
    servers: list[str] = []
    try:
        import winreg

        base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as root_k:
            idx = 0
            while True:
                try:
                    sub = winreg.EnumKey(root_k, idx)
                    idx += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(root_k, sub) as sub_k:
                        for val_name in ("NameServer", "DhcpNameServer"):
                            try:
                                val, _ = winreg.QueryValueEx(sub_k, val_name)
                                for token in str(val).replace(",", " ").split():
                                    token = token.strip()
                                    if token and "." in token and token not in servers:
                                        ipaddress.IPv4Address(token)
                                        servers.append(token)
                            except (OSError, ValueError):
                                continue
                except OSError:
                    continue
    except Exception:
        pass
    return servers[:3]


def query_dns_ptr(ip_str: str, dns_servers: list[str], timeout: float = 0.3) -> str:
    """Fast direct UDP 53 PTR lookup (avoids Windows gethostbyaddr 4.5s NetBT stall)."""
    if not dns_servers:
        return ""
    query = _build_ptr_query(ip_str)
    for srv in dns_servers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(query, (srv, 53))
                resp, _ = sock.recvfrom(1024)
            ptr_name = _parse_dns_ptr_response(resp, len(query))
            if ptr_name and ptr_name != ip_str:
                return ptr_name
        except OSError:
            continue
    return ""


def query_mdns_ptr(ip_str: str, timeout: float = 0.25) -> str:
    """Send unicast UDP 5353 mDNS reverse PTR query for x.x.x.x.in-addr.arpa."""
    query = _build_ptr_query(ip_str)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (ip_str, 5353))
            resp, _ = sock.recvfrom(1024)
        return _parse_dns_ptr_response(resp, len(query))
    except OSError:
        return ""


def probe_tcp_port(ip_str: str, port: int, timeout: float = 0.35) -> tuple[bool, int | None]:
    """Attempt TCP connection to (ip_str, port). Returns (is_open, connect_ms)."""
    t0 = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            err = sock.connect_ex((ip_str, port))
            if err == 0:
                elapsed_ms = int(round((time.perf_counter() - t0) * 1000))
                return True, elapsed_ms
    except OSError:
        pass
    return False, None


def infer_device_type(
    ip_str: str,
    is_local_pc: bool,
    gateway_ips: set[str],
    open_ports: list[int],
    vendor: str,
    ttl: int | None,
    hostname: str,
) -> str:
    """Classify the discovered host into a clear Thai/English device role."""
    if is_local_pc:
        return "เครื่องนี้ (This PC)"
    if ip_str in gateway_ips:
        return "Gateway / Router"

    ports_set = set(open_ports)
    v_low = vendor.lower()
    h_low = hostname.lower()

    if ports_set & {9100, 515, 631} or any(
        b in v_low for b in ("brother", "epson", "canon", "ricoh", "kyocera", "xerox")
    ):
        return "เครื่องพิมพ์ (Printer)"

    if 554 in ports_set or any(
        b in v_low for b in ("hikvision", "dahua", "axis", "uniview", "zkteco")
    ):
        return "กล้อง / NVR / Access"

    if any(b in v_low for b in ("synology", "qnap")) or ports_set & {5000, 5001}:
        return "NAS / Storage"

    if any(
        b in v_low
        for b in ("mikrotik", "ubiquiti", "cisco", "tp-link", "ruijie", "fortinet", "aruba", "zyxel")
    ):
        return "อุปกรณ์เครือข่าย (Network)"

    if 3389 in ports_set or ((ports_set & {135, 139, 445}) and (ttl is None or 96 < ttl <= 128)):
        return "Windows PC / Server"

    if 22 in ports_set and (ttl is not None and ttl <= 64):
        return "Linux / Server"

    if ttl is not None:
        if 96 < ttl <= 128:
            return "Windows Host"
        if ttl > 200:
            return "Network Switch / Gear"

    if any(b in v_low for b in ("apple", "samsung", "xiaomi", "oppo", "vivo")) or (
        "iphone" in h_low or "ipad" in h_low or "android" in h_low
    ):
        return "มือถือ / แท็บเล็ต"

    if ports_set & {80, 443, 8080, 8443}:
        return "Web / Smart Device"

    return "อุปกรณ์ในแลน (Host)"


class LanScannerEngine:
    """Concurrent LAN scanner with clean start/stop lifecycle and streaming callbacks."""

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._running = False
        self._dns_servers: list[str] = []

    @property
    def is_running(self) -> bool:
        return self._running

    def stop(self) -> None:
        self._stop_event.set()

    def scan_single_host(
        self,
        ip_str: str,
        config: ScanConfig,
        local_ip_map: dict[str, NetworkInterface],
        local_networks: list[tuple[ipaddress.IPv4Network, NetworkInterface]],
        gateway_ips: set[str],
    ) -> HostScanResult:
        """Scan one IPv4 target using ARP + ICMP + fallback TCP + Hostname + Port Scan."""
        if self._stop_event.is_set():
            return HostScanResult(ip=ip_str, online=False)

        # 1. Check if target is one of the local PC's own adapter IPs
        if ip_str in local_ip_map:
            iface = local_ip_map[ip_str]
            local_name = socket.gethostname()
            open_ports: list[int] = []
            if config.scan_ports and config.ports:
                for p in config.ports:
                    if self._stop_event.is_set():
                        break
                    is_open, _ = probe_tcp_port(ip_str, p, timeout=0.15)
                    if is_open:
                        open_ports.append(p)
            vendor = lookup_mac_vendor(iface.mac)
            banner_data = collect_host_banners(ip_str, open_ports, timeout_scale=0.6)
            os_name, os_conf, os_ev = detect_os(
                is_local_pc=True,
                open_ports=open_ports,
                ttl=128,
                vendor=vendor,
                hostname=local_name,
                smb_info=banner_data["smb"],  # type: ignore[arg-type]
                ssh_banner=banner_data["ssh"],  # type: ignore[arg-type]
                http_infos=banner_data["http"],  # type: ignore[arg-type]
            )
            return HostScanResult(
                ip=ip_str,
                online=True,
                hostname=local_name,
                latency_ms=0,
                latency_text="<1 ms",
                mac=iface.mac,
                vendor=vendor,
                device_type="เครื่องนี้ (This PC)",
                os_name=os_name,
                os_confidence=os_conf,
                os_evidence=os_ev,
                open_ports=open_ports,
                port_banners=banner_data["banners"],  # type: ignore[arg-type]
                smb_info=banner_data["smb"],  # type: ignore[arg-type]
                discovery_method="Local NIC",
                ttl=128,
            )

        # Determine if IP belongs to one of our directly-attached L2 subnets (where ARP works)
        ip_obj = ipaddress.IPv4Address(ip_str)
        matching_iface: NetworkInterface | None = None
        for net, iface in local_networks:
            if ip_obj in net and net.prefixlen < 32:
                matching_iface = iface
                break

        # 2. ICMP Ping + Local Subnet ARP
        icmp_alive, rtt_ms, ttl = win32_icmp_ping(ip_str, timeout_ms=config.ping_timeout_ms)

        mac_addr: str | None = None
        if matching_iface is not None and not self._stop_event.is_set():
            mac_addr = win32_send_arp(ip_str, matching_iface.ip)

        arp_alive = mac_addr is not None
        tcp_alive = False
        tcp_rtt_ms: int | None = None
        pre_open_ports: set[int] = set()

        # 3. Fallback quick TCP probe when not on local L2 (or when ARP didn't reply) and ICMP is blocked
        if not icmp_alive and not arp_alive and not self._stop_event.is_set():
            quick_ports = [80, 443, 445, 3389, 22]
            for qp in quick_ports:
                if self._stop_event.is_set():
                    break
                ok, c_ms = probe_tcp_port(ip_str, qp, timeout=min(0.25, config.port_timeout_sec))
                if ok:
                    tcp_alive = True
                    tcp_rtt_ms = c_ms
                    pre_open_ports.add(qp)
                    break

        online = icmp_alive or arp_alive or tcp_alive
        if not online:
            return HostScanResult(ip=ip_str, online=False)

        # Build discovery method + latency text
        methods = []
        if arp_alive:
            methods.append("ARP")
        if icmp_alive:
            methods.append("ICMP")
        if tcp_alive:
            methods.append("TCP")
        discovery_method = "+".join(methods)

        if icmp_alive and rtt_ms is not None:
            latency_ms = rtt_ms
            latency_text = "<1 ms" if rtt_ms == 0 else f"{rtt_ms} ms"
        elif tcp_rtt_ms is not None:
            latency_ms = tcp_rtt_ms
            latency_text = f"~{max(1, tcp_rtt_ms)} ms (TCP)"
        else:
            latency_ms = 1
            latency_text = "Online (Firewall)"

        # 4. Resolve Hostname (NetBIOS + Reverse DNS + mDNS)
        hostname = "-"
        workgroup = ""
        if config.resolve_hostname and not self._stop_event.is_set():
            nb_name, nb_wg, nb_mac = query_netbios_info(ip_str, timeout=0.35)
            if nb_wg:
                workgroup = nb_wg
            if not mac_addr and nb_mac:
                mac_addr = nb_mac

            dns_servers = self._dns_servers or get_system_dns_servers()
            for gw in gateway_ips:
                if gw not in dns_servers:
                    dns_servers = [*dns_servers, gw]
            dns_name = query_dns_ptr(ip_str, dns_servers, timeout=0.28)

            if dns_name:
                hostname = dns_name
                if nb_name and nb_name.lower() not in dns_name.lower():
                    hostname = f"{nb_name} ({dns_name})"
            elif nb_name:
                hostname = nb_name
            else:
                mdns_name = query_mdns_ptr(ip_str, timeout=0.28)
                if mdns_name:
                    hostname = mdns_name

        # 5. Port Scan on alive host
        open_ports_list: list[int] = []
        if config.scan_ports and config.ports and not self._stop_event.is_set():
            for p in config.ports:
                if self._stop_event.is_set():
                    break
                if p in pre_open_ports:
                    open_ports_list.append(p)
                    continue
                is_open, c_ms = probe_tcp_port(ip_str, p, timeout=config.port_timeout_sec)
                if is_open:
                    open_ports_list.append(p)
                    if latency_text == "Online (Firewall)" and c_ms is not None:
                        latency_ms = c_ms
                        latency_text = f"~{max(1, c_ms)} ms (TCP)"

        final_mac = mac_addr if mac_addr else "-"
        vendor = lookup_mac_vendor(final_mac) if final_mac != "-" else "-"

        # 6. Banner Grabbing & OS Detection
        banner_data = {
            "smb": {},
            "smb_shares": [],
            "ssh": "",
            "http": [],
            "ssl_certs": [],
            "snmp": {},
            "upnp": {},
            "banners": {},
        }
        if (open_ports_list or config.deep_inspect) and not self._stop_event.is_set():
            banner_data = collect_host_banners(
                ip_str,
                open_ports_list,
                timeout_scale=1.0,
                probe_udp_services=config.deep_inspect,
            )
            smb_dict: dict[str, str] = banner_data["smb"]  # type: ignore[assignment]
            snmp_dict: dict[str, str] = banner_data["snmp"]  # type: ignore[assignment]
            if hostname == "-" and smb_dict.get("dns_computer"):
                hostname = smb_dict["dns_computer"]
            elif hostname == "-" and smb_dict.get("nb_computer"):
                hostname = smb_dict["nb_computer"]
            elif hostname == "-" and snmp_dict.get("sys_name"):
                hostname = snmp_dict["sys_name"]
            if not workgroup and smb_dict.get("nb_domain"):
                workgroup = smb_dict["nb_domain"]

        os_name, os_conf, os_ev = detect_os(
            is_local_pc=False,
            open_ports=open_ports_list,
            ttl=ttl,
            vendor=vendor,
            hostname=hostname,
            smb_info=banner_data["smb"],  # type: ignore[arg-type]
            ssh_banner=banner_data["ssh"],  # type: ignore[arg-type]
            http_infos=banner_data["http"],  # type: ignore[arg-type]
        )

        dev_type = infer_device_type(
            ip_str=ip_str,
            is_local_pc=False,
            gateway_ips=gateway_ips,
            open_ports=open_ports_list,
            vendor=vendor,
            ttl=ttl,
            hostname=hostname,
        )

        return HostScanResult(
            ip=ip_str,
            online=True,
            hostname=hostname,
            workgroup=workgroup,
            latency_ms=latency_ms,
            latency_text=latency_text,
            mac=final_mac,
            vendor=vendor,
            device_type=dev_type,
            os_name=os_name,
            os_confidence=os_conf,
            os_evidence=os_ev,
            open_ports=open_ports_list,
            port_banners=banner_data["banners"],  # type: ignore[arg-type]
            smb_info=banner_data["smb"],  # type: ignore[arg-type]
            smb_shares=banner_data["smb_shares"],  # type: ignore[arg-type]
            ssl_certs=banner_data["ssl_certs"],  # type: ignore[arg-type]
            snmp_info=banner_data["snmp"],  # type: ignore[arg-type]
            upnp_info=banner_data["upnp"],  # type: ignore[arg-type]
            discovery_method=discovery_method,
            ttl=ttl,
            deep_inspected=config.deep_inspect,
        )

    def run_scan(
        self,
        config: ScanConfig,
        on_host_done: Callable[[HostScanResult, int, int], None] | None = None,
        on_finished: Callable[[bool, float], None] | None = None,
    ) -> list[HostScanResult]:
        """Run a full IP range scan synchronously (call from worker thread for GUI)."""
        self._stop_event.clear()
        self._running = True
        self._dns_servers = get_system_dns_servers()
        start_time = time.perf_counter()

        local_ip_map = {iface.ip: iface for iface in config.local_interfaces}
        local_networks: list[tuple[ipaddress.IPv4Network, NetworkInterface]] = []
        gateway_ips: set[str] = set()
        for iface in config.local_interfaces:
            if iface.gateway:
                gateway_ips.add(iface.gateway)
            try:
                net = ipaddress.IPv4Network(f"{iface.ip}/{iface.prefix_len}", strict=False)
                local_networks.append((net, iface))
            except ValueError:
                pass

        total = len(config.target_ips)
        results: list[HostScanResult] = []
        completed_count = 0

        try:
            workers = max(1, min(config.max_workers, total or 1))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="lanscan") as pool:
                future_map = {
                    pool.submit(
                        self.scan_single_host,
                        ip,
                        config,
                        local_ip_map,
                        local_networks,
                        gateway_ips,
                    ): ip
                    for ip in config.target_ips
                }
                for fut in as_completed(future_map):
                    if self._stop_event.is_set():
                        for pending in future_map:
                            pending.cancel()
                        break
                    try:
                        res = fut.result()
                    except Exception:
                        res = HostScanResult(ip=future_map[fut], online=False)
                    completed_count += 1
                    results.append(res)
                    if on_host_done is not None:
                        on_host_done(res, completed_count, total)
        finally:
            self._running = False
            elapsed = time.perf_counter() - start_time
            was_cancelled = self._stop_event.is_set()
            if on_finished is not None:
                on_finished(was_cancelled, elapsed)

        return results
