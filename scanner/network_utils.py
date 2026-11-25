"""Network interface detection, IP range parsing, and port preset utilities."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import ipaddress
import re
import socket
from dataclasses import dataclass

from .oui_db import normalize_mac

# Comprehensive TCP service ports (105 high-value LAN, Enterprise, DevOps, DB, CCTV, IoT, and Printer ports)
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    69: "TFTP-TCP",
    79: "Finger",
    80: "HTTP",
    81: "HTTP-81",
    88: "Kerberos",
    110: "POP3",
    111: "RPCbind",
    113: "Ident",
    119: "NNTP",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP-TCP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE-TCP",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    515: "LPD-Print",
    548: "AFP-Mac",
    554: "RTSP-Cam",
    587: "Submission",
    631: "IPP-Print",
    636: "LDAPS",
    873: "Rsync",
    902: "VMware-Auth",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle-DB",
    1723: "PPTP",
    1883: "MQTT",
    2049: "NFS",
    2121: "FTP-Alt",
    2375: "Docker-API",
    2376: "Docker-TLS",
    2379: "etcd",
    3000: "Grafana/Web",
    3128: "Squid-Proxy",
    3268: "AD-GC",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4000: "Web-4000",
    4369: "Erlang-EPMD",
    4443: "HTTPS-4443",
    4505: "SaltStack",
    4848: "GlassFish",
    5000: "UPnP/NAS",
    5001: "NAS-SSL",
    5060: "SIP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "RabbitMQ",
    5800: "VNC-HTTP",
    5900: "VNC",
    5901: "VNC-1",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6000: "X11",
    6379: "Redis",
    6443: "Kubernetes-API",
    7001: "WebLogic",
    7070: "AnyDesk",
    7474: "Neo4j",
    8000: "HTTP-8000",
    8006: "Proxmox-VE",
    8008: "HTTP-8008",
    8009: "Tomcat-AJP",
    8080: "HTTP-Alt",
    8081: "HTTP-8081",
    8088: "HTTP-8088",
    8090: "HTTP-8090",
    8161: "ActiveMQ",
    8181: "HTTP-8181",
    8200: "MiniDLNA",
    8291: "MikroTik-Winbox",
    8443: "HTTPS-Alt",
    8500: "Consul",
    8728: "MikroTik-API",
    8729: "MikroTik-API-SSL",
    8883: "MQTTS",
    8888: "Jupyter/Web",
    9000: "Portainer/Web",
    9001: "Supervisor",
    9042: "Cassandra",
    9090: "Prometheus/Cockpit",
    9100: "Printer-RAW",
    9200: "Elasticsearch",
    9443: "Portainer-SSL",
    10000: "Webmin",
    11211: "Memcached",
    27017: "MongoDB",
    32400: "Plex",
    37777: "Dahua-DVR",
}

PORT_PRESETS: dict[str, str] = {
    "พอร์ตพื้นฐาน (เร็ว - 8 พอร์ต)": "22, 80, 139, 443, 445, 3389, 8080, 9100",
    "สำนักงานครบถ้วน (16 พอร์ต)": "21, 22, 23, 53, 80, 135, 139, 443, 445, 554, 631, 3306, 3389, 5900, 8080, 9100",
    "เจาะลึก / VA ละเอียด (106 พอร์ต)": ", ".join(str(p) for p in sorted(COMMON_PORTS.keys())),
    "Well-Known Ports ทั้งหมด (1-1024)": "1-1024",
    "กล้องวงจรปิด / IoT / NAS": "22, 80, 443, 445, 554, 1883, 5000, 5001, 8000, 8080, 8200, 8443, 37777",
    "เซิร์ฟเวอร์ / ฐานข้อมูล / DevOps": "21, 22, 53, 80, 88, 389, 443, 445, 636, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5985, 6379, 6443, 8006, 8080, 8443, 9000, 9090, 9200, 11211, 27017",
}


@dataclass(slots=True)
class NetworkInterface:
    name: str
    description: str
    ip: str
    netmask: str
    prefix_len: int
    gateway: str
    mac: str
    start_ip: str
    end_ip: str

    @property
    def display_label(self) -> str:
        gw_part = f" | GW {self.gateway}" if self.gateway else ""
        return f"{self.name} — {self.ip}/{self.prefix_len} ({self.start_ip} - {self.end_ip}{gw_part})"


def ip_to_int(ip_str: str) -> int:
    """Convert IPv4 string to 32-bit unsigned integer for accurate sorting/comparison."""
    try:
        return int(ipaddress.IPv4Address(ip_str.strip()))
    except Exception:
        return 0


def _subnet_host_bounds(ip_str: str, prefix_len: int) -> tuple[str, str]:
    """Compute usable Start IP and End IP for an interface IPv4/prefix."""
    net = ipaddress.IPv4Network(f"{ip_str}/{prefix_len}", strict=False)
    if net.prefixlen >= 31:
        return str(net.network_address), str(net.broadcast_address)
    first_host = ipaddress.IPv4Address(int(net.network_address) + 1)
    last_host = ipaddress.IPv4Address(int(net.broadcast_address) - 1)
    # Cap auto-fill default range at /22 (1022 hosts) centered on current /24 if interface is /16 or /8
    if net.num_addresses > 1024:
        sub24 = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
        first_host = ipaddress.IPv4Address(int(sub24.network_address) + 1)
        last_host = ipaddress.IPv4Address(int(sub24.broadcast_address) - 1)
    return str(first_host), str(last_host)


# Windows GetAdaptersInfo ctypes structures (locale-independent, fast, reliable IPv4 + Mask + Gateway + MAC)
MAX_ADAPTER_NAME_LENGTH = 256
MAX_ADAPTER_DESCRIPTION_LENGTH = 128
MAX_ADAPTER_ADDRESS_LENGTH = 8


class _IP_ADDR_STRING(ctypes.Structure):
    pass


_IP_ADDR_STRING._fields_ = [
    ("Next", ctypes.POINTER(_IP_ADDR_STRING)),
    ("IpAddress", ctypes.c_char * 16),
    ("IpMask", ctypes.c_char * 16),
    ("Context", wt.DWORD),
]


class _IP_ADAPTER_INFO(ctypes.Structure):
    pass


_IP_ADAPTER_INFO._fields_ = [
    ("Next", ctypes.POINTER(_IP_ADAPTER_INFO)),
    ("ComboIndex", wt.DWORD),
    ("AdapterName", ctypes.c_char * (MAX_ADAPTER_NAME_LENGTH + 4)),
    ("Description", ctypes.c_char * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
    ("AddressLength", wt.UINT),
    ("Address", ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
    ("Index", wt.DWORD),
    ("Type", wt.UINT),
    ("DhcpEnabled", wt.UINT),
    ("CurrentIpAddress", ctypes.POINTER(_IP_ADDR_STRING)),
    ("IpAddressList", _IP_ADDR_STRING),
    ("GatewayList", _IP_ADDR_STRING),
    ("DhcpServer", _IP_ADDR_STRING),
    ("HaveWins", wt.BOOL),
    ("PrimaryWinsServer", _IP_ADDR_STRING),
    ("SecondaryWinsServer", _IP_ADDR_STRING),
    ("LeaseObtained", ctypes.c_int64),
    ("LeaseExpires", ctypes.c_int64),
]


def _get_friendly_names_from_registry() -> dict[str, str]:
    """Map Adapter GUID '{...}' -> Windows Friendly Connection Name (e.g. 'Ethernet', 'Wi-Fi')."""
    mapping: dict[str, str] = {}
    try:
        import winreg

        base_key = (
            r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
        )
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key) as net_key:
            i = 0
            while True:
                try:
                    sub_guid = winreg.EnumKey(net_key, i)
                    i += 1
                except OSError:
                    break
                if not sub_guid.startswith("{"):
                    continue
                try:
                    with winreg.OpenKey(net_key, f"{sub_guid}\\Connection") as conn_key:
                        name_val, _ = winreg.QueryValueEx(conn_key, "Name")
                        if name_val:
                            mapping[sub_guid.upper()] = str(name_val)
                except OSError:
                    continue
    except Exception:
        pass
    return mapping


def detect_network_interfaces() -> list[NetworkInterface]:
    """Detect active IPv4 network interfaces on Windows with Subnet, Gateway, and MAC."""
    interfaces: list[NetworkInterface] = []
    friendly_map = _get_friendly_names_from_registry()

    try:
        iphlpapi = ctypes.windll.iphlpapi
        GetAdaptersInfo = iphlpapi.GetAdaptersInfo
        GetAdaptersInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        GetAdaptersInfo.restype = ctypes.c_ulong

        buf_len = ctypes.c_ulong(32768)
        buf = ctypes.create_string_buffer(buf_len.value)
        ret = GetAdaptersInfo(buf, ctypes.byref(buf_len))
        if ret == 111:  # ERROR_BUFFER_OVERFLOW
            buf = ctypes.create_string_buffer(buf_len.value)
            ret = GetAdaptersInfo(buf, ctypes.byref(buf_len))

        if ret == 0:
            adapter_ptr = ctypes.cast(buf, ctypes.POINTER(_IP_ADAPTER_INFO))
            while adapter_ptr:
                adapter = adapter_ptr.contents
                guid = adapter.AdapterName.decode("ascii", errors="ignore").strip()
                desc = adapter.Description.decode("mbcs", errors="replace").strip()
                friendly = friendly_map.get(guid.upper(), desc or "Network Adapter")

                mac_bytes = bytes(adapter.Address[: adapter.AddressLength])
                mac_str = (
                    normalize_mac(":".join(f"{b:02X}" for b in mac_bytes))
                    if len(mac_bytes) == 6 and any(mac_bytes)
                    else "-"
                )

                gw_ip = adapter.GatewayList.IpAddress.decode("ascii", errors="ignore").strip()
                if gw_ip == "0.0.0.0":
                    gw_ip = ""

                # Walk all IPv4 addresses assigned to this adapter
                ip_node_ptr = ctypes.pointer(adapter.IpAddressList)
                while ip_node_ptr:
                    ip_node = ip_node_ptr.contents
                    ip_str = ip_node.IpAddress.decode("ascii", errors="ignore").strip()
                    mask_str = ip_node.IpMask.decode("ascii", errors="ignore").strip()
                    if ip_str and ip_str not in ("0.0.0.0", "127.0.0.1"):
                        try:
                            net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
                            start_ip, end_ip = _subnet_host_bounds(ip_str, net.prefixlen)
                            interfaces.append(
                                NetworkInterface(
                                    name=friendly,
                                    description=desc,
                                    ip=ip_str,
                                    netmask=mask_str,
                                    prefix_len=net.prefixlen,
                                    gateway=gw_ip,
                                    mac=mac_str,
                                    start_ip=start_ip,
                                    end_ip=end_ip,
                                )
                            )
                        except ValueError:
                            pass
                    ip_node_ptr = ip_node.Next

                adapter_ptr = adapter.Next
    except Exception:
        pass

    # Fallback if GetAdaptersInfo yields nothing
    if not interfaces:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            start_ip, end_ip = _subnet_host_bounds(local_ip, 24)
            interfaces.append(
                NetworkInterface(
                    name="Primary Network",
                    description="Default IPv4 Interface",
                    ip=local_ip,
                    netmask="255.255.255.0",
                    prefix_len=24,
                    gateway="",
                    mac="-",
                    start_ip=start_ip,
                    end_ip=end_ip,
                )
            )
        except Exception:
            pass

    # Sort so LAN interfaces with gateways & /24 subnets appear before /32 VPN tunnels
    interfaces.sort(
        key=lambda iface: (
            0 if iface.gateway else 1,
            0 if iface.prefix_len < 32 else 1,
            iface.name.lower(),
        )
    )
    return interfaces


def expand_single_range_token(token: str) -> tuple[str, str]:
    """
    Expand a single CIDR or shorthand token into (start_ip, end_ip).
    Examples:
      - '192.168.1.0/24' -> ('192.168.1.1', '192.168.1.254')
      - '192.168.1.10-50' -> ('192.168.1.10', '192.168.1.50')
      - '192.168.1.10-192.168.1.80' -> ('192.168.1.10', '192.168.1.80')
      - '192.168.1.15' -> ('192.168.1.15', '192.168.1.15')
    """
    raw = token.strip()
    if "/" in raw:
        net = ipaddress.IPv4Network(raw, strict=False)
        if net.prefixlen >= 31:
            return str(net.network_address), str(net.broadcast_address)
        return (
            str(ipaddress.IPv4Address(int(net.network_address) + 1)),
            str(ipaddress.IPv4Address(int(net.broadcast_address) - 1)),
        )

    if "-" in raw:
        left, right = [p.strip() for p in raw.split("-", 1)]
        start_addr = ipaddress.IPv4Address(left)
        if "." in right:
            end_addr = ipaddress.IPv4Address(right)
        else:
            last_octet = int(right)
            if not (0 <= last_octet <= 255):
                raise ValueError(f"ค่าหลักสุดท้ายของ IP ไม่ถูกต้อง: {right}")
            prefix = ".".join(left.split(".")[:3])
            end_addr = ipaddress.IPv4Address(f"{prefix}.{last_octet}")
        return str(start_addr), str(end_addr)

    addr = ipaddress.IPv4Address(raw)
    return str(addr), str(addr)


def parse_ip_range(start_text: str, end_text: str = "") -> list[str]:
    """
    Parse user IP range inputs into an ordered list of IPv4 strings.
    Supports:
      1) Start IP + End IP (e.g. '192.168.31.1' and '192.168.31.254')
      2) End IP as just last octet (e.g. Start '192.168.31.1', End '100')
      3) CIDR or comma-separated tokens in start_text (e.g. '192.168.31.0/24' or '192.168.31.1-50, 192.168.31.200-210')
    """
    s_raw = start_text.strip()
    e_raw = end_text.strip()

    if not s_raw:
        raise ValueError("กรุณาระบุ IP เริ่มต้น")

    # Case A: comma-separated ranges, CIDR, or dash shorthand inside start_text when end_text is empty or identical
    if "," in s_raw or "/" in s_raw or ("-" in s_raw and not e_raw):
        seen: set[int] = set()
        result_ints: list[int] = []
        for part in s_raw.split(","):
            part = part.strip()
            if not part:
                continue
            p_start, p_end = expand_single_range_token(part)
            a_int = int(ipaddress.IPv4Address(p_start))
            b_int = int(ipaddress.IPv4Address(p_end))
            if a_int > b_int:
                raise ValueError(f"IP เริ่มต้น ({p_start}) มากกว่า IP สิ้นสุด ({p_end})")
            if b_int - a_int + 1 > 65536:
                raise ValueError("ช่วง IP กว้างเกินไป (รองรับสูงสุดไม่เกิน 65,536 IP ต่อการสแกน 1 ครั้ง)")
            for val in range(a_int, b_int + 1):
                if val not in seen:
                    seen.add(val)
                    result_ints.append(val)
        return [str(ipaddress.IPv4Address(v)) for v in result_ints]

    # Case B: standard Start IP + End IP
    start_addr = ipaddress.IPv4Address(s_raw)
    if not e_raw:
        end_addr = start_addr
    elif re.fullmatch(r"\d{1,3}", e_raw):
        octet = int(e_raw)
        if not (0 <= octet <= 255):
            raise ValueError(f"ค่าหลักสุดท้ายของ IP สิ้นสุดต้องอยู่ระหว่าง 0-255 (ได้รับ {e_raw})")
        base = ".".join(str(start_addr).split(".")[:3])
        end_addr = ipaddress.IPv4Address(f"{base}.{octet}")
    else:
        end_addr = ipaddress.IPv4Address(e_raw)

    start_int = int(start_addr)
    end_int = int(end_addr)
    if start_int > end_int:
        raise ValueError(f"IP เริ่มต้น ({start_addr}) ต้องไม่มากกว่า IP สิ้นสุด ({end_addr})")

    count = end_int - start_int + 1
    if count > 65536:
        raise ValueError(
            f"ช่วง IP มีจำนวนมากถึง {count:,} รายการ (จำกัดไม่เกิน 65,536 IP เพื่อป้องกันเครือข่ายค้าง)"
        )

    return [str(ipaddress.IPv4Address(i)) for i in range(start_int, end_int + 1)]


def parse_ports(port_text: str) -> list[int]:
    """
    Parse port specification string (e.g. '22, 80, 443, 8000-8005') into sorted unique TCP ports.
    """
    raw = port_text.strip()
    if not raw:
        return []
    ports: set[int] = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            a_str, b_str = [x.strip() for x in token.split("-", 1)]
            a, b = int(a_str), int(b_str)
            if a > b or a < 1 or b > 65535:
                raise ValueError(f"ช่วงพอร์ตไม่ถูกต้อง: {token}")
            ports.update(range(a, b + 1))
        else:
            p = int(token)
            if not (1 <= p <= 65535):
                raise ValueError(f"หมายเลขพอร์ตต้องอยู่ระหว่าง 1-65535 (ได้รับ {p})")
            ports.add(p)
    return sorted(ports)
