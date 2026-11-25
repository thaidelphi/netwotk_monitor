"""Defensive LAN Host Vulnerability & Exposure Audit with deep protocol checks and CVE/CWE matching."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date

from .engine import HostScanResult

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


@dataclass(slots=True)
class VulnFinding:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    port: int | None
    description: str
    remediation: str
    cve_ids: list[str] = field(default_factory=list)


def _parse_openssh_version(banner: str) -> tuple[int, int] | None:
    """Extract (major, minor) from SSH banner like 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3'."""
    m = re.search(r"OpenSSH[_\s]+(\d+)\.(\d+)", banner, re.IGNORECASE)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def audit_host_vulnerabilities(res: HostScanResult) -> list[VulnFinding]:
    """
    Analyze a HostScanResult for network exposure, SMBv1, weak TLS, HTTP security headers,
    cleartext protocols, unauthenticated datastores, EOL OS, and version-matched CVEs.
    """
    if not res.online:
        return [
            VulnFinding(
                severity="INFO",
                title="เครื่องไม่ตอบสนอง (Offline)",
                port=None,
                description="ไม่สามารถเชื่อมต่อเครื่องเป้าหมายได้ในขณะนี้",
                remediation="ตรวจสอบว่าเครื่องเปิดอยู่และเชื่อมต่อเครือข่ายเดียวกัน",
            )
        ]

    findings: list[VulnFinding] = []
    ports = set(res.open_ports)

    # 1. SMBv1 Enabled (verified via SMB_COM_NEGOTIATE)
    if res.smb_info.get("smbv1_enabled") == "true":
        findings.append(
            VulnFinding(
                severity="CRITICAL",
                title="เปิดใช้งานโปรโตคอล SMBv1 ที่ไม่ปลอดภัย",
                port=445,
                description="เซิร์ฟเวอร์ตอบรับการเจรจาโปรโตคอล SMBv1 ('NT LM 0.12') ซึ่งเสี่ยงต่อช่องโหว่ระดับวิกฤต",
                remediation="ปิด SMBv1 ทันที (Windows: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol) และอัปเดตแพตช์ MS17-010",
                cve_ids=["CVE-2017-0144 (EternalBlue)", "CVE-2017-0145"],
            )
        )

    # 2. Unauthenticated Docker Engine API (2375)
    if 2375 in ports:
        dk_b = res.port_banners.get(2375, "")
        findings.append(
            VulnFinding(
                severity="CRITICAL" if "no auth" in dk_b.lower() else "HIGH",
                title="เปิด Docker Daemon API แบบไม่เข้ารหัส (Port 2375)",
                port=2375,
                description=f"พอร์ต 2375 เปิดรับคำสั่ง Docker API โดยไม่ใช้ TLS ({dk_b or 'Docker API'})",
                remediation="ปิด TCP 2375 หรือเปลี่ยนไปใช้ TLS Mutual Auth (Port 2376) และจำกัด IP ด้วย Firewall",
                cve_ids=["CWE-306"],
            )
        )

    # 3. Exposed Redis (6379)
    if 6379 in ports:
        rd_b = res.port_banners.get(6379, "")
        is_no_auth = "no auth" in rd_b.lower()
        findings.append(
            VulnFinding(
                severity="CRITICAL" if is_no_auth else "MEDIUM",
                title="Redis Server เปิดออกสู่เครือข่าย" + (" (ไม่ต้องใช้รหัสผ่าน!)" if is_no_auth else ""),
                port=6379,
                description=f"ตรวจพบพอร์ต 6379 ({rd_b or 'Redis'}) เปิดรับการเชื่อมต่อในวงแลน",
                remediation="ตั้ง `bind 127.0.0.1`, กำหนด `requirepass` ที่แข็งแรง และปิดพอร์ตด้วย Firewall",
                cve_ids=["CWE-306"] if is_no_auth else ["CWE-284"],
            )
        )

    # 4. VNC without authentication (5900 / 5901)
    for vp in (5900, 5901):
        if vp not in ports:
            continue
        vnc_banner = res.port_banners.get(vp, "")
        if "no auth" in vnc_banner.lower():
            findings.append(
                VulnFinding(
                    severity="CRITICAL",
                    title=f"VNC เปิดให้ควบคุมหน้าจอโดยไม่ใช้รหัสผ่าน (Port {vp})",
                    port=vp,
                    description=f"พอร์ต {vp} ตอบกลับ: {vnc_banner} ทำให้ทุกคนในวงแลนเข้าควบคุมหน้าจอได้ทันที",
                    remediation="ตั้งรหัสผ่าน VNC, เปิดใช้การเข้ารหัส (TLS/VeNCrypt) หรือจำกัด IP ด้วย Firewall",
                    cve_ids=["CWE-306"],
                )
            )
        else:
            findings.append(
                VulnFinding(
                    severity="MEDIUM",
                    title=f"เปิดบริการ Remote VNC (Port {vp})",
                    port=vp,
                    description=f"พบพอร์ต VNC เปิดใช้งาน ({vnc_banner or 'RFB'}) ซึ่งมักไม่เข้ารหัสทราฟฟิก",
                    remediation="ใช้งานผ่าน SSH Tunnel / VPN หรือปิดบริการหากไม่จำเป็น",
                    cve_ids=["CWE-319"],
                )
            )

    # 5. Exposed Elasticsearch / Memcached / MongoDB
    if 9200 in ports:
        es_b = res.port_banners.get(9200, "")
        findings.append(
            VulnFinding(
                severity="HIGH" if "no auth" in es_b.lower() else "MEDIUM",
                title="เปิดพอร์ต Elasticsearch HTTP API สู่เครือข่าย",
                port=9200,
                description=f"ตรวจพบพอร์ต 9200 ({es_b or 'Elasticsearch'}) เปิดเข้าถึงจากวงแลน",
                remediation="เปิดใช้ X-Pack Security / Authentication และจำกัด IP ที่เข้าถึง",
                cve_ids=["CWE-306"] if "no auth" in es_b.lower() else ["CWE-284"],
            )
        )

    if 11211 in ports:
        mc_b = res.port_banners.get(11211, "")
        findings.append(
            VulnFinding(
                severity="MEDIUM",
                title="เปิดบริการ Memcached สู่เครือข่าย (Port 11211)",
                port=11211,
                description=f"พอร์ต Memcached เปิดรับคำสั่งโดยไม่มีการยืนยันตัวตน ({mc_b or 'Memcached'})",
                remediation="ตั้งให้ฟังเฉพาะ `127.0.0.1` และปิด UDP listener (-U 0)",
                cve_ids=["CVE-2018-1000115", "CWE-306"],
            )
        )

    # 6. Cleartext management protocols (Telnet 23, FTP 21/2121, rlogin/rsh/rexec)
    if 23 in ports:
        findings.append(
            VulnFinding(
                severity="HIGH",
                title="เปิดใช้ Telnet (ส่งรหัสผ่านแบบไม่เข้ารหัส)",
                port=23,
                description="โปรโตคอล Telnet ส่งชื่อผู้ใช้และรหัสผ่านเป็น Plaintext เสี่ยงต่อการดักจับข้อมูลในวงแลน",
                remediation="ปิดบริการ Telnet แล้วเปลี่ยนไปใช้ SSH (Port 22) หรือ HTTPS แทน",
                cve_ids=["CWE-319", "CWE-522"],
            )
        )

    for rp, rname in ((512, "rexec"), (513, "rlogin"), (514, "rsh")):
        if rp in ports:
            findings.append(
                VulnFinding(
                    severity="HIGH",
                    title=f"เปิดบริการ Legacy Berkeley R-Service ({rname} / Port {rp})",
                    port=rp,
                    description=f"โปรโตคอล {rname} ไม่มีการเข้ารหัสและเชื่อใจตาม Host/IP ซึ่งไม่ปลอดภัย",
                    remediation=f"ปิดบริการ {rname} และเปลี่ยนไปใช้ SSH แทน",
                    cve_ids=["CWE-319", "CWE-287"],
                )
            )

    for fp in (21, 2121):
        if fp in ports:
            findings.append(
                VulnFinding(
                    severity="MEDIUM",
                    title=f"เปิดใช้ FTP (โอนไฟล์และล็อกอินแบบไม่เข้ารหัส - Port {fp})",
                    port=fp,
                    description=f"พบพอร์ต FTP เปิดใช้งาน ({res.port_banners.get(fp, 'FTP')})",
                    remediation="เปลี่ยนไปใช้ SFTP (SSH) หรือ FTPS (TLS) และปิด Anonymous Login",
                    cve_ids=["CWE-319"],
                )
            )

    # 7. End-of-Life Windows OS & Windows Build-based CVE indicators
    os_low = res.os_name.lower()
    os_build_str = res.smb_info.get("os_build", "")
    os_build = int(os_build_str) if os_build_str.isdigit() else None

    if any(eol in os_low for eol in ("windows 7", "windows 8", "windows xp", "2008", "2012", "2003")):
        eol_cves: list[str] = []
        if 445 in ports:
            eol_cves.extend(["CVE-2017-0144 (EternalBlue)", "CVE-2017-0145"])
        if 3389 in ports and any(k in os_low for k in ("windows 7", "2008", "xp", "2003")):
            eol_cves.append("CVE-2019-0708 (BlueKeep)")
        findings.append(
            VulnFinding(
                severity="HIGH",
                title="ระบบปฏิบัติการหมดระยะสนับสนุน (End-of-Life OS)",
                port=445 if 445 in ports else (3389 if 3389 in ports else None),
                description=f"ตรวจพบ OS: {res.os_name} ซึ่งไม่ได้รับแพตช์ความปลอดภัยจากผู้ผลิตแล้ว (ควรตรวจสอบสถานะแพตช์ย้อนหลัง)",
                remediation="อัปเกรดเป็น Windows 10/11 หรือ Windows Server รุ่นที่ยังรองรับ ปิด SMBv1 และเปิดใช้ NLA",
                cve_ids=eol_cves or ["CWE-1104"],
            )
        )
    elif os_build in (18362, 18363) and 445 in ports:
        findings.append(
            VulnFinding(
                severity="HIGH",
                title="Windows 10 รุ่น 1903/1909 (ตรวจสอบแพตช์ SMBv3 Compression)",
                port=445,
                description=f"ตรวจพบ SMB Build {os_build} ซึ่งอยู่ในช่วงเวอร์ชันที่เคยมีช่องโหว่ SMBGhost หากยังไม่อัปเดต KB4551762",
                remediation="ตรวจสอบ Windows Update ให้ติดตั้งแพตช์ KB4551762 หรืออัปเกรดเป็น Windows 10/11 รุ่นล่าสุด",
                cve_ids=["CVE-2020-0796 (SMBGhost)"],
            )
        )

    # 8. SNMP public / private community exposure
    if res.snmp_info:
        if res.snmp_info.get("community_private") == "true":
            findings.append(
                VulnFinding(
                    severity="HIGH",
                    title="SNMP ตอบสนองด้วย Community Read/Write ('private')",
                    port=161,
                    description="อุปกรณ์ยอมรับ SNMP Community 'private' ซึ่งมักให้สิทธิ์แก้ไขการตั้งค่าอุปกรณ์ได้",
                    remediation="เปลี่ยนหรือปิด Community 'private' ทันที อัปเกรดเป็น SNMPv3 และตั้ง ACL จำกัด IP",
                    cve_ids=["CVE-2002-0013", "CWE-287"],
                )
            )
        if res.snmp_info.get("community_public") == "true" or "community_private" not in res.snmp_info:
            findings.append(
                VulnFinding(
                    severity="MEDIUM",
                    title="SNMP ตอบสนองด้วย Community เริ่มต้น ('public')",
                    port=161,
                    description="สามารถอ่านข้อมูลระบบ/รุ่นอุปกรณ์ผ่าน SNMP v1/v2c ด้วยรหัส 'public' ได้",
                    remediation="เปลี่ยน Community String จาก 'public' เป็นค่าที่เดายาก อัปเกรดเป็น SNMPv3 หรือจำกัด IP",
                    cve_ids=["CVE-2002-0013", "CWE-287"],
                )
            )

    # 9. Exposed Database & Infrastructure ports
    for db_port, db_name in (
        (3306, "MySQL/MariaDB"),
        (5432, "PostgreSQL"),
        (1433, "Microsoft SQL Server"),
        (1521, "Oracle Database"),
        (27017, "MongoDB"),
    ):
        if db_port in ports:
            banner = res.port_banners.get(db_port, db_name)
            findings.append(
                VulnFinding(
                    severity="MEDIUM",
                    title=f"เปิดพอร์ตฐานข้อมูล {db_name} สู่เครือข่าย",
                    port=db_port,
                    description=f"พอร์ต {db_port} ({banner}) เปิดรับการเชื่อมต่อจากเครื่องอื่นในวงแลน",
                    remediation="ตั้งค่า Bind Address เป็น 127.0.0.1 หากใช้เฉพาะในเครื่อง หรือตั้ง Firewall จำกัดเฉพาะ IP ที่อนุญาต",
                    cve_ids=["CWE-284"],
                )
            )
            if db_port == 5432 and "no ssl" in banner.lower():
                findings.append(
                    VulnFinding(
                        severity="LOW",
                        title="PostgreSQL ไม่ได้เปิดใช้การเข้ารหัส SSL",
                        port=5432,
                        description="เซิร์ฟเวอร์ตอบกลับ 'No SSL' เมื่อร้องขอการเชื่อมต่อแบบเข้ารหัส",
                        remediation="เปิดใช้งาน `ssl = on` ในไฟล์ postgresql.conf",
                        cve_ids=["CWE-319"],
                    )
                )

    if 2049 in ports or 111 in ports:
        p_found = 2049 if 2049 in ports else 111
        findings.append(
            VulnFinding(
                severity="MEDIUM",
                title=f"เปิดบริการ NFS / RPCbind (Port {p_found})",
                port=p_found,
                description="บริการแชร์ไฟล์ NFS/RPC อาจอนุญาตให้เครื่องอื่นในวงแลน Mount โฟลเดอร์ได้หากตั้งค่า Export กว้างเกินไป",
                remediation="ตรวจสอบไฟล์ `/etc/exports` ให้จำกัดเฉพาะ IP ที่อนุญาต และเปิดใช้ Firewall",
                cve_ids=["CWE-284"],
            )
        )

    if 5985 in ports:
        findings.append(
            VulnFinding(
                severity="MEDIUM",
                title="เปิดใช้ WinRM แบบ HTTP ไม่เข้ารหัส (Port 5985)",
                port=5985,
                description="บริการ Windows Remote Management เปิดพอร์ต HTTP 5985 บนเครือข่าย",
                remediation="จำกัด IP ด้วย Windows Firewall หรือใช้ WinRM HTTPS (Port 5986)",
                cve_ids=["CWE-319"],
            )
        )

    if 8291 in ports or 8728 in ports:
        mp = 8291 if 8291 in ports else 8728
        findings.append(
            VulnFinding(
                severity="MEDIUM",
                title=f"เปิดพอร์ตจัดการ MikroTik Winbox/API (Port {mp})",
                port=mp,
                description="พอร์ตจัดการ RouterOS เปิดรับการเชื่อมต่อจากวงแลน (ควรตรวจสอบเวอร์ชัน RouterOS ให้เป็นรุ่นล่าสุด)",
                remediation="จำกัด IP ที่เข้าถึงใน `/ip service` (Allowed Address) และอัปเดต RouterOS ป้องกันช่องโหว่ Winbox",
                cve_ids=["CVE-2018-14847 (Winbox Old Ver)"],
            )
        )

    if 1883 in ports:
        findings.append(
            VulnFinding(
                severity="MEDIUM",
                title="เปิดพอร์ต MQTT (IoT) แบบไม่เข้ารหัส",
                port=1883,
                description="พอร์ต 1883 ส่งข้อมูลอุปกรณ์ IoT แบบไม่เข้ารหัส TLS และอาจเปิดรับคำสั่งโดยไม่ยืนยันตัวตน",
                remediation="เปิดใช้ Username/Password และเปลี่ยนไปใช้ MQTTS (Port 8883)",
                cve_ids=["CWE-319", "CWE-306"],
            )
        )

    # 10. SMB Shares & NetBIOS
    if 445 in ports:
        non_default_shares = [
            s
            for s in res.smb_shares
            if not any(s.upper().startswith(adm) for adm in ("ADMIN$", "C$", "D$", "E$", "IPC$", "PRINT$"))
        ]
        if non_default_shares:
            findings.append(
                VulnFinding(
                    severity="MEDIUM",
                    title="พบโฟลเดอร์แชร์ / เครื่องพิมพ์ที่มองเห็นได้ผ่าน SMB",
                    port=445,
                    description="รายการที่มองเห็น: " + ", ".join(non_default_shares[:8]),
                    remediation="ตรวจสอบสิทธิ์การแชร์ (Share & NTFS Permissions) ไม่ให้สิทธิ์ Everyone เขียน/อ่านข้อมูลสำคัญ",
                    cve_ids=["CWE-732"],
                )
            )
        elif res.smb_info.get("smbv1_enabled") != "true":
            findings.append(
                VulnFinding(
                    severity="INFO",
                    title="เปิดบริการแชร์ไฟล์ Windows SMB (Port 445)",
                    port=445,
                    description="พอร์ต 445 เปิดใช้งานในวงแลน",
                    remediation="ตรวจสอบให้แน่ใจว่าปิด SMBv1 แล้ว และอัปเดตแพตช์ Windows สม่ำเสมอ",
                )
            )

    if 139 in ports:
        findings.append(
            VulnFinding(
                severity="LOW",
                title="เปิดใช้ NetBIOS Session Service (Port 139)",
                port=139,
                description="พอร์ต 139 เป็นโปรโตคอลเก่าที่ใช้ร่วมกับการแชร์ไฟล์และมักถูกใช้สืบค้นชื่อเครื่อง",
                remediation="พิจารณาปิด 'NetBIOS over TCP/IP' ในตั้งค่า TCP/IPv4 หากระบบใช้ SMB 445 ได้ปกติ",
                cve_ids=["CWE-200"],
            )
        )

    if 3389 in ports:
        findings.append(
            VulnFinding(
                severity="LOW",
                title="เปิดบริการ Remote Desktop (RDP 3389)",
                port=3389,
                description="เครื่องเปิดรับการรีโมตหน้าจอ RDP ในวงแลน",
                remediation="เปิดใช้ Network Level Authentication (NLA) ตั้งรหัสผ่านให้รัดกุม และจำกัด IP ที่รีโมตได้",
                cve_ids=["CWE-284"],
            )
        )

    if 389 in ports:
        findings.append(
            VulnFinding(
                severity="LOW",
                title="เปิดใช้ LDAP แบบไม่เข้ารหัส (Port 389)",
                port=389,
                description="พอร์ต 389 ส่งคำค้นหาและข้อมูลยืนยันตัวตนโดยไม่เข้ารหัส TLS หากไม่ใช้ StartTLS",
                remediation="ใช้งาน LDAPS (Port 636) หรือบังคับ LDAP Signing/Channel Binding",
                cve_ids=["CWE-319"],
            )
        )

    # 11. Deep HTTP / Web Security Headers & Version CVE checks
    has_https = bool(ports & {443, 4443, 5001, 8006, 8443, 9443, 10000})
    for hinfo in res.http_infos:
        hp = int(hinfo["port"]) if str(hinfo.get("port", "")).isdigit() else 80
        srv = hinfo.get("server", "")
        powered = hinfo.get("powered_by", "")
        combo_low = f"{srv} {powered}".lower()

        if hinfo.get("git_exposed") == "true":
            findings.append(
                VulnFinding(
                    severity="HIGH",
                    title=f"เว็บเซิร์ฟเวอร์เปิดเผยโฟลเดอร์ .git (Port {hp})",
                    port=hp,
                    description=f"เข้าถึง `/.git/HEAD` ได้ (HTTP 200) อาจทำให้ซอร์สโค้ดหรือข้อมูลลับรั่วไหล",
                    remediation="บล็อกการเข้าถึงไฟล์ที่ขึ้นต้นด้วย `.git` ในการตั้งค่า Web Server ทันที",
                    cve_ids=["CWE-538"],
                )
            )

        if hinfo.get("dir_listing") == "true":
            findings.append(
                VulnFinding(
                    severity="MEDIUM",
                    title=f"เปิด Directory Listing บนเว็บเซิร์ฟเวอร์ (Port {hp})",
                    port=hp,
                    description="หน้าแรกแสดงรายการไฟล์ในโฟลเดอร์ (`Index of /`) สู่เครือข่าย",
                    remediation="ปิด Directory Indexing (เช่น `Options -Indexes` ใน Apache หรือ `autoindex off;` ใน Nginx)",
                    cve_ids=["CWE-548"],
                )
            )

        allow_m = hinfo.get("allow_methods", "").upper()
        risky_m = [m for m in ("TRACE", "PUT", "DELETE") if m in allow_m]
        if risky_m:
            findings.append(
                VulnFinding(
                    severity="MEDIUM",
                    title=f"เว็บเซิร์ฟเวอร์อนุญาต HTTP Method ที่มีความเสี่ยง ({', '.join(risky_m)})",
                    port=hp,
                    description=f"Header `Allow: {hinfo.get('allow_methods', '')}` บนพอร์ต {hp}",
                    remediation="ปิด HTTP Methods ที่ไม่จำเป็น (โดยเฉพาะ TRACE / PUT / DELETE) ใน Web Server",
                    cve_ids=["CVE-2003-1567", "CWE-16"] if "TRACE" in risky_m else ["CWE-749"],
                )
            )

        if "apache/2.4.49" in combo_low or "apache/2.4.50" in combo_low:
            findings.append(
                VulnFinding(
                    severity="CRITICAL",
                    title=f"Apache HTTP Server เวอร์ชันเสี่ยง Path Traversal / RCE (Port {hp})",
                    port=hp,
                    description=f"ตรวจพบ Header: {srv}",
                    remediation="อัปเดต Apache HTTP Server เป็นเวอร์ชัน 2.4.51 ขึ้นไปทันที",
                    cve_ids=["CVE-2021-41773", "CVE-2021-42013"],
                )
            )
        elif "microsoft-iis/7." in combo_low or "microsoft-iis/8." in combo_low:
            findings.append(
                VulnFinding(
                    severity="MEDIUM",
                    title=f"ตรวจพบ Microsoft IIS รุ่นเก่า (Port {hp})",
                    port=hp,
                    description=f"ตรวจพบ Header: {srv} (ควรตรวจสอบสถานะแพตช์ HTTP.sys)",
                    remediation="อัปเกรดระบบปฏิบัติการ/IIS และตรวจสอบการติดตั้งแพตช์ MS15-034",
                    cve_ids=["CVE-2015-1635"],
                )
            )

        if any(php_old in combo_low for php_old in ("php/5.", "php/7.0", "php/7.1", "php/7.2", "php/7.3", "php/7.4")):
            findings.append(
                VulnFinding(
                    severity="HIGH",
                    title=f"เว็บเซิร์ฟเวอร์ใช้ PHP เวอร์ชันหมดอายุสนับสนุน ({powered})",
                    port=hp,
                    description=f"Header `X-Powered-By: {powered}` แสดงเวอร์ชัน PHP ที่สิ้นสุดระยะสนับสนุน (EOL)",
                    remediation="อัปเกรดเป็น PHP 8.2+ และปิดการแสดง `expose_php = Off` ใน php.ini",
                    cve_ids=["CWE-1104", "CWE-200"],
                )
            )

        if hinfo.get("missing_sec_headers") and hinfo.get("scheme") in ("http", "https"):
            findings.append(
                VulnFinding(
                    severity="LOW",
                    title=f"เว็บเซิร์ฟเวอร์ขาด HTTP Security Headers (Port {hp})",
                    port=hp,
                    description=f"Header ที่ขาด: {hinfo['missing_sec_headers']}",
                    remediation="เพิ่ม Header `X-Frame-Options`, `X-Content-Type-Options: nosniff` และ `Strict-Transport-Security` (สำหรับ HTTPS)",
                    cve_ids=["CWE-693"],
                )
            )

        if hinfo.get("scheme") == "http" and not has_https:
            findings.append(
                VulnFinding(
                    severity="LOW",
                    title=f"เว็บจัดการอุปกรณ์ทำงานบน HTTP ไม่เข้ารหัส (Port {hp})",
                    port=hp,
                    description=f"พบเว็บเซิร์ฟเวอร์ ({srv or 'HTTP'}) โดยไม่มีพอร์ต HTTPS รองรับ",
                    remediation="หลีกเลี่ยงการล็อกอินผ่านเครือข่ายที่ไม่น่าเชื่อถือ หรือเปิดใช้ HTTPS หากอุปกรณ์รองรับ",
                    cve_ids=["CWE-319"],
                )
            )

    # 12. SSL/TLS Protocol Version, Weak Key Size, & Certificate Expiration checks
    today_str = date.today().isoformat()
    for cert in res.ssl_certs:
        c_port = int(cert["port"]) if str(cert.get("port", "")).isdigit() else None
        tls_ver = cert.get("tls_version", "")
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append(
                VulnFinding(
                    severity="HIGH",
                    title=f"รองรับโปรโตคอล TLS เวอร์ชันเก่าที่ไม่ปลอดภัย ({tls_ver} - Port {c_port})",
                    port=c_port,
                    description=f"พอร์ต {c_port} เจรจาเชื่อมต่อด้วย {tls_ver} ({cert.get('tls_cipher', '')}) ซึ่งถูกยกเลิกมาตรฐานแล้ว",
                    remediation="ปิด TLS 1.0 / 1.1 และบังคับใช้เฉพาะ TLS 1.2 / TLS 1.3",
                    cve_ids=["CVE-2011-3389 (BEAST)", "CVE-2014-3566 (POODLE)"],
                )
            )

        key_bits_s = cert.get("ssl_key_bits", "")
        sig_alg = cert.get("ssl_sig_alg", "").lower()
        if (key_bits_s.isdigit() and int(key_bits_s) < 2048) or ("sha1" in sig_alg):
            findings.append(
                VulnFinding(
                    severity="MEDIUM",
                    title=f"ใบรับรอง SSL ใช้คีย์หรืออัลกอริทึมเข้ารหัสอ่อนแอ (Port {c_port})",
                    port=c_port,
                    description=f"Key Size: {key_bits_s or '?'} bit | Signature: {sig_alg or '?'}",
                    remediation="ออกใบรับรองใหม่ด้วย RSA >= 2048 bit (หรือ ECDSA P-256) และ SHA-256",
                    cve_ids=["CWE-326", "CWE-327"],
                )
            )

        exp = cert.get("ssl_expires", "")
        days_left_s = cert.get("ssl_days_left", "")
        subj = cert.get("ssl_subject", "")
        iss = cert.get("ssl_issuer", "")
        if exp and exp < today_str:
            findings.append(
                VulnFinding(
                    severity="MEDIUM",
                    title=f"ใบรับรอง SSL/TLS หมดอายุแล้ว (Port {c_port})",
                    port=c_port,
                    description=f"Certificate ({subj}) หมดอายุเมื่อ {exp}",
                    remediation="ต่ออายุหรือสร้างใบรับรอง SSL/TLS ใหม่บนอุปกรณ์/เซิร์ฟเวอร์",
                    cve_ids=["CWE-298"],
                )
            )
        elif days_left_s.lstrip("-").isdigit() and 0 <= int(days_left_s) <= 30:
            findings.append(
                VulnFinding(
                    severity="LOW",
                    title=f"ใบรับรอง SSL/TLS ใกล้หมดอายุใน {days_left_s} วัน (Port {c_port})",
                    port=c_port,
                    description=f"Certificate ({subj}) จะหมดอายุวันที่ {exp}",
                    remediation="เตรียมต่ออายุใบรับรอง SSL/TLS ก่อนวันหมดอายุ",
                    cve_ids=["CWE-298"],
                )
            )

        if subj and iss and subj == iss:
            findings.append(
                VulnFinding(
                    severity="INFO",
                    title=f"ใช้ใบรับรอง SSL แบบ Self-Signed (Port {c_port})",
                    port=c_port,
                    description=f"Subject และ Issuer เป็นชื่อเดียวกัน ({subj})",
                    remediation="สำหรับระบบภายในใช้งานได้ปกติ แต่หากเป็นระบบสำคัญควรใช้ Internal CA หรือ Let's Encrypt",
                    cve_ids=["CWE-295"],
                )
            )

    # 13. OpenSSH Banner CVE matching
    ssh_b = res.port_banners.get(22, "")
    if ssh_b:
        ssh_ver = _parse_openssh_version(ssh_b)
        is_win_ssh = "windows" in ssh_b.lower()
        if ssh_ver is not None:
            if (8, 5) <= ssh_ver < (9, 8) and not is_win_ssh:
                findings.append(
                    VulnFinding(
                        severity="HIGH",
                        title="OpenSSH เวอร์ชันอยู่ในช่วงที่อาจมีช่องโหว่ regreSSHion / Terrapin",
                        port=22,
                        description=f"ตรวจพบ Banner: {ssh_b} (ควรตรวจสอบว่า OS ออกแพตช์ย้อนหลังแล้วหรือไม่)",
                        remediation="อัปเดตแพ็กเกจ `openssh-server` เป็นเวอร์ชันล่าสุด หรือจำกัด IP ที่เข้าพอร์ต 22",
                        cve_ids=["CVE-2024-6387 (regreSSHion)", "CVE-2023-48795 (Terrapin)"],
                    )
                )
            elif ssh_ver < (8, 5):
                cves = ["CVE-2023-48795 (Terrapin)"]
                if ssh_ver < (7, 4):
                    cves.extend(["CVE-2016-10009", "CVE-2016-10012"])
                findings.append(
                    VulnFinding(
                        severity="MEDIUM" if ssh_ver < (7, 4) else "LOW",
                        title="OpenSSH Server เป็นเวอร์ชันเก่า",
                        port=22,
                        description=f"ตรวจพบ Banner: {ssh_b}",
                        remediation="อัปเดต OpenSSH / Firmware อุปกรณ์ให้เป็นเวอร์ชันล่าสุด",
                        cve_ids=cves,
                    )
                )

    # 14. RTSP Camera stream
    if 554 in ports:
        findings.append(
            VulnFinding(
                severity="INFO",
                title="เปิดบริการสตรีมวิดีโอ RTSP (Port 554)",
                port=554,
                description=f"พบพอร์ตกล้อง/NVR ({res.port_banners.get(554, 'RTSP')})",
                remediation="ตรวจสอบว่าเปิดใช้รหัสผ่าน RTSP และแยกกล้องวงจรปิดไว้ใน VLAN เฉพาะ",
            )
        )

    if not findings:
        findings.append(
            VulnFinding(
                severity="INFO",
                title="ไม่พบความเสี่ยงจากพอร์ต/บริการที่สแกน",
                port=None,
                description="ไม่พบพอร์ตบริการที่มีความเสี่ยงเปิดอยู่จากการตรวจสอบเบื้องต้น",
                remediation="รักษาระดับความปลอดภัยและอัปเดตแพตช์ระบบอย่างสม่ำเสมอ",
            )
        )

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.port or 0))
    return findings


def summarize_host_risk(findings: list[VulnFinding]) -> tuple[str, int, dict[str, int]]:
    """
    Compute (risk_badge_label, numeric_risk_score, severity_counts) for a host's VA findings.
    """
    counts = {sev: 0 for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1

    score = (
        counts["CRITICAL"] * 40
        + counts["HIGH"] * 20
        + counts["MEDIUM"] * 8
        + counts["LOW"] * 2
    )
    if counts["CRITICAL"] > 0:
        label = f"CRITICAL ({counts['CRITICAL']})"
    elif counts["HIGH"] > 0:
        label = f"HIGH ({counts['HIGH']})"
    elif counts["MEDIUM"] > 0:
        label = f"MEDIUM ({counts['MEDIUM']})"
    elif counts["LOW"] > 0:
        label = f"LOW ({counts['LOW']})"
    else:
        label = "ปลอดภัย (OK)"
    return label, score, counts
