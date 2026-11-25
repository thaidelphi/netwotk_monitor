"""Defensive LAN Host Vulnerability & Exposure Audit (configuration, cleartext, cert, and EOL checks)."""

from __future__ import annotations

from dataclasses import dataclass
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


def audit_host_vulnerabilities(res: HostScanResult) -> list[VulnFinding]:
    """
    Analyze a HostScanResult for common network exposure, cleartext protocols,
    weak authentication, certificate issues, and end-of-life OS risks.
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

    # 1. VNC without authentication (5900)
    vnc_banner = res.port_banners.get(5900, "")
    if 5900 in ports:
        if "no auth" in vnc_banner.lower():
            findings.append(
                VulnFinding(
                    severity="CRITICAL",
                    title="VNC เปิดให้ควบคุมหน้าจอโดยไม่ใช้รหัสผ่าน",
                    port=5900,
                    description=f"พอร์ต 5900 ตอบกลับ: {vnc_banner} ทำให้ทุกคนในวงแลนเข้าควบคุมหน้าจอได้ทันที",
                    remediation="ตั้งรหัสผ่าน VNC, เปิดใช้การเข้ารหัส (TLS/VeNCrypt) หรือจำกัด IP ด้วย Firewall",
                )
            )
        else:
            findings.append(
                VulnFinding(
                    severity="MEDIUM",
                    title="เปิดบริการ Remote VNC (Port 5900)",
                    port=5900,
                    description=f"พบพอร์ต VNC เปิดใช้งาน ({vnc_banner or 'RFB'}) ซึ่งมักไม่เข้ารหัสทราฟฟิก",
                    remediation="ใช้งานผ่าน SSH Tunnel / VPN หรือปิดบริการหากไม่จำเป็น",
                )
            )

    # 2. Cleartext management protocols (Telnet 23, FTP 21)
    if 23 in ports:
        findings.append(
            VulnFinding(
                severity="HIGH",
                title="เปิดใช้ Telnet (ส่งรหัสผ่านแบบไม่เข้ารหัส)",
                port=23,
                description="โปรโตคอล Telnet ส่งชื่อผู้ใช้และรหัสผ่านเป็น Plaintext เสี่ยงต่อการดักจับข้อมูลในวงแลน",
                remediation="ปิดบริการ Telnet แล้วเปลี่ยนไปใช้ SSH (Port 22) หรือ HTTPS แทน",
            )
        )

    if 21 in ports:
        findings.append(
            VulnFinding(
                severity="MEDIUM",
                title="เปิดใช้ FTP (โอนไฟล์และล็อกอินแบบไม่เข้ารหัส)",
                port=21,
                description=f"พบพอร์ต FTP เปิดใช้งาน ({res.port_banners.get(21, 'FTP')})",
                remediation="เปลี่ยนไปใช้ SFTP (SSH) หรือ FTPS (TLS) และปิด Anonymous Login",
            )
        )

    # 3. End-of-Life Windows OS
    os_low = res.os_name.lower()
    if any(eol in os_low for eol in ("windows 7", "windows 8", "windows xp", "2008", "2012", "2003")):
        findings.append(
            VulnFinding(
                severity="HIGH",
                title="ระบบปฏิบัติการหมดระยะสนับสนุน (End-of-Life OS)",
                port=None,
                description=f"ตรวจพบ OS: {res.os_name} ซึ่งไม่ได้รับแพตช์อุดช่องโหว่ความปลอดภัยจากผู้ผลิตแล้ว",
                remediation="อัปเกรดเป็น Windows 10/11 หรือ Windows Server รุ่นที่ยังรองรับ หรือแยก VLAN เฉพาะ",
            )
        )

    # 4. SNMP public community exposure
    if res.snmp_info:
        findings.append(
            VulnFinding(
                severity="MEDIUM",
                title="SNMP ตอบสนองด้วย Community เริ่มต้น ('public')",
                port=161,
                description="สามารถอ่านข้อมูลระบบ/รุ่นอุปกรณ์ผ่าน SNMP v1/v2c ด้วยรหัส 'public' ได้",
                remediation="เปลี่ยน Community String จาก 'public' เป็นค่าที่เดายาก อัปเกรดเป็น SNMPv3 หรือจำกัด IP",
            )
        )

    # 5. Exposed Database ports
    for db_port, db_name in ((3306, "MySQL/MariaDB"), (5432, "PostgreSQL"), (1433, "Microsoft SQL Server")):
        if db_port in ports:
            banner = res.port_banners.get(db_port, db_name)
            findings.append(
                VulnFinding(
                    severity="MEDIUM",
                    title=f"เปิดพอร์ตฐานข้อมูล {db_name} สู่เครือข่าย",
                    port=db_port,
                    description=f"พอร์ต {db_port} ({banner}) เปิดรับการเชื่อมต่อจากเครื่องอื่นในวงแลน",
                    remediation="ตั้งค่า Bind Address เป็น 127.0.0.1 หากใช้เฉพาะในเครื่อง หรือตั้ง Firewall จำกัดเฉพาะ IP ที่อนุญาต",
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
                    )
                )

    # 6. MQTT unencrypted (1883)
    if 1883 in ports:
        findings.append(
            VulnFinding(
                severity="MEDIUM",
                title="เปิดพอร์ต MQTT (IoT) แบบไม่เข้ารหัส",
                port=1883,
                description="พอร์ต 1883 ส่งข้อมูลอุปกรณ์ IoT แบบไม่เข้ารหัส TLS และอาจเปิดรับคำสั่งโดยไม่ยืนยันตัวตน",
                remediation="เปิดใช้ Username/Password และเปลี่ยนไปใช้ MQTTS (Port 8883)",
            )
        )

    # 7. SMB Shares & NetBIOS
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
                )
            )
        else:
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
            )
        )

    # 8. RDP (3389)
    if 3389 in ports:
        findings.append(
            VulnFinding(
                severity="LOW",
                title="เปิดบริการ Remote Desktop (RDP 3389)",
                port=3389,
                description="เครื่องเปิดรับการรีโมตหน้าจอ RDP ในวงแลน",
                remediation="เปิดใช้ Network Level Authentication (NLA) ตั้งรหัสผ่านให้รัดกุม และจำกัด IP ที่รีโมตได้",
            )
        )

    # 9. HTTP unencrypted web management vs HTTPS
    has_https = bool(ports & {443, 8443, 5001})
    for hp in (80, 8080, 8000, 5000):
        if hp in ports:
            banner = res.port_banners.get(hp, "")
            if not has_https:
                findings.append(
                    VulnFinding(
                        severity="LOW",
                        title=f"เว็บจัดการอุปกรณ์ทำงานบน HTTP ไม่เข้ารหัส (Port {hp})",
                        port=hp,
                        description=f"พบเว็บเซิร์ฟเวอร์ ({banner or 'HTTP'}) โดยไม่มีพอร์ต HTTPS รองรับ",
                        remediation="หลีกเลี่ยงการล็อกอินผ่านเครือข่ายที่ไม่น่าเชื่อถือ หรือเปิดใช้ HTTPS หากอุปกรณ์รองรับ",
                    )
                )

    # 10. SSL/TLS Certificate checks
    today_str = date.today().isoformat()
    for cert in res.ssl_certs:
        c_port = int(cert["port"]) if str(cert.get("port", "")).isdigit() else None
        exp = cert.get("ssl_expires", "")
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
                )
            )
        elif subj and iss and subj == iss:
            findings.append(
                VulnFinding(
                    severity="INFO",
                    title=f"ใช้ใบรับรอง SSL แบบ Self-Signed (Port {c_port})",
                    port=c_port,
                    description=f"Subject และ Issuer เป็นชื่อเดียวกัน ({subj})",
                    remediation="สำหรับระบบภายในใช้งานได้ปกติ แต่หากเป็นระบบสำคัญควรใช้ Internal CA หรือ Let's Encrypt",
                )
            )

    # 11. SSH legacy version check
    ssh_b = res.port_banners.get(22, "")
    if ssh_b:
        if any(old in ssh_b for old in ("OpenSSH_4.", "OpenSSH_5.", "OpenSSH_6.", "OpenSSH_7.0", "OpenSSH_7.2")):
            findings.append(
                VulnFinding(
                    severity="LOW",
                    title="เวอร์ชัน SSH Server ค่อนข้างเก่า",
                    port=22,
                    description=f"ตรวจพบ Banner: {ssh_b}",
                    remediation="อัปเดต OpenSSH / Firmware อุปกรณ์ให้เป็นเวอร์ชันล่าสุด",
                )
            )

    # 12. RTSP Camera stream
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
