"""OS Fingerprinting & Service Banner Inspection (SMB2/NTLMSSP, SSH, HTTP/HTTPS, SSL Cert, Generic Banners)."""

from __future__ import annotations

import platform
import re
import socket
import ssl
import struct


def _decode_utf16le(data: bytes) -> str:
    try:
        return data.decode("utf-16-le", errors="ignore").strip("\x00 ")
    except Exception:
        return ""


def probe_smb_ntlm_os(ip_str: str, timeout: float = 0.45) -> dict[str, str]:
    """
    Perform a lightweight SMB2 Negotiate + NTLMSSP Negotiate handshake on TCP 445
    to extract exact Windows Build/Version and NetBIOS/DNS Computer & Domain names.
    """
    info: dict[str, str] = {}

    # 1. SMB2 Negotiate Request (dialects: 0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
    smb2_neg_hdr = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",  # 4
        64,          # 2 StructureSize
        0,           # 2 CreditCharge
        0,           # 4 Status
        0,           # 2 Command: NEGOTIATE
        1,           # 2 CreditRequest
        0,           # 4 Flags
        0,           # 4 NextCommand
        1,           # 8 MessageId
        0,           # 4 Reserved/ProcessId
        0,           # 4 TreeId
        0,           # 8 SessionId
        b"\x00" * 16,  # 16 Signature
    )
    dialects = struct.pack("<HHHHH", 0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
    smb2_neg_body = struct.pack(
        "<HHHHI16sQ",
        36,          # StructureSize
        5,           # DialectCount
        1,           # SecurityMode (signing enabled)
        0,           # Reserved
        0,           # Capabilities
        b"\x11" * 16,  # ClientGuid
        0,           # ClientStartTime
    ) + dialects
    neg_pdu = smb2_neg_hdr + smb2_neg_body
    neg_pkt = struct.pack(">I", len(neg_pdu)) + neg_pdu

    # 2. NTLMSSP_NEGOTIATE (Type 1) wrapped in minimal ASN.1/GSSAPI SPNEGO or raw NTLMSSP
    ntlm_type1 = struct.pack(
        "<8sIIHHIHHI",
        b"NTLMSSP\x00",
        1,           # MessageType = Negotiate
        0x60088215,  # Flags (Unicode, OEM, RequestTarget, NTLM, ExtendedSessionSec, AlwaysSign, Version)
        0, 0, 0,     # DomainNameFields
        0, 0, 0,     # WorkstationFields
    )
    # Wrap NTLMSSP Type 1 in simple SPNEGO NegTokenInit (OID 1.3.6.1.4.1.311.2.2.10 NTLMSSP)
    oid_ntlmssp = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
    oid_spnego = b"\x06\x06\x2b\x06\x01\x05\x05\x02"

    def _asn1_len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        if n <= 0xFF:
            return bytes([0x81, n])
        return struct.pack(">BH", 0x82, n)

    def _tlv(tag: int, val: bytes) -> bytes:
        return bytes([tag]) + _asn1_len(len(val)) + val

    mech_types = _tlv(0xA0, _tlv(0x30, oid_ntlmssp))
    mech_token = _tlv(0xA2, _tlv(0x04, ntlm_type1))
    neg_token_init = _tlv(0xA0, _tlv(0x30, mech_types + mech_token))
    spnego_blob = _tlv(0x60, oid_spnego + neg_token_init)

    smb2_ss_hdr = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",
        64,
        0,
        0,
        1,           # Command: SESSION_SETUP (1)
        1,
        0,
        0,
        2,           # MessageId = 2
        0,
        0,
        0,
        b"\x00" * 16,
    )
    # SessionSetup body: 25 bytes fixed (offset of SecurityBuffer = 64 + 24 = 88)
    smb2_ss_body = struct.pack(
        "<HBBIIHHQ",
        25,          # StructureSize
        0,           # Flags
        1,           # SecurityMode
        0,           # Capabilities
        0,           # Channel
        88,          # SecurityBufferOffset
        len(spnego_blob),  # SecurityBufferLength
        0,           # PreviousSessionId
    ) + spnego_blob
    ss_pdu = smb2_ss_hdr + smb2_ss_body
    ss_pkt = struct.pack(">I", len(ss_pdu)) + ss_pdu

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip_str, 445))
            sock.sendall(neg_pkt)
            resp1 = sock.recv(4096)
            if len(resp1) < 68 or resp1[4:8] != b"\xfeSMB":
                return info
            sock.sendall(ss_pkt)
            resp2 = sock.recv(4096)
    except OSError:
        return info

    idx = resp2.find(b"NTLMSSP\x00\x02\x00\x00\x00")
    if idx == -1 or len(resp2) < idx + 48:
        return info

    ntlm = resp2[idx:]
    try:
        target_len, _, target_off = struct.unpack_from("<HHI", ntlm, 12)
        flags = struct.unpack_from("<I", ntlm, 20)[0]
        ti_len, _, ti_off = struct.unpack_from("<HHI", ntlm, 40)

        if target_len > 0 and target_off + target_len <= len(ntlm):
            t_name = _decode_utf16le(ntlm[target_off : target_off + target_len])
            if t_name:
                info["target_name"] = t_name

        # Version struct (8 bytes at offset 48) when NTLMSSP_NEGOTIATE_VERSION (0x02000000) is set
        if (flags & 0x02000000) and len(ntlm) >= 56:
            major, minor, build, _, _, _, ntlm_rev = struct.unpack_from("<BBHBBBB", ntlm, 48)
            info["ntlm_version"] = f"{major}.{minor}.{build}"
            info["os_build"] = str(build)
            if major == 10 and minor == 0:
                if build >= 26100:
                    info["os_guess"] = f"Windows 11 24H2+ / Server 2025 (Build {build})"
                elif build >= 22000:
                    info["os_guess"] = f"Windows 11 (Build {build})"
                elif build >= 20348:
                    info["os_guess"] = f"Windows Server 2022 / Win 10 (Build {build})"
                elif build >= 17763:
                    info["os_guess"] = f"Windows 10 / Server 2019 (Build {build})"
                else:
                    info["os_guess"] = f"Windows 10 / Server 2016 (Build {build})"
            elif major == 6 and minor == 3:
                info["os_guess"] = f"Windows 8.1 / Server 2012 R2 (Build {build})"
            elif major == 6 and minor == 2:
                info["os_guess"] = f"Windows 8 / Server 2012 (Build {build})"
            elif major == 6 and minor == 1:
                info["os_guess"] = f"Windows 7 / Server 2008 R2 (Build {build})"
            elif major == 6 and minor == 0:
                info["os_guess"] = f"Windows Vista / Server 2008 (Build {build})"
            elif major == 5:
                info["os_guess"] = f"Windows XP / Server 2003 (Build {build})"

        # Parse AV_PAIR list inside TargetInfo
        if ti_len > 0 and ti_off + ti_len <= len(ntlm):
            pos = ti_off
            end = ti_off + ti_len
            while pos + 4 <= end:
                av_id, av_len = struct.unpack_from("<HH", ntlm, pos)
                pos += 4
                if av_id == 0 or pos + av_len > end:
                    break
                val_str = _decode_utf16le(ntlm[pos : pos + av_len])
                if av_id == 1 and val_str:
                    info["nb_computer"] = val_str
                elif av_id == 2 and val_str:
                    info["nb_domain"] = val_str
                elif av_id == 3 and val_str:
                    info["dns_computer"] = val_str
                elif av_id == 4 and val_str:
                    info["dns_domain"] = val_str
                pos += av_len
    except Exception:
        pass

    return info


def probe_ssh_banner(ip_str: str, port: int = 22, timeout: float = 0.4) -> str:
    """Grab SSH server identification banner (e.g. 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3')."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip_str, port))
            data = sock.recv(256)
            line = data.decode("utf-8", errors="ignore").splitlines()[0].strip()
            if line.startswith("SSH-"):
                return line
    except Exception:
        pass
    return ""


def probe_http_info(ip_str: str, port: int, use_ssl: bool = False, timeout: float = 0.55) -> dict[str, str]:
    """Fetch HTTP/HTTPS status, Server header, page <title>, and SSL cert Common Name."""
    result: dict[str, str] = {}
    req = (
        f"GET / HTTP/1.0\r\n"
        f"Host: {ip_str}\r\n"
        f"User-Agent: LANScanner/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip_str, port))

        if use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(raw_sock, server_hostname=ip_str)
            try:
                der_cert = conn.getpeercert(binary_form=True)
                if der_cert:
                    from cryptography import x509

                    cert_obj = x509.load_der_x509_certificate(der_cert)
                    subj = cert_obj.subject.rfc4514_string()
                    iss = cert_obj.issuer.rfc4514_string()
                    result["ssl_subject"] = subj[:100]
                    result["ssl_issuer"] = iss[:100]
                    result["ssl_expires"] = cert_obj.not_valid_after_utc.strftime("%Y-%m-%d")
                    try:
                        san = cert_obj.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )
                        dns_names = san.value.get_values_for_type(x509.DNSName)
                        if dns_names:
                            result["ssl_san"] = ", ".join(dns_names[:5])
                    except Exception:
                        pass
            except Exception:
                pass
        else:
            conn = raw_sock

        with conn:
            conn.sendall(req)
            chunks: list[bytes] = []
            total = 0
            while total < 4096:
                try:
                    chunk = conn.recv(1024)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            raw_resp = b"".join(chunks)
    except Exception:
        return result

    text = raw_resp.decode("utf-8", errors="ignore")
    if "\r\n\r\n" in text:
        hdr_part, body_part = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        hdr_part, body_part = text.split("\n\n", 1)
    else:
        hdr_part, body_part = text, ""

    lines = hdr_part.splitlines()
    if lines:
        result["status"] = lines[0].strip()[:60]
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            kl = k.strip().lower()
            if kl == "server":
                result["server"] = v.strip()[:80]
            elif kl == "location":
                result["location"] = v.strip()[:80]
            elif kl == "www-authenticate":
                result["auth"] = v.strip()[:60]

    m = re.search(r"<title[^>]*>(.*?)</title>", body_part, re.IGNORECASE | re.DOTALL)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()
        if title:
            result["title"] = title[:80]

    return result


def probe_generic_banner(ip_str: str, port: int, timeout: float = 0.35) -> str:
    """Read initial greeting banner for FTP(21), Telnet(23), SMTP(25), POP3(110), IMAP(143), VNC(5900)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip_str, port))
            data = sock.recv(256)
            cleaned = "".join(ch for ch in data.decode("utf-8", errors="ignore") if ch.isprintable()).strip()
            return cleaned[:90]
    except Exception:
        return ""


def probe_mysql_banner(ip_str: str, port: int = 3306, timeout: float = 0.35) -> str:
    """Parse MySQL / MariaDB initial handshake packet to extract exact server version."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip_str, port))
            data = sock.recv(256)
        if len(data) > 6 and data[4] == 10:
            end = data.find(b"\x00", 5)
            if end != -1:
                ver = data[5:end].decode("utf-8", errors="ignore").strip()
                if ver:
                    return f"MySQL/MariaDB {ver}"
    except Exception:
        pass
    return ""


def probe_rtsp_banner(ip_str: str, port: int = 554, timeout: float = 0.4) -> str:
    """Send RTSP OPTIONS to identify IP camera / NVR firmware."""
    req = f"OPTIONS rtsp://{ip_str}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode("ascii")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip_str, port))
            sock.sendall(req)
            resp = sock.recv(512).decode("utf-8", errors="ignore")
        for line in resp.splitlines():
            if line.lower().startswith("server:"):
                return f"RTSP ({line.split(':', 1)[1].strip()[:70]})"
        if resp.startswith("RTSP/"):
            return resp.splitlines()[0].strip()[:60]
    except Exception:
        pass
    return ""


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _ber_tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(val)) + val


def _encode_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for sub in parts[2:]:
        if sub == 0:
            out.append(0)
        else:
            enc = []
            while sub > 0:
                enc.append(sub & 0x7F)
                sub >>= 7
            enc.reverse()
            for i in range(len(enc) - 1):
                enc[i] |= 0x80
            out.extend(enc)
    return _ber_tlv(0x06, bytes(out))


def _read_ber_tlv(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    tag = buf[pos]
    pos += 1
    lbyte = buf[pos]
    pos += 1
    if lbyte & 0x80:
        num = lbyte & 0x7F
        length = int.from_bytes(buf[pos : pos + num], "big")
        pos += num
    else:
        length = lbyte
    val = buf[pos : pos + length]
    return tag, val, pos + length


def _decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    res = [raw[0] // 40, raw[0] % 40]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            res.append(val)
            val = 0
    return ".".join(str(x) for x in res)


def probe_rdp_ssl_cert(ip_str: str, port: int = 3389, timeout: float = 0.5) -> dict[str, str]:
    """Perform X.224 RDP Negotiate (PROTOCOL_SSL) + TLS handshake to extract RDP server certificate info."""
    info: dict[str, str] = {}
    # TPKT(4) + X.224 CR(7) + RDP_NEG_REQ(8) requesting SSL (0x01)
    rdp_neg = bytes.fromhex("030000130ee000000000000100080001000000")
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        raw.connect((ip_str, port))
        raw.sendall(rdp_neg)
        resp = raw.recv(64)
        if len(resp) < 11:
            raw.close()
            return info
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(raw, server_hostname=ip_str) as tls:
            der_cert = tls.getpeercert(binary_form=True)
            if der_cert:
                from cryptography import x509

                cert_obj = x509.load_der_x509_certificate(der_cert)
                info["ssl_subject"] = cert_obj.subject.rfc4514_string()[:100]
                info["ssl_issuer"] = cert_obj.issuer.rfc4514_string()[:100]
                info["ssl_expires"] = cert_obj.not_valid_after_utc.strftime("%Y-%m-%d")
    except Exception:
        pass

    # If device is a printer or responded to SNMP, try querying Printer-MIB toner/ink levels (1.3.6.1.2.1.43.11.1.1)
    if info and any(
        kw in info.get("sys_descr", "").lower()
        for kw in ("brother", "epson", "canon", "hewlett", "hp ", "ricoh", "kyocera", "xerox", "printer", "nc-")
    ):
        supplies: list[str] = []
        for idx in range(1, 6):
            oids_p = (
                f"1.3.6.1.2.1.43.11.1.1.6.1.{idx}",  # prtMarkerSuppliesDescription
                f"1.3.6.1.2.1.43.11.1.1.8.1.{idx}",  # prtMarkerSuppliesMaxCapacity
                f"1.3.6.1.2.1.43.11.1.1.9.1.{idx}",  # prtMarkerSuppliesLevel
            )
            vb_p = b"".join(_ber_tlv(0x30, _encode_oid(o) + b"\x05\x00") for o in oids_p)
            pdu_p = _ber_tlv(
                0xA0,
                _ber_tlv(0x02, (0x2000 + idx).to_bytes(2, "big"))
                + _ber_tlv(0x02, b"\x00")
                + _ber_tlv(0x02, b"\x00")
                + _ber_tlv(0x30, vb_p),
            )
            msg_p = _ber_tlv(
                0x30,
                _ber_tlv(0x02, b"\x01") + _ber_tlv(0x04, community.encode("ascii")) + pdu_p,
            )
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(timeout)
                    sock.sendto(msg_p, (ip_str, 161))
                    resp_p, _ = sock.recvfrom(2048)
                _, seq_b, _ = _read_ber_tlv(resp_p, 0)
                p = 0
                _, _, p = _read_ber_tlv(seq_b, p)
                _, _, p = _read_ber_tlv(seq_b, p)
                _, pdu_b, _ = _read_ber_tlv(seq_b, p)
                q = 0
                _, _, q = _read_ber_tlv(pdu_b, q)
                _, _, q = _read_ber_tlv(pdu_b, q)
                _, _, q = _read_ber_tlv(pdu_b, q)
                _, vbl_b, _ = _read_ber_tlv(pdu_b, q)
                r = 0
                desc_s, max_c, cur_l = "", 0, -1
                while r < len(vbl_b):
                    _, vb_i, r = _read_ber_tlv(vbl_b, r)
                    k = 0
                    _, oid_r, k = _read_ber_tlv(vb_i, k)
                    vt, vr, _ = _read_ber_tlv(vb_i, k)
                    os_str = _decode_oid(oid_r)
                    if os_str.startswith("1.3.6.1.2.1.43.11.1.1.6.") and vt == 0x04:
                        desc_s = vr.decode("utf-8", errors="ignore").strip()
                    elif os_str.startswith("1.3.6.1.2.1.43.11.1.1.8.") and vt == 0x02:
                        max_c = int.from_bytes(vr, "big", signed=True)
                    elif os_str.startswith("1.3.6.1.2.1.43.11.1.1.9.") and vt == 0x02:
                        cur_l = int.from_bytes(vr, "big", signed=True)
                if desc_s:
                    if max_c > 0 and cur_l >= 0:
                        pct = min(100, int(round(cur_l * 100 / max_c)))
                        supplies.append(f"{desc_s}: {pct}%")
                    elif cur_l == -3:
                        supplies.append(f"{desc_s}: OK")
                    elif cur_l == 0:
                        supplies.append(f"{desc_s}: 0% (Empty)")
                    else:
                        supplies.append(desc_s)
            except Exception:
                break
        if supplies:
            info["printer_supplies"] = " | ".join(supplies)

    return info


def probe_smb_shares(ip_str: str, timeout: float = 0.8) -> list[str]:
    """Enumerate visible SMB shares via Windows NetShareEnum (netapi32.dll) with short timeout."""
    import ctypes
    import ctypes.wintypes as wt

    class _SHARE_INFO_1(ctypes.Structure):
        _fields_ = [
            ("shi1_netname", wt.LPWSTR),
            ("shi1_type", wt.DWORD),
            ("shi1_remark", wt.LPWSTR),
        ]

    shares: list[str] = []
    try:
        netapi32 = ctypes.windll.netapi32
        buf_ptr = ctypes.c_void_p()
        entries_read = wt.DWORD()
        total_entries = wt.DWORD()
        resume_handle = wt.DWORD(0)

        ret = netapi32.NetShareEnum(
            ctypes.c_wchar_p(f"\\\\{ip_str}"),
            1,
            ctypes.byref(buf_ptr),
            0xFFFFFFFF,
            ctypes.byref(entries_read),
            ctypes.byref(total_entries),
            ctypes.byref(resume_handle),
        )
        if ret == 0 and buf_ptr:
            try:
                arr = ctypes.cast(buf_ptr, ctypes.POINTER(_SHARE_INFO_1))
                for i in range(entries_read.value):
                    name = arr[i].shi1_netname or ""
                    stype = arr[i].shi1_type & 0x0FFFFFFF
                    kind = {0: "Disk", 1: "Printer", 2: "Device", 3: "IPC"}.get(stype, "Other")
                    if name:
                        shares.append(f"{name} ({kind})")
            finally:
                netapi32.NetApiBufferFree(buf_ptr)
    except Exception:
        pass
    return shares[:20]


def probe_vnc_banner(ip_str: str, port: int = 5900, timeout: float = 0.4) -> str:
    """Read VNC RFB protocol version and supported security types."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip_str, port))
            ver = sock.recv(64).decode("ascii", errors="ignore").strip()
            if not ver.startswith("RFB "):
                return ""
            # Echo back client RFB version to read security types
            sock.sendall((ver + "\n").encode("ascii"))
            sec = sock.recv(32)
            sec_names = {1: "None (No Auth!)", 2: "VNC Auth", 16: "Tight", 18: "TLS", 19: "VeNCrypt"}
            if ver >= "RFB 003.007" and sec and sec[0] > 0:
                types = [sec_names.get(b, f"Type {b}") for b in sec[1 : 1 + sec[0]]]
                return f"{ver} [Auth: {', '.join(types[:4])}]"
            return ver
    except Exception:
        return ""


def probe_postgres_banner(ip_str: str, port: int = 5432, timeout: float = 0.35) -> str:
    """Probe PostgreSQL port 5432 with SSLRequest to confirm PostgreSQL service & TLS support."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip_str, port))
            # PostgreSQL SSLRequest packet: length=8, code=80877103
            sock.sendall(struct.pack(">II", 8, 80877103))
            resp = sock.recv(16)
            if resp == b"S":
                return "PostgreSQL (SSL Supported)"
            if resp == b"N":
                return "PostgreSQL (No SSL)"
    except Exception:
        pass
    return ""


def probe_snmp_sysinfo(ip_str: str, community: str = "public", timeout: float = 0.28) -> dict[str, str]:
    """Query SNMPv2c UDP 161 for sysDescr (1.1.0), sysUpTime (1.3.0), sysName (1.5.0)."""
    oids = ("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0")
    varbinds = b"".join(_ber_tlv(0x30, _encode_oid(o) + b"\x05\x00") for o in oids)
    req_id = 0x1234
    pdu = _ber_tlv(
        0xA0,
        _ber_tlv(0x02, req_id.to_bytes(2, "big"))
        + _ber_tlv(0x02, b"\x00")
        + _ber_tlv(0x02, b"\x00")
        + _ber_tlv(0x30, varbinds),
    )
    msg = _ber_tlv(
        0x30,
        _ber_tlv(0x02, b"\x01") + _ber_tlv(0x04, community.encode("ascii")) + pdu,
    )
    info: dict[str, str] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(msg, (ip_str, 161))
            resp, _ = sock.recvfrom(4096)
    except OSError:
        return info

    try:
        _, seq_body, _ = _read_ber_tlv(resp, 0)
        p = 0
        _, _, p = _read_ber_tlv(seq_body, p)  # version
        _, _, p = _read_ber_tlv(seq_body, p)  # community
        _, pdu_body, _ = _read_ber_tlv(seq_body, p)
        q = 0
        _, _, q = _read_ber_tlv(pdu_body, q)  # req_id
        _, _, q = _read_ber_tlv(pdu_body, q)  # err_status
        _, _, q = _read_ber_tlv(pdu_body, q)  # err_idx
        _, vbl_body, _ = _read_ber_tlv(pdu_body, q)
        r = 0
        while r < len(vbl_body):
            _, vb_item, r = _read_ber_tlv(vbl_body, r)
            k = 0
            _, oid_raw, k = _read_ber_tlv(vb_item, k)
            vtag, vraw, _ = _read_ber_tlv(vb_item, k)
            oid_s = _decode_oid(oid_raw)
            if oid_s == "1.3.6.1.2.1.1.1.0" and vtag == 0x04:
                info["sys_descr"] = vraw.decode("utf-8", errors="ignore").strip()[:140]
            elif oid_s == "1.3.6.1.2.1.1.3.0" and vtag == 0x43:
                ticks = int.from_bytes(vraw, "big")
                secs = ticks // 100
                days, rem = divmod(secs, 86400)
                hrs, rem = divmod(rem, 3600)
                mins, _ = divmod(rem, 60)
                info["uptime"] = f"{days} วัน {hrs} ชม. {mins} นาที" if days else f"{hrs} ชม. {mins} นาที"
            elif oid_s == "1.3.6.1.2.1.1.5.0" and vtag == 0x04:
                info["sys_name"] = vraw.decode("utf-8", errors="ignore").strip()[:80]
    except Exception:
        pass

    # If device is a printer or responded to SNMP, try querying Printer-MIB toner/ink levels (1.3.6.1.2.1.43.11.1.1)
    if info and any(
        kw in info.get("sys_descr", "").lower()
        for kw in ("brother", "epson", "canon", "hewlett", "hp ", "ricoh", "kyocera", "xerox", "printer", "nc-")
    ):
        supplies: list[str] = []
        for idx in range(1, 6):
            oids_p = (
                f"1.3.6.1.2.1.43.11.1.1.6.1.{idx}",  # prtMarkerSuppliesDescription
                f"1.3.6.1.2.1.43.11.1.1.8.1.{idx}",  # prtMarkerSuppliesMaxCapacity
                f"1.3.6.1.2.1.43.11.1.1.9.1.{idx}",  # prtMarkerSuppliesLevel
            )
            vb_p = b"".join(_ber_tlv(0x30, _encode_oid(o) + b"\x05\x00") for o in oids_p)
            pdu_p = _ber_tlv(
                0xA0,
                _ber_tlv(0x02, (0x2000 + idx).to_bytes(2, "big"))
                + _ber_tlv(0x02, b"\x00")
                + _ber_tlv(0x02, b"\x00")
                + _ber_tlv(0x30, vb_p),
            )
            msg_p = _ber_tlv(
                0x30,
                _ber_tlv(0x02, b"\x01") + _ber_tlv(0x04, community.encode("ascii")) + pdu_p,
            )
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(timeout)
                    sock.sendto(msg_p, (ip_str, 161))
                    resp_p, _ = sock.recvfrom(2048)
                _, seq_b, _ = _read_ber_tlv(resp_p, 0)
                p = 0
                _, _, p = _read_ber_tlv(seq_b, p)
                _, _, p = _read_ber_tlv(seq_b, p)
                _, pdu_b, _ = _read_ber_tlv(seq_b, p)
                q = 0
                _, _, q = _read_ber_tlv(pdu_b, q)
                _, _, q = _read_ber_tlv(pdu_b, q)
                _, _, q = _read_ber_tlv(pdu_b, q)
                _, vbl_b, _ = _read_ber_tlv(pdu_b, q)
                r = 0
                desc_s, max_c, cur_l = "", 0, -1
                while r < len(vbl_b):
                    _, vb_i, r = _read_ber_tlv(vbl_b, r)
                    k = 0
                    _, oid_r, k = _read_ber_tlv(vb_i, k)
                    vt, vr, _ = _read_ber_tlv(vb_i, k)
                    os_str = _decode_oid(oid_r)
                    if os_str.startswith("1.3.6.1.2.1.43.11.1.1.6.") and vt == 0x04:
                        desc_s = vr.decode("utf-8", errors="ignore").strip()
                    elif os_str.startswith("1.3.6.1.2.1.43.11.1.1.8.") and vt == 0x02:
                        max_c = int.from_bytes(vr, "big", signed=True)
                    elif os_str.startswith("1.3.6.1.2.1.43.11.1.1.9.") and vt == 0x02:
                        cur_l = int.from_bytes(vr, "big", signed=True)
                if desc_s:
                    if max_c > 0 and cur_l >= 0:
                        pct = min(100, int(round(cur_l * 100 / max_c)))
                        supplies.append(f"{desc_s}: {pct}%")
                    elif cur_l == -3:
                        supplies.append(f"{desc_s}: OK")
                    elif cur_l == 0:
                        supplies.append(f"{desc_s}: 0% (Empty)")
                    else:
                        supplies.append(desc_s)
            except Exception:
                break
        if supplies:
            info["printer_supplies"] = " | ".join(supplies)

    return info


def probe_ssdp_upnp(ip_str: str, timeout: float = 0.25) -> dict[str, str]:
    """Send unicast SSDP M-SEARCH to UDP 1900 for UPnP server/device description."""
    msg = (
        f"M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip_str}:1900\r\n"
        f'MAN: "ssdp:discover"\r\n'
        f"MX: 1\r\n"
        f"ST: ssdp:all\r\n\r\n"
    ).encode("ascii")
    info: dict[str, str] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(msg, (ip_str, 1900))
            resp, _ = sock.recvfrom(2048)
        text = resp.decode("utf-8", errors="ignore")
        for line in text.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                kl = k.strip().lower()
                if kl == "server" and "server" not in info:
                    info["server"] = v.strip()[:90]
                elif kl == "location" and "location" not in info:
                    info["location"] = v.strip()[:120]
        # Fetch UPnP XML description if hosted on same IP
        loc = info.get("location", "")
        if loc.startswith(f"http://{ip_str}"):
            try:
                import urllib.request

                with urllib.request.urlopen(loc, timeout=0.4) as r:
                    xml_txt = r.read(8192).decode("utf-8", errors="ignore")
                for tag in ("friendlyName", "manufacturer", "modelName", "serialNumber"):
                    m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", xml_txt, re.IGNORECASE | re.DOTALL)
                    if m and m.group(1).strip():
                        info[tag] = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            except Exception:
                pass
    except OSError:
        pass
    return info


def collect_host_banners(
    ip_str: str,
    open_ports: list[int],
    timeout_scale: float = 1.0,
    probe_udp_services: bool = False,
) -> dict[str, object]:
    """
    Probe open ports (and optional SNMP/SSDP) on an alive host to gather OS clues and service banners.
    Returns dict with keys: 'smb', 'ssh', 'http', 'snmp', 'upnp', 'ssl_certs', 'banners'.
    """
    banners: dict[int, str] = {}
    smb_info: dict[str, str] = {}
    ssh_banner = ""
    http_infos: list[dict[str, str]] = []
    ssl_certs: list[dict[str, str]] = []
    ports_set = set(open_ports)

    if 445 in ports_set:
        smb_info = probe_smb_ntlm_os(ip_str, timeout=0.45 * timeout_scale)
        if smb_info.get("os_guess"):
            banners[445] = f"SMB2 ({smb_info['os_guess']})"
        elif smb_info.get("target_name"):
            banners[445] = f"SMB2 ({smb_info['target_name']})"

    if 22 in ports_set:
        ssh_banner = probe_ssh_banner(ip_str, 22, timeout=0.4 * timeout_scale)
        if ssh_banner:
            banners[22] = ssh_banner

    for hp in (80, 443, 8080, 8443, 8000, 5000, 5001):
        if hp in ports_set:
            use_ssl = hp in (443, 8443, 5001)
            hinfo = probe_http_info(ip_str, hp, use_ssl=use_ssl, timeout=0.5 * timeout_scale)
            if hinfo:
                http_infos.append(hinfo)
                parts = []
                if hinfo.get("server"):
                    parts.append(hinfo["server"])
                if hinfo.get("title"):
                    parts.append(f'"{hinfo["title"]}"')
                if not parts and hinfo.get("status"):
                    parts.append(hinfo["status"])
                if parts:
                    banners[hp] = " | ".join(parts)
                if hinfo.get("ssl_subject"):
                    ssl_certs.append({"port": str(hp), **hinfo})

    if 554 in ports_set:
        rtsp_b = probe_rtsp_banner(ip_str, 554, timeout=0.4 * timeout_scale)
        if rtsp_b:
            banners[554] = rtsp_b

    if 3306 in ports_set:
        mysql_b = probe_mysql_banner(ip_str, 3306, timeout=0.35 * timeout_scale)
        if mysql_b:
            banners[3306] = mysql_b

    if 5432 in ports_set:
        pg_b = probe_postgres_banner(ip_str, 5432, timeout=0.35 * timeout_scale)
        if pg_b:
            banners[5432] = pg_b

    if 5900 in ports_set:
        vnc_b = probe_vnc_banner(ip_str, 5900, timeout=0.4 * timeout_scale)
        if vnc_b:
            banners[5900] = vnc_b

    if 3389 in ports_set:
        rdp_cert = probe_rdp_ssl_cert(ip_str, 3389, timeout=0.5 * timeout_scale)
        if rdp_cert.get("ssl_subject"):
            ssl_certs.append({"port": "3389", **rdp_cert})
            banners[3389] = f"RDP TLS ({rdp_cert['ssl_subject']})"

    for gp in (21, 23, 25, 110, 143):
        if gp in ports_set:
            gb = probe_generic_banner(ip_str, gp, timeout=0.35 * timeout_scale)
            if gb:
                banners[gp] = gb

    smb_shares: list[str] = []
    snmp_info: dict[str, str] = {}
    upnp_info: dict[str, str] = {}
    if probe_udp_services:
        snmp_info = probe_snmp_sysinfo(ip_str, timeout=0.32 * timeout_scale)
        upnp_info = probe_ssdp_upnp(ip_str, timeout=0.28 * timeout_scale)
        if 445 in ports_set:
            smb_shares = probe_smb_shares(ip_str)

    return {
        "smb": smb_info,
        "smb_shares": smb_shares,
        "ssh": ssh_banner,
        "http": http_infos,
        "ssl_certs": ssl_certs,
        "snmp": snmp_info,
        "upnp": upnp_info,
        "banners": banners,
    }


def detect_os(
    *,
    is_local_pc: bool,
    open_ports: list[int],
    ttl: int | None,
    vendor: str,
    hostname: str,
    smb_info: dict[str, str],
    ssh_banner: str,
    http_infos: list[dict[str, str]],
) -> tuple[str, str, str]:
    """
    Infer OS name, confidence level, and evidence summary from multi-protocol probes.
    Returns (os_name, confidence, evidence).
    """
    if is_local_pc:
        win_rel = platform.release()
        win_ver = platform.version()
        os_str = f"Windows {win_rel} (Build {win_ver})"
        return os_str, "100% (เครื่องนี้)", f"Local OS ({platform.platform()})"

    evidences: list[str] = []
    ports_set = set(open_ports)
    v_low = vendor.lower()
    h_low = hostname.lower()

    # 1. Exact SMB2 NTLMSSP OS Version
    if smb_info.get("os_guess"):
        evidences.append(f"SMB NTLMSSP v{smb_info.get('ntlm_version', '')}")
        if ttl is not None:
            evidences.append(f"TTL={ttl}")
        return smb_info["os_guess"], "สูง (High)", " • ".join(evidences)

    # 2. SSH Banner OS clues
    if ssh_banner:
        s_low = ssh_banner.lower()
        evidences.append(f"SSH: {ssh_banner}")
        if ttl is not None:
            evidences.append(f"TTL={ttl}")
        if "rosssh" in s_low or "mikrotik" in v_low:
            return "MikroTik RouterOS", "สูง (High)", " • ".join(evidences)
        if "for_windows" in s_low:
            return "Windows (OpenSSH)", "สูง (High)", " • ".join(evidences)
        if "ubuntu" in s_low:
            return "Linux (Ubuntu)", "สูง (High)", " • ".join(evidences)
        if "debian" in s_low:
            return "Linux (Debian)", "สูง (High)", " • ".join(evidences)
        if "raspbian" in s_low or "raspberry" in v_low:
            return "Linux (Raspberry Pi OS)", "สูง (High)", " • ".join(evidences)
        if "dropbear" in s_low:
            return "Embedded Linux (Dropbear)", "สูง (High)", " • ".join(evidences)
        if "cisco" in s_low or "cisco" in v_low:
            return "Cisco IOS / NX-OS", "สูง (High)", " • ".join(evidences)
        if "zyxel" in v_low:
            return "Zyxel Firmware (Embedded)", "ปานกลาง (Medium)", " • ".join(evidences)
        if ttl is not None and ttl <= 64:
            return "Linux / Unix (OpenSSH)", "ปานกลาง (Medium)", " • ".join(evidences)

    # 3. HTTP Server / Title clues
    for h in http_infos:
        srv = h.get("server", "")
        title = h.get("title", "")
        combo = f"{srv} {title}".lower()
        if srv:
            evidences.append(f"HTTP Server: {srv}")
        if title:
            evidences.append(f"Title: {title}")
        if "microsoft-iis" in combo or "microsoft-httpapi" in combo:
            return "Windows Server / Windows", "สูง (High)", " • ".join(evidences)
        if "routeros" in combo or "mikrotik" in combo:
            return "MikroTik RouterOS", "สูง (High)", " • ".join(evidences)
        if "synology" in combo or "diskstation" in combo:
            return "Synology DSM (Linux)", "สูง (High)", " • ".join(evidences)
        if "proxmox" in combo:
            return "Proxmox VE (Debian Linux)", "สูง (High)", " • ".join(evidences)
        if "esxi" in combo or "vmware" in combo:
            return "VMware ESXi", "สูง (High)", " • ".join(evidences)
        if "brother" in combo or "virata-emweb" in combo or "debut" in combo:
            return "Printer Firmware (Embedded)", "ปานกลาง (Medium)", " • ".join(evidences)
        if "hikvision" in combo or "dahua" in combo or "app-webs" in combo:
            return "Embedded Linux (NVR/CCTV)", "ปานกลาง (Medium)", " • ".join(evidences)

    # 4. Vendor + Port heuristics
    if any(b in v_low for b in ("brother", "epson", "canon", "ricoh", "kyocera", "xerox")) or (
        ports_set & {9100, 515, 631}
    ):
        evidences.append("Printer Port/OUI")
        if ttl is not None:
            evidences.append(f"TTL={ttl}")
        return "Printer Firmware (Embedded)", "ปานกลาง (Medium)", " • ".join(evidences)

    if any(b in v_low for b in ("mikrotik",)):
        return "MikroTik RouterOS", "ปานกลาง (Medium)", f"Vendor={vendor}"

    if any(b in v_low for b in ("cisco", "aruba", "fortinet", "ruijie", "ubiquiti", "zyxel")):
        if ttl is not None:
            evidences.append(f"TTL={ttl}")
        evidences.append(f"Vendor={vendor}")
        return "Network OS / Embedded Linux", "ปานกลาง (Medium)", " • ".join(evidences)

    if 3389 in ports_set or (ports_set & {135, 139, 445}):
        evidences.append("Windows Ports (RDP/SMB/NetBIOS)")
        if ttl is not None:
            evidences.append(f"TTL={ttl}")
        return "Windows", "ปานกลาง (Medium)", " • ".join(evidences)

    # 5. TTL Fallback
    if ttl is not None:
        evidences.append(f"ICMP TTL={ttl}")
        if 96 < ttl <= 128:
            return "Windows (คาดการณ์จาก TTL)", "คาดการณ์ (Low)", " • ".join(evidences)
        if 32 < ttl <= 64:
            if "apple" in v_low or "iphone" in h_low or "mac" in h_low:
                return "macOS / iOS", "ปานกลาง (Medium)", f"Vendor={vendor} • TTL={ttl}"
            if any(b in v_low for b in ("samsung", "xiaomi", "oppo", "vivo")):
                return "Android (Linux)", "ปานกลาง (Medium)", f"Vendor={vendor} • TTL={ttl}"
            return "Linux / Unix / Embedded", "คาดการณ์ (Low)", " • ".join(evidences)
        if ttl > 200:
            return "Network Gear / Embedded OS", "คาดการณ์ (Low)", " • ".join(evidences)

    return "ไม่ทราบ OS", "ต่ำ (Unknown)", "ไม่มีพอร์ต/TTL ที่ระบุ OS ได้"
