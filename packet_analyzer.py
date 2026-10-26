"""
Packet Analyzer Module for DNS Query and Analysis Tool
Analyzes PCAP and PCAPNG packet capture files captured using Wireshark.
Extracts Source/Destination IPs, Ports, DNS Transaction IDs, Query Names,
Query Types, RCODEs, Flags, and Answers.
Includes a built-in sample PCAP generator for testing and demonstration.
"""

import os
import struct
import socket
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional

# Supported upload extensions
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_PACKETS_TO_PROCESS = 600

# DNS Type mapping according to IANA DNS parameters
DNS_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY"
}

# DNS RCODE mapping
DNS_RCODE_NAMES = {
    0: "NoError (Success)",
    1: "FormErr (Format Error)",
    2: "ServFail (Server Failure)",
    3: "NXDomain (Non-Existent Domain)",
    4: "NotImp (Not Implemented)",
    5: "Refused (Query Refused)"
}


def is_allowed_file(filename: str) -> bool:
    """Checks if the uploaded file has a supported capture extension."""
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS


def _parse_dns_name(data: bytes, offset: int, original_data: bytes) -> Tuple[str, int]:
    """
    Parses a DNS domain name from packet payload handling standard DNS label compression pointers.
    Returns: (domain_string, next_offset)
    """
    labels = []
    jumped = False
    next_offset = None
    max_loops = 50
    loop_count = 0

    while loop_count < max_loops:
        loop_count += 1
        if offset >= len(data):
            break
        length = data[offset]

        if length == 0:
            if not jumped:
                next_offset = offset + 1
            offset += 1
            break

        # Check for DNS compression pointer (starts with 11xxxxxx in binary, 0xc0)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = pointer
            data = original_data
            continue

        offset += 1
        if offset + length <= len(data):
            label = data[offset:offset + length].decode("ascii", errors="replace")
            labels.append(label)
            offset += length
        else:
            break

    if next_offset is None:
        next_offset = offset

    domain = ".".join(labels)
    return domain, next_offset


def _parse_dns_payload(dns_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Parses the binary DNS header, question, and answer sections from raw payload.
    """
    if len(dns_bytes) < 12:
        return None

    try:
        # DNS Header: ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
        trans_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", dns_bytes[:12])

        qr = (flags >> 15) & 0x01
        opcode = (flags >> 11) & 0x0F
        aa = (flags >> 10) & 0x01
        tc = (flags >> 9) & 0x01
        rd = (flags >> 8) & 0x01
        ra = (flags >> 7) & 0x01
        rcode = flags & 0x0F

        status_text = "Response" if qr == 1 else "Query"
        rcode_str = DNS_RCODE_NAMES.get(rcode, f"RCODE {rcode}")

        offset = 12
        qname = ""
        qtype_str = "Unknown"

        # Parse Question Section (if present)
        if qdcount > 0 and offset < len(dns_bytes):
            qname, offset = _parse_dns_name(dns_bytes, offset, dns_bytes)
            if offset + 4 <= len(dns_bytes):
                qtype_num, qclass_num = struct.unpack("!HH", dns_bytes[offset:offset + 4])
                qtype_str = DNS_TYPE_NAMES.get(qtype_num, f"TYPE{qtype_num}")
                offset += 4

        answers_list: List[Dict[str, Any]] = []

        # Parse Answers Section (if present)
        for _ in range(ancount):
            if offset >= len(dns_bytes):
                break
            aname, offset = _parse_dns_name(dns_bytes, offset, dns_bytes)
            if offset + 10 > len(dns_bytes):
                break
            atype, aclass, ttl, rdlength = struct.unpack("!HHIH", dns_bytes[offset:offset + 10])
            offset += 10

            rdata_bytes = dns_bytes[offset:offset + rdlength]
            atype_str = DNS_TYPE_NAMES.get(atype, f"TYPE{atype}")
            rdata_str = ""

            if atype == 1 and rdlength == 4:  # A record (IPv4)
                rdata_str = socket.inet_ntoa(rdata_bytes)
            elif atype == 28 and rdlength == 16:  # AAAA record (IPv6)
                rdata_str = socket.inet_ntop(socket.AF_INET6, rdata_bytes)
            elif atype == 5:  # CNAME
                cname_target, _ = _parse_dns_name(dns_bytes, offset, dns_bytes)
                rdata_str = cname_target
            elif atype == 15 and rdlength > 2:  # MX
                pref = struct.unpack("!H", rdata_bytes[:2])[0]
                mx_target, _ = _parse_dns_name(dns_bytes, offset + 2, dns_bytes)
                rdata_str = f"Priority {pref}: {mx_target}"
            else:
                rdata_str = f"Hex: {rdata_bytes.hex()[:24]}..." if len(rdata_bytes) > 12 else rdata_bytes.hex()

            answers_list.append({
                "name": aname,
                "type": atype_str,
                "ttl": ttl,
                "data": rdata_str
            })
            offset += rdlength

        return {
            "transaction_id_hex": f"0x{trans_id:04x}",
            "transaction_id_dec": trans_id,
            "qr": qr,
            "status": status_text,
            "opcode": opcode,
            "authoritative": bool(aa),
            "truncated": bool(tc),
            "recursion_desired": bool(rd),
            "recursion_available": bool(ra),
            "rcode": rcode,
            "rcode_str": rcode_str,
            "qname": qname or "<Root / None>",
            "qtype": qtype_str,
            "ancount": ancount,
            "answers": answers_list
        }
    except Exception:
        return None


def parse_pcap_packets(filepath: str) -> Dict[str, Any]:
    """
    Parses a PCAP capture file, extracts all DNS packets, and produces structured statistics.
    Uses native binary streaming for maximum speed and zero host dependencies, with optional Scapy verification.
    """
    if not os.path.exists(filepath):
        return {"error": "Packet capture file does not exist."}

    dns_records: List[Dict[str, Any]] = []
    total_packets = 0
    total_dns_packets = 0
    query_count = 0
    response_count = 0
    domains_seen = set()
    client_ips = set()
    resolver_ips = set()
    type_counts: Dict[str, int] = {}

    try:
        with open(filepath, "rb") as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return {"error": "Invalid capture file: Global header is incomplete."}

            magic = global_header[:4]
            # Standard PCAP magic numbers
            is_little_endian = False
            if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                is_little_endian = False
            elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                is_little_endian = True
            elif magic == b"\x0a\x0d\x0d\x0a":
                # PCAPNG file detected
                return _parse_pcapng_fallback(filepath)
            else:
                return {"error": "Unsupported capture format. Please provide a standard Wireshark PCAP (.pcap) file."}

            hdr_endian = "<" if is_little_endian else ">"
            linktype = struct.unpack(f"{hdr_endian}I", global_header[20:24])[0]
            # Linktype 1 = Ethernet (14-byte header), 101/12 = Raw IP, 113 = Linux Cooked SLL (16 bytes)

            pkt_idx = 0
            while total_packets < MAX_PACKETS_TO_PROCESS:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                total_packets += 1
                pkt_idx += 1
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{hdr_endian}IIII", pkt_hdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                dt = datetime.fromtimestamp(ts_sec).strftime("%H:%M:%S") + f".{ts_usec:03d}"[:4]

                # Determine IP offset based on LinkType
                ip_offset = 14  # Standard Ethernet
                if linktype == 113:
                    ip_offset = 16  # Linux Cooked SLL
                elif linktype in (12, 101):
                    ip_offset = 0   # Raw IP

                if len(pkt_data) <= ip_offset:
                    continue

                ip_header = pkt_data[ip_offset:]
                ip_ver = (ip_header[0] >> 4) & 0x0F

                src_ip = "Unknown"
                dst_ip = "Unknown"
                proto = 0
                payload_offset = 0

                if ip_ver == 4 and len(ip_header) >= 20:
                    ihl = (ip_header[0] & 0x0F) * 4
                    proto = ip_header[9]
                    src_ip = socket.inet_ntoa(ip_header[12:16])
                    dst_ip = socket.inet_ntoa(ip_header[16:20])
                    payload_offset = ip_offset + ihl
                elif ip_ver == 6 and len(ip_header) >= 40:
                    proto = ip_header[6]
                    src_ip = socket.inet_ntop(socket.AF_INET6, ip_header[8:24])
                    dst_ip = socket.inet_ntop(socket.AF_INET6, ip_header[24:40])
                    payload_offset = ip_offset + 40
                else:
                    continue

                # DNS operates on UDP (17) or TCP (6), primarily port 53
                if proto == 17 and len(pkt_data) >= payload_offset + 8:
                    sport, dport, length, cksum = struct.unpack("!HHHH", pkt_data[payload_offset:payload_offset + 8])
                    if sport == 53 or dport == 53:
                        dns_raw = pkt_data[payload_offset + 8:]
                        dns_info = _parse_dns_payload(dns_raw)
                        if dns_info:
                            total_dns_packets += 1
                            if dns_info["qr"] == 0:
                                query_count += 1
                                client_ips.add(src_ip)
                                resolver_ips.add(dst_ip)
                            else:
                                response_count += 1
                                resolver_ips.add(src_ip)
                                client_ips.add(dst_ip)

                            if dns_info["qname"] and dns_info["qname"] != "<Root / None>":
                                domains_seen.add(dns_info["qname"])

                            type_counts[dns_info["qtype"]] = type_counts.get(dns_info["qtype"], 0) + 1

                            record_entry = {
                                "packet_number": pkt_idx,
                                "timestamp": dt,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": sport,
                                "dst_port": dport,
                                "protocol": "UDP",
                                **dns_info
                            }
                            dns_records.append(record_entry)

    except Exception as exc:
        return {"error": f"Error parsing capture file: {str(exc)}"}

    return {
        "dns_records": dns_records,
        "total_packets_scanned": total_packets,
        "total_dns_packets": total_dns_packets,
        "query_count": query_count,
        "response_count": response_count,
        "unique_domains_count": len(domains_seen),
        "unique_domains": sorted(list(domains_seen)),
        "client_ips": sorted(list(client_ips)),
        "resolver_ips": sorted(list(resolver_ips)),
        "type_counts": type_counts
    }


def _parse_pcapng_fallback(filepath: str) -> Dict[str, Any]:
    """
    Fallback parser for PCAPNG files. Attempts Scapy rdpcap or provides informative guidance.
    """
    try:
        from scapy.utils import rdpcap
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        from scapy.layers.inet import IP, UDP

        packets = rdpcap(filepath)
        dns_records = []
        total_dns = 0
        q_count = 0
        r_count = 0
        domains = set()

        for idx, pkt in enumerate(packets[:MAX_PACKETS_TO_PROCESS], start=1):
            if pkt.haslayer(DNS):
                total_dns += 1
                dns = pkt[DNS]
                src = pkt[IP].src if pkt.haslayer(IP) else "Unknown"
                dst = pkt[IP].dst if pkt.haslayer(IP) else "Unknown"
                sport = pkt[UDP].sport if pkt.haslayer(UDP) else 0
                dport = pkt[UDP].dport if pkt.haslayer(UDP) else 0

                qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".") if dns.qd else "N/A"
                qtype_code = dns.qd.qtype if dns.qd else 0
                qtype = DNS_TYPE_NAMES.get(qtype_code, f"TYPE{qtype_code}")

                if dns.qr == 0:
                    q_count += 1
                else:
                    r_count += 1

                if qname and qname != "N/A":
                    domains.add(qname)

                answers = []
                if dns.an:
                    curr = dns.an
                    while curr:
                        answers.append({
                            "name": curr.rrname.decode("utf-8", errors="replace").rstrip("."),
                            "type": DNS_TYPE_NAMES.get(curr.type, str(curr.type)),
                            "ttl": curr.ttl,
                            "data": str(getattr(curr, "rdata", ""))
                        })
                        curr = curr.payload if hasattr(curr, "payload") and isinstance(curr.payload, DNSRR) else None

                dns_records.append({
                    "packet_number": idx,
                    "timestamp": datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:12],
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": sport,
                    "dst_port": dport,
                    "protocol": "UDP",
                    "transaction_id_hex": f"0x{dns.id:04x}",
                    "transaction_id_dec": dns.id,
                    "qr": dns.qr,
                    "status": "Response" if dns.qr == 1 else "Query",
                    "rcode": dns.rcode,
                    "rcode_str": DNS_RCODE_NAMES.get(dns.rcode, f"RCODE {dns.rcode}"),
                    "qname": qname,
                    "qtype": qtype,
                    "ancount": dns.ancount,
                    "answers": answers
                })

        return {
            "dns_records": dns_records,
            "total_packets_scanned": len(packets),
            "total_dns_packets": total_dns,
            "query_count": q_count,
            "response_count": r_count,
            "unique_domains_count": len(domains),
            "unique_domains": sorted(list(domains)),
            "client_ips": [],
            "resolver_ips": [],
            "type_counts": {}
        }
    except Exception as exc:
        return {
            "error": f"PCAPNG analysis encountered an issue: {str(exc)}. Tip: Save the capture as standard PCAP in Wireshark via File -> Save As -> Wireshark/tcpdump (...pcap)."
        }


def generate_sample_pcap(filepath: str) -> str:
    """
    Generates a realistic binary PCAP file containing sample DNS queries and responses
    (google.com A, github.com AAAA, wikipedia.org MX, and an NXDOMAIN response).
    Allows immediate testing without requiring Wireshark installation.
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    # Standard PCAP Global Header: Magic (0xa1b2c3d4), Version 2.4, Zone 0, Sigfigs 0, Snaplen 65535, LinkType 1 (Ethernet)
    global_hdr = struct.pack(">IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    def make_eth_ip_udp(src_ip: str, dst_ip: str, sport: int, dport: int, udp_payload: bytes) -> bytes:
        # 14-byte Ethernet header: Dst MAC (6), Src MAC (6), EtherType 0x0800 (2)
        eth = b"\x00\x1a\x2b\x3c\x4d\x5e\x70\x08\x94\x36\x69\x0b\x08\x00"
        # 20-byte IPv4 Header
        total_len = 20 + 8 + len(udp_payload)
        ip_src = socket.inet_aton(src_ip)
        ip_dst = socket.inet_aton(dst_ip)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, 0x4000, 64, 17, 0, ip_src, ip_dst)
        # 8-byte UDP Header
        udp_len = 8 + len(udp_payload)
        udp_hdr = struct.pack("!HHHH", sport, dport, udp_len, 0)
        return eth + ip_hdr + udp_hdr + udp_payload

    def encode_qname(name: str) -> bytes:
        res = b""
        for label in name.split("."):
            res += bytes([len(label)]) + label.encode("ascii")
        return res + b"\x00"

    packets_data = []
    base_ts = 1714000000

    # 1. Query: google.com A (Client -> Resolver)
    dns_q1 = struct.pack("!HHHHHH", 0x1a2b, 0x0100, 1, 0, 0, 0) + encode_qname("google.com") + struct.pack("!HH", 1, 1)
    packets_data.append((base_ts, 120000, make_eth_ip_udp("192.168.1.105", "8.8.8.8", 53210, 53, dns_q1)))

    # 2. Response: google.com A (Resolver -> Client, Ans: 142.250.190.46)
    dns_r1 = struct.pack("!HHHHHH", 0x1a2b, 0x8180, 1, 1, 0, 0) + encode_qname("google.com") + struct.pack("!HH", 1, 1)
    dns_r1 += b"\xc0\x0c" + struct.pack("!HHIH4s", 1, 1, 300, 4, socket.inet_aton("142.250.190.46"))
    packets_data.append((base_ts, 142000, make_eth_ip_udp("8.8.8.8", "192.168.1.105", 53, 53210, dns_r1)))

    # 3. Query: github.com AAAA
    dns_q2 = struct.pack("!HHHHHH", 0x2c3d, 0x0100, 1, 0, 0, 0) + encode_qname("github.com") + struct.pack("!HH", 28, 1)
    packets_data.append((base_ts + 1, 210000, make_eth_ip_udp("192.168.1.105", "1.1.1.1", 53211, 53, dns_q2)))

    # 4. Response: github.com AAAA (Ans: 2606:50c0:8000::153)
    dns_r2 = struct.pack("!HHHHHH", 0x2c3d, 0x8180, 1, 1, 0, 0) + encode_qname("github.com") + struct.pack("!HH", 28, 1)
    dns_r2 += b"\xc0\x0c" + struct.pack("!HHIH16s", 28, 1, 60, 16, socket.inet_pton(socket.AF_INET6, "2606:50c0:8000::153"))
    packets_data.append((base_ts + 1, 235000, make_eth_ip_udp("1.1.1.1", "192.168.1.105", 53, 53211, dns_r2)))

    # 5. Query: non-existent-test-domain-999.org A
    dns_q3 = struct.pack("!HHHHHH", 0x3d4e, 0x0100, 1, 0, 0, 0) + encode_qname("non-existent-test-domain-999.org") + struct.pack("!HH", 1, 1)
    packets_data.append((base_ts + 2, 310000, make_eth_ip_udp("192.168.1.105", "8.8.8.8", 53212, 53, dns_q3)))

    # 6. Response: NXDOMAIN (RCODE = 3)
    dns_r3 = struct.pack("!HHHHHH", 0x3d4e, 0x8183, 1, 0, 0, 0) + encode_qname("non-existent-test-domain-999.org") + struct.pack("!HH", 1, 1)
    packets_data.append((base_ts + 2, 345000, make_eth_ip_udp("8.8.8.8", "192.168.1.105", 53, 53212, dns_r3)))

    with open(filepath, "wb") as f:
        f.write(global_hdr)
        for s, us, pdata in packets_data:
            plen = len(pdata)
            f.write(struct.pack(">IIII", s, us, plen, plen))
            f.write(pdata)

    return filepath
