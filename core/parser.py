import struct
import socket
from typing import Dict, Any, Optional, Tuple

class PacketParser:
    """
    TCP/IP protokol başlıklarını (IPv4, TCP, UDP, ICMP) bit seviyesinde ayrıştıran sınıf.
    Cisco Packet Tracer'daki PDU (Protocol Data Unit) başlıklarının doğrudan Python karşılığıdır.
    """

    @staticmethod
    def parse_ipv4(data: bytes) -> Optional[Dict[str, Any]]:
        """
        IPv4 Başlığını (RFC 791) ayrıştırır (Minimum 20 byte).
        """
        if len(data) < 20:
            return None
        
        # İlk 20 byte'ı aç (unpack)
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4  # Header length in bytes
        
        if version != 4 or len(data) < ihl:
            return None
            
        tos = ip_header[1]
        total_length = ip_header[2]
        identification = ip_header[3]
        flags_offset = ip_header[4]
        ttl = ip_header[5]
        protocol_num = ip_header[6]
        checksum = ip_header[7]
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])
        
        protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
        protocol = protocol_names.get(protocol_num, f"PROTO_{protocol_num}")
        
        payload = data[ihl:]
        
        return {
            "version": version,
            "ihl": ihl,
            "total_length": total_length,
            "ttl": ttl,
            "protocol": protocol,
            "protocol_num": protocol_num,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "payload": payload
        }

    @staticmethod
    def parse_tcp(data: bytes) -> Optional[Dict[str, Any]]:
        """
        TCP Başlığını (RFC 793) ve bayraklarını (SYN, ACK, FIN, RST, PSH, URG) ayrıştırır.
        """
        if len(data) < 20:
            return None
            
        tcp_header = struct.unpack('!HHIIBBHHH', data[:20])
        src_port = tcp_header[0]
        dst_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        offset_reserved = tcp_header[4]
        data_offset = (offset_reserved >> 4) * 4
        flags_byte = tcp_header[5]
        window_size = tcp_header[6]
        
        # Bayrak maskelemesi (Flag Bitmasks)
        flags = {
            "FIN": bool(flags_byte & 0x01),
            "SYN": bool(flags_byte & 0x02),
            "RST": bool(flags_byte & 0x04),
            "PSH": bool(flags_byte & 0x08),
            "ACK": bool(flags_byte & 0x10),
            "URG": bool(flags_byte & 0x20)
        }
        
        active_flags = [k for k, v in flags.items() if v]
        flag_summary = ",".join(active_flags) if active_flags else "NONE"
        
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq_num": seq_num,
            "ack_num": ack_num,
            "data_offset": data_offset,
            "flags": flags,
            "flag_summary": flag_summary,
            "window_size": window_size,
            "payload": data[data_offset:] if len(data) >= data_offset else b""
        }

    @staticmethod
    def parse_udp(data: bytes) -> Optional[Dict[str, Any]]:
        """
        UDP Başlığını (RFC 768) ayrıştırır (8 byte).
        """
        if len(data) < 8:
            return None
            
        udp_header = struct.unpack('!HHHH', data[:8])
        src_port = udp_header[0]
        dst_port = udp_header[1]
        length = udp_header[2]
        checksum = udp_header[3]
        
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "payload": data[8:]
        }

    @staticmethod
    def parse_icmp(data: bytes) -> Optional[Dict[str, Any]]:
        """
        ICMP Başlığını (RFC 792) ayrıştırır (Ping Echo Request/Reply).
        """
        if len(data) < 4:
            return None
            
        icmp_header = struct.unpack('!BBH', data[:4])
        icmp_type = icmp_header[0]
        code = icmp_header[1]
        checksum = icmp_header[2]
        
        type_names = {
            0: "Echo Reply (Ping Yanıtı)",
            3: "Destination Unreachable (Hedefe Ulaşılamadı)",
            8: "Echo Request (Ping İsteği)",
            11: "Time Exceeded (TTL Süresi Doldu)"
        }
        type_str = type_names.get(icmp_type, f"Type {icmp_type}")
        
        return {
            "type": icmp_type,
            "code": code,
            "type_str": type_str,
            "payload": data[4:]
        }
