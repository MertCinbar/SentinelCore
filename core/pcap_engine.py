import struct
import socket
import time
from typing import Generator, Tuple, Optional

class PcapEngine:
    """
    Wireshark ve Cisco Packet Tracer uyumlu PCAP (Libpcap) Dosya Okuyucu ve Üreticisi.
    Harici bağımlılık olmadan saf Python (struct) ile binary pcap ayrıştırması yapar.
    """

    PCAP_MAGIC = 0xa1b2c3d4  # Standard Libpcap Magic Number
    LINKTYPE_ETHERNET = 1
    LINKTYPE_RAW = 101

    @staticmethod
    def read_packets(filepath: str) -> Generator[Tuple[float, bytes], None, None]:
        """
        Bir .pcap dosyasındaki paketleri (timestamp, raw_data) olarak sırayla okur.
        """
        with open(filepath, 'rb') as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return

            magic = struct.unpack('!I', global_header[:4])[0]
            # Big-endian veya Little-endian kontrolü
            is_big_endian = (magic == PcapEngine.PCAP_MAGIC)
            endian_fmt = '!' if is_big_endian else '<'

            link_type = struct.unpack(f'{endian_fmt}I', global_header[20:24])[0]

            while True:
                pkt_header = f.read(16)
                if len(pkt_header) < 16:
                    break

                ts_sec, ts_usec, cap_len, orig_len = struct.unpack(f'{endian_fmt}IIII', pkt_header)
                pkt_data = f.read(cap_len)
                if len(pkt_data) < cap_len:
                    break

                ts = ts_sec + (ts_usec / 1_000_000.0)

                # Eğer Ethernet başlığı varsa (14 byte), IP paketine ulaşmak için sıyır
                ip_data = pkt_data
                if link_type == PcapEngine.LINKTYPE_ETHERNET and len(pkt_data) >= 14:
                    ether_type = struct.unpack('!H', pkt_data[12:14])[0]
                    if ether_type == 0x0800:  # IPv4
                        ip_data = pkt_data[14:]

                yield (ts, ip_data)

    @staticmethod
    def create_sample_pcap(filepath: str):
        """
        Doğrulanmış test ve tatbikat için örnek bir sample_attack.pcap dosyası oluşturur.
        İçinde normal HTTP akışı, Nmap Port Taraması ve SYN Flood saldırısı bulunur.
        """
        with open(filepath, 'wb') as f:
            # 1. Global Header (24 byte, Ethernet link type)
            global_header = struct.pack(
                '!IHHiIII',
                PcapEngine.PCAP_MAGIC,
                2, 4, 0, 0, 65535,
                PcapEngine.LINKTYPE_ETHERNET
            )
            f.write(global_header)

            now = int(time.time())

            # Sahte Ethernet Başlığı (14 byte: Dst MAC, Src MAC, Type 0x0800)
            eth_hdr = b'\x00\x1a\x2b\x3c\x4d\x5e\x00\x50\x56\xc0\x00\x08\x08\x00'

            def write_ip_pkt(src_ip_str, dst_ip_str, protocol_num, payload_bytes, offset_sec=0):
                src_b = socket.inet_aton(src_ip_str)
                dst_b = socket.inet_aton(dst_ip_str)
                total_len = 20 + len(payload_bytes)
                ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, 1234, 0, 64, protocol_num, 0, src_b, dst_b)
                full_frame = eth_hdr + ip_hdr + payload_bytes
                
                # Packet Header (16 byte)
                f.write(struct.pack('!IIII', now + offset_sec, 0, len(full_frame), len(full_frame)))
                f.write(full_frame)

            # Normal HTTPS İsteği (Port 443)
            tcp_payload = struct.pack('!HHIIBBHHH', 51234, 443, 100, 200, 0x50, 0x18, 8192, 0, 0) + b'TLS_CLIENT_HELLO'
            write_ip_pkt("192.168.1.105", "142.250.187.174", 6, tcp_payload, 0)

            # Nmap Port Taraması (Port 21, 22, 23, 80, 443, 445, 3389, 8080)
            attacker = "10.0.0.99"
            victim = "192.168.1.100"
            for idx, port in enumerate([21, 22, 23, 80, 443, 445, 1433, 3389, 8080]):
                tcp_scan = struct.pack('!HHIIBBHHH', 40000 + idx, port, 1000 + idx, 0, 0x50, 0x02, 1024, 0, 0)
                write_ip_pkt(attacker, victim, 6, tcp_scan, 1)

            # SYN Flood DoS
            for idx in range(15):
                spoofed = f"172.16.1.{idx + 1}"
                tcp_syn = struct.pack('!HHIIBBHHH', 30000 + idx, 80, 5000 + idx, 0, 0x50, 0x02, 1024, 0, 0)
                write_ip_pkt(spoofed, victim, 6, tcp_syn, 2)
