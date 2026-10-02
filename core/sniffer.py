import socket
import struct
import threading
import time
import random
from typing import Callable, Optional
from .models import PacketRecord, AlertRecord, TrafficMetrics
from .parser import PacketParser
from .detector import ThreatDetector
from .geoip import GeoIPResolver
from .pcap_engine import PcapEngine

class NetworkSniffer:
    """
    3 Modlu Hibrit Paket Yakalama ve Trafik Yönetim Motoru:
    1. LIVE: Fiziksel Ağ Kartı Raw Socket Dinleyicisi
    2. PCAP: Wireshark / Cisco Packet Tracer Yakalama Dosyalarını Oynatma
    3. SIMULATION: Gerçek Zamanlı Trafik & Siber Saldırı Tatbikat Motoru
    """

    def __init__(self, on_packet_callback: Callable[[PacketRecord, Optional[AlertRecord]], None]):
        self.on_packet = on_packet_callback
        self.detector = ThreatDetector()
        
        self.is_running = False
        self.mode = "SIMULATION"  # LIVE, PCAP, SIMULATION
        self.thread: Optional[threading.Thread] = None
        
        self.packet_counter = 0
        self.metrics = TrafficMetrics()
        self.start_time = time.time()
        self.last_metric_calc = time.time()
        self.packets_in_window = 0
        self.bytes_in_window = 0

    def start(self, mode: str = "SIMULATION", pcap_path: Optional[str] = None):
        if self.is_running:
            self.stop()
            
        self.is_running = True
        self.mode = mode
        self.metrics.active_mode = mode
        
        if mode == "LIVE":
            self.thread = threading.Thread(target=self._run_live_sniffer, daemon=True)
        elif mode == "PCAP" and pcap_path:
            self.thread = threading.Thread(target=self._run_pcap_replay, args=(pcap_path,), daemon=True)
        else:
            self.thread = threading.Thread(target=self._run_simulation_generator, daemon=True)
            
        self.thread.start()

    def stop(self):
        self.is_running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)

    def trigger_attack(self, attack_type: str, target_ip: str = "192.168.1.100", target_port: int = 80):
        """
        Kullanıcının panelden tek tıkla canlı saldırı tatbikatı başlatmasını sağlar.
        """
        threading.Thread(target=self._execute_attack, args=(attack_type, target_ip, target_port), daemon=True).start()

    def _execute_attack(self, attack_type: str, target_ip: str, target_port: int):
        attacker_ip = f"10.0.0.{random.randint(15, 250)}"
        
        if attack_type == "PORT_SCAN":
            # Nmap Hızlı Port Taraması (15 farklı port)
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
            for p in ports:
                if not self.is_running:
                    break
                self._dispatch_synthetic_packet(
                    protocol="TCP",
                    src_ip=attacker_ip,
                    dst_ip=target_ip,
                    src_port=random.randint(40000, 65000),
                    dst_port=p,
                    flags={"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
                    summary=f"TCP Port Taraması İsteği: {attacker_ip} -> {target_ip}:{p} [SYN]"
                )
                time.sleep(0.08)

        elif attack_type == "SYN_FLOOD":
            # SYN Flood DoS (Cevapsız 25 hızlı SYN)
            for _ in range(25):
                if not self.is_running:
                    break
                spoofed_src = f"172.16.{random.randint(1, 10)}.{random.randint(1, 254)}"
                self._dispatch_synthetic_packet(
                    protocol="TCP",
                    src_ip=spoofed_src,
                    dst_ip=target_ip,
                    src_port=random.randint(30000, 65000),
                    dst_port=target_port,
                    flags={"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
                    summary=f"SYN Flood DoS Paketi: {spoofed_src} -> {target_ip}:{target_port} [SYN]"
                )
                time.sleep(0.04)

        elif attack_type == "ICMP_FLOOD":
            # ICMP Ping of Death / Sweep
            for i in range(16):
                if not self.is_running:
                    break
                self._dispatch_synthetic_packet(
                    protocol="ICMP",
                    src_ip=attacker_ip,
                    dst_ip=f"192.168.1.{100 + (i % 5)}",
                    src_port=None,
                    dst_port=None,
                    length=random.randint(512, 1480),
                    summary=f"ICMP Echo Sweep İsteği: {attacker_ip} -> 192.168.1.{100 + (i % 5)} [Ping]"
                )
                time.sleep(0.06)

        elif attack_type == "XMAS_SCAN":
            # Xmas Tree Stealth Scan (FIN + PSH + URG)
            for p in [80, 443, 22, 3389]:
                self._dispatch_synthetic_packet(
                    protocol="TCP",
                    src_ip=attacker_ip,
                    dst_ip=target_ip,
                    src_port=random.randint(45000, 65000),
                    dst_port=p,
                    flags={"SYN": False, "ACK": False, "FIN": True, "RST": False, "PSH": True, "URG": True},
                    summary=f"Xmas Tree Gizli Tarama: {attacker_ip} -> {target_ip}:{p} [FIN,PSH,URG]"
                )
                time.sleep(0.1)

    def _run_live_sniffer(self):
        """
        Windows / Linux Canlı Raw Socket Dinleyicisi
        """
        try:
            # Yerel IP tespit et
            host_name = socket.gethostname()
            local_ip = socket.gethostbyname(host_name)
            
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            raw_sock.bind((local_ip, 0))
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Windows Promiscuous Mode (SIO_RCVALL)
            try:
                raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except Exception:
                pass  # Yönetici yetkisi yoksa normal devam et
                
            while self.is_running:
                data, _ = raw_sock.recvfrom(65535)
                self._process_raw_ip_packet(data)
                
        except Exception as e:
            # Raw socket başlatılamazsa (yetki sorunu) otomatik simülasyon moduna dön
            print(f"[SentinelCore Sniffer] Raw socket başlatılamadı ({e}), Simülasyon Moduna geçiliyor.")
            self.mode = "SIMULATION"
            self.metrics.active_mode = "SIMULATION"
            self._run_simulation_generator()

    def _process_raw_ip_packet(self, data: bytes):
        ip_info = PacketParser.parse_ipv4(data)
        if not ip_info:
            return
            
        proto = ip_info["protocol"]
        payload = ip_info["payload"]
        src_port, dst_port, tcp_flags = None, None, None
        summary = f"{proto} {ip_info['src_ip']} -> {ip_info['dst_ip']}"
        
        if proto == "TCP":
            tcp_info = PacketParser.parse_tcp(payload)
            if tcp_info:
                src_port = tcp_info["src_port"]
                dst_port = tcp_info["dst_port"]
                tcp_flags = tcp_info["flags"]
                summary = f"TCP {ip_info['src_ip']}:{src_port} -> {ip_info['dst_ip']}:{dst_port} [{tcp_info['flag_summary']}]"
        elif proto == "UDP":
            udp_info = PacketParser.parse_udp(payload)
            if udp_info:
                src_port = udp_info["src_port"]
                dst_port = udp_info["dst_port"]
                summary = f"UDP {ip_info['src_ip']}:{src_port} -> {ip_info['dst_ip']}:{dst_port} (Len: {udp_info['length']})"
        elif proto == "ICMP":
            icmp_info = PacketParser.parse_icmp(payload)
            if icmp_info:
                summary = f"ICMP {ip_info['src_ip']} -> {ip_info['dst_ip']} [{icmp_info['type_str']}]"

        src_geo = GeoIPResolver.resolve(ip_info["src_ip"])
        dst_geo = GeoIPResolver.resolve(ip_info["dst_ip"])

        self.packet_counter += 1
        pkt = PacketRecord(
            id=self.packet_counter,
            timestamp=time.time(),
            protocol=proto,
            src_ip=ip_info["src_ip"],
            dst_ip=ip_info["dst_ip"],
            src_port=src_port,
            dst_port=dst_port,
            length=len(data),
            ttl=ip_info["ttl"],
            tcp_flags=tcp_flags,
            summary=summary,
            src_country=src_geo["country"],
            src_flag=src_geo["flag"],
            dst_country=dst_geo["country"],
            dst_flag=dst_geo["flag"]
        )
        
        # Tehdit denetimi
        alert = self.detector.analyze_packet(pkt)
        self._update_metrics(pkt, alert)
        self.on_packet(pkt, alert)

    def _run_pcap_replay(self, pcap_path: str):
        """
        Wireshark / Cisco Packet Tracer PCAP dosyasını okuyup canlı gibi oynatır.
        """
        try:
            for ts, ip_data in PcapEngine.read_packets(pcap_path):
                if not self.is_running:
                    break
                self._process_raw_ip_packet(ip_data)
                time.sleep(0.12)
        except Exception as e:
            print(f"[SentinelCore Sniffer] PCAP oynatma hatası: {e}")

    def _run_simulation_generator(self):
        """
        Gerçekçi İnternet ve Yerel Ağ Trafiği Üreticisi (DNS, HTTPS, API, Ping, NTP)
        """
        common_destinations = [
            ("142.250.187.174", 443, "HTTPS Google Cloud Services"),
            ("104.244.42.1", 443, "HTTPS CDN Edge Gateway"),
            ("8.8.8.8", 53, "DNS Query (A / AAAA)"),
            ("1.1.1.1", 53, "DNS Query (DoT / UDP)"),
            ("192.168.1.1", 80, "HTTP Yerel Router Gateway"),
            ("192.168.1.25", 8080, "HTTP Kurumsal API Backend"),
            ("216.58.214.14", 443, "TLS YouTube Streaming Chunk")
        ]
        
        while self.is_running:
            # Rastgele normal bir paket üret
            target_ip, target_port, desc = random.choice(common_destinations)
            my_ip = "192.168.1.105"
            proto = "TCP" if target_port in [443, 80, 8080] else "UDP"
            
            flags = None
            if proto == "TCP":
                flags = {"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": random.choice([True, False]), "URG": False}
                
            self._dispatch_synthetic_packet(
                protocol=proto,
                src_ip=my_ip,
                dst_ip=target_ip,
                src_port=random.randint(49152, 65535),
                dst_port=target_port,
                flags=flags,
                summary=f"{proto} {my_ip} -> {target_ip}:{target_port} ({desc})"
            )
            
            # Rastgele doğal bekleme süresi (10ms - 250ms arası canlı akış hissi)
            time.sleep(random.uniform(0.08, 0.35))

    def _dispatch_synthetic_packet(self, protocol: str, src_ip: str, dst_ip: str,
                                   src_port: Optional[int] = None, dst_port: Optional[int] = None,
                                   flags: Optional[dict] = None, length: Optional[int] = None,
                                   summary: str = ""):
        self.packet_counter += 1
        pkt_len = length or random.randint(64, 1420)
        src_geo = GeoIPResolver.resolve(src_ip)
        dst_geo = GeoIPResolver.resolve(dst_ip)
        
        pkt = PacketRecord(
            id=self.packet_counter,
            timestamp=time.time(),
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            length=pkt_len,
            ttl=random.randint(52, 128),
            tcp_flags=flags,
            summary=summary,
            src_country=src_geo["country"],
            src_flag=src_geo["flag"],
            dst_country=dst_geo["country"],
            dst_flag=dst_geo["flag"]
        )
        
        alert = self.detector.analyze_packet(pkt)
        self._update_metrics(pkt, alert)
        self.on_packet(pkt, alert)

    def _update_metrics(self, pkt: PacketRecord, alert: Optional[AlertRecord]):
        self.metrics.total_packets += 1
        self.metrics.total_bytes += pkt.length
        
        if pkt.protocol == "TCP":
            self.metrics.tcp_count += 1
        elif pkt.protocol == "UDP":
            self.metrics.udp_count += 1
        elif pkt.protocol == "ICMP":
            self.metrics.icmp_count += 1
        else:
            self.metrics.other_count += 1
            
        if alert or pkt.is_threat:
            self.metrics.threat_count += 1
            
        self.packets_in_window += 1
        self.bytes_in_window += pkt.length
        
        now = time.time()
        elapsed = now - self.last_metric_calc
        if elapsed >= 1.0:
            self.metrics.packets_per_second = round(self.packets_in_window / elapsed, 1)
            self.metrics.bandwidth_kbps = round((self.bytes_in_window * 8) / (elapsed * 1024), 1)
            self.packets_in_window = 0
            self.bytes_in_window = 0
            self.last_metric_calc = now
