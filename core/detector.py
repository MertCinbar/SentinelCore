import time
import uuid
from typing import Optional, List, Dict
from collections import defaultdict, deque
from .models import PacketRecord, AlertRecord

class ThreatDetector:
    """
    Kural ve Anomali Tabanlı Ağ Saldırı Tespit Motoru (IDS).
    Gerçek zamanlı akan paketlerde port taraması, SYN flood ve anormal protokol modellerini yakalar.
    """

    def __init__(self):
        # Port Scan Takibi: {src_ip: deque([(timestamp, dst_port)])}
        self.port_scan_tracker = defaultdict(lambda: deque(maxlen=200))
        
        # SYN Flood Takibi: {(src_ip, dst_ip): deque([timestamp])}
        self.syn_flood_tracker = defaultdict(lambda: deque(maxlen=300))
        
        # ICMP Flood Takibi: {src_ip: deque([timestamp])}
        self.icmp_flood_tracker = defaultdict(lambda: deque(maxlen=200))
        
        # Son üretilen alarmların tekrarını önlemek için soğuma (cooldown) tablosu
        self.alert_cooldown: Dict[str, float] = {}

    def analyze_packet(self, packet: PacketRecord) -> Optional[AlertRecord]:
        now = time.time()
        
        # 1. KURAL: TCP Bayrak Analizi (Stealth Scan: Null Scan & Xmas Scan)
        if packet.protocol == "TCP" and packet.tcp_flags:
            flags = packet.tcp_flags
            
            # Null Scan: Hiçbir bayrak açık değil
            if not any(flags.values()):
                return self._create_alert(
                    severity="HIGH",
                    alert_type="STEALTH_NULL_SCAN",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    target_port=packet.dst_port,
                    details=f"Gizli Null Scan (Sıfır Bayrak) Tespit Edildi! Hedef Port: {packet.dst_port}"
                )
            
            # Xmas Scan: FIN, PSH, URG aynı anda açık
            if flags.get("FIN") and flags.get("PSH") and flags.get("URG"):
                return self._create_alert(
                    severity="HIGH",
                    alert_type="STEALTH_XMAS_SCAN",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    target_port=packet.dst_port,
                    details=f"Xmas Tree Port Taraması (FIN+PSH+URG) Tespit Edildi! Hedef Port: {packet.dst_port}"
                )

        # 2. KURAL: Port Taraması (Port Scan / Nmap Reconnaissance)
        if packet.protocol == "TCP" and packet.dst_port:
            tracker = self.port_scan_tracker[packet.src_ip]
            tracker.append((now, packet.dst_port))
            
            # Son 4 saniyedeki benzersiz portları filtrele
            recent_ports = {port for ts, port in tracker if now - ts <= 4.0}
            if len(recent_ports) >= 8:
                alert = self._create_alert(
                    severity="CRITICAL",
                    alert_type="PORT_SCAN",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    target_port=packet.dst_port,
                    details=f"Nmap/Port Taraması Tespit Edildi! {packet.src_ip} adresi son 4 saniyede {len(recent_ports)} farklı porta bağlandı.",
                    cooldown_key=f"PORTSCAN_{packet.src_ip}"
                )
                if alert:
                    packet.is_threat = True
                    packet.threat_type = "PORT_SCAN"
                    return alert

        # 3. KURAL: SYN Flood Saldırısı (DoS)
        if packet.protocol == "TCP" and packet.tcp_flags:
            if packet.tcp_flags.get("SYN") and not packet.tcp_flags.get("ACK"):
                key = (packet.src_ip, packet.dst_ip)
                syn_tracker = self.syn_flood_tracker[key]
                syn_tracker.append(now)
                
                # Son 2 saniyedeki cevapsız SYN sayısı
                recent_syns = [ts for ts in syn_tracker if now - ts <= 2.0]
                if len(recent_syns) >= 12:
                    alert = self._create_alert(
                        severity="CRITICAL",
                        alert_type="SYN_FLOOD",
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        target_port=packet.dst_port,
                        details=f"SYN Flood DoS Saldırısı! {packet.src_ip} $\\rightarrow$ {packet.dst_ip}:{packet.dst_port} hattında saniyede {len(recent_syns)} SYN paketi!",
                        cooldown_key=f"SYNFLOOD_{packet.src_ip}_{packet.dst_ip}"
                    )
                    if alert:
                        packet.is_threat = True
                        packet.threat_type = "SYN_FLOOD"
                        return alert

        # 4. KURAL: ICMP Ping Flood / Sweep
        if packet.protocol == "ICMP":
            icmp_tracker = self.icmp_flood_tracker[packet.src_ip]
            icmp_tracker.append(now)
            
            recent_icmps = [ts for ts in icmp_tracker if now - ts <= 2.0]
            if len(recent_icmps) >= 10:
                alert = self._create_alert(
                    severity="HIGH",
                    alert_type="ICMP_FLOOD",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    target_port=None,
                    details=f"ICMP Ping Flood / Süpürme Saldırısı! {packet.src_ip} son 2 saniyede {len(recent_icmps)} ping paketi gönderdi.",
                    cooldown_key=f"ICMP_{packet.src_ip}"
                )
                if alert:
                    packet.is_threat = True
                    packet.threat_type = "ICMP_FLOOD"
                    return alert

        # 5. KURAL: Kritik/Şüpheli Portlara Erişim Denetimi
        risky_ports = {
            23: "Telnet (Şifresiz Güvensiz Terminal)",
            445: "SMB (WannaCry / EternalBlue Hedefi)",
            3389: "RDP (Uzak Masaüstü Brute-Force Hedefi)",
            31337: "Back Orifice (Bilinen Arka Kapı / Truva Atı)"
        }
        if packet.dst_port in risky_ports:
            desc = risky_ports[packet.dst_port]
            alert = self._create_alert(
                severity="MEDIUM",
                alert_type="SUSPICIOUS_PORT",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                target_port=packet.dst_port,
                details=f"Kritik ve Hassas Porta Erişim İsteği: Port {packet.dst_port} ({desc})",
                cooldown_key=f"RISKY_{packet.src_ip}_{packet.dst_port}",
                cooldown_sec=10.0
            )
            if alert:
                packet.is_threat = True
                packet.threat_type = "SUSPICIOUS_PORT"
                return alert

        return None

    def _create_alert(self, severity: str, alert_type: str, src_ip: str, dst_ip: str,
                      target_port: Optional[int], details: str,
                      cooldown_key: Optional[str] = None, cooldown_sec: float = 4.0) -> Optional[AlertRecord]:
        now = time.time()
        if cooldown_key:
            last_alert_time = self.alert_cooldown.get(cooldown_key, 0.0)
            if now - last_alert_time < cooldown_sec:
                return None  # Cooldown süresinde tekrar alarm üretme
            self.alert_cooldown[cooldown_key] = now

        return AlertRecord(
            id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=now,
            severity=severity,
            alert_type=alert_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            target_port=target_port,
            details=details,
            count=1
        )
