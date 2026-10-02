import time
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class PacketRecord(BaseModel):
    id: int
    timestamp: float = Field(default_factory=time.time)
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: int
    ttl: Optional[int] = None
    tcp_flags: Optional[Dict[str, bool]] = None
    summary: str
    src_country: Optional[str] = "Yerel"
    src_flag: Optional[str] = "🌐"
    dst_country: Optional[str] = "İnternet"
    dst_flag: Optional[str] = "🌐"
    is_threat: bool = False
    threat_type: Optional[str] = None

class AlertRecord(BaseModel):
    id: str
    timestamp: float = Field(default_factory=time.time)
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    alert_type: str  # PORT_SCAN, SYN_FLOOD, ARP_SPOOF, ICMP_SWEEP, SUSPICIOUS_PORT
    src_ip: str
    dst_ip: str
    target_port: Optional[int] = None
    details: str
    count: int = 1

class TrafficMetrics(BaseModel):
    total_packets: int = 0
    total_bytes: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    other_count: int = 0
    threat_count: int = 0
    packets_per_second: float = 0.0
    bandwidth_kbps: float = 0.0
    active_mode: str = "SIMULATION"  # LIVE, PCAP, SIMULATION
