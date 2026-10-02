import struct
import socket
import unittest
import time
from core.parser import PacketParser
from core.detector import ThreatDetector
from core.models import PacketRecord
from fastapi.testclient import TestClient
from web.server import app

class TestSentinelCore(unittest.TestCase):

    def test_ipv4_parsing(self):
        # 20-byte sahte IPv4 paketi oluştur (Version=4, IHL=5, Protocol=6 (TCP), Src=192.168.1.10, Dst=10.0.0.1)
        src_bytes = socket.inet_aton("192.168.1.10")
        dst_bytes = socket.inet_aton("10.0.0.1")
        ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 12345, 0, 64, 6, 0, src_bytes, dst_bytes)
        
        parsed = PacketParser.parse_ipv4(ip_header)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["version"], 4)
        self.assertEqual(parsed["protocol"], "TCP")
        self.assertEqual(parsed["src_ip"], "192.168.1.10")
        self.assertEqual(parsed["dst_ip"], "10.0.0.1")

    def test_tcp_flags_parsing(self):
        # 20-byte sahte TCP paketi (SrcPort=4444, DstPort=80, SYN+ACK bayrağı = 0x12)
        tcp_header = struct.pack('!HHIIBBHHH', 4444, 80, 1000, 2000, 0x50, 0x12, 8192, 0, 0)
        parsed = PacketParser.parse_tcp(tcp_header)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["src_port"], 4444)
        self.assertEqual(parsed["dst_port"], 80)
        self.assertTrue(parsed["flags"]["SYN"])
        self.assertTrue(parsed["flags"]["ACK"])
        self.assertFalse(parsed["flags"]["FIN"])

    def test_port_scan_detection(self):
        detector = ThreatDetector()
        attacker = "192.168.1.99"
        victim = "192.168.1.1"
        
        alert_triggered = False
        # 10 farklı porta hızlı istek gönder
        for p in range(20, 31):
            pkt = PacketRecord(
                id=p,
                protocol="TCP",
                src_ip=attacker,
                dst_ip=victim,
                dst_port=p,
                length=64,
                summary="Scan packet"
            )
            alert = detector.analyze_packet(pkt)
            if alert and alert.alert_type == "PORT_SCAN":
                alert_triggered = True
                break
                
        self.assertTrue(alert_triggered, "Port taraması tespit edilmeliydi!")

    def test_syn_flood_detection(self):
        detector = ThreatDetector()
        attacker = "172.16.0.5"
        victim = "192.168.1.50"
        
        alert_triggered = False
        for i in range(15):
            pkt = PacketRecord(
                id=i,
                protocol="TCP",
                src_ip=attacker,
                dst_ip=victim,
                dst_port=80,
                length=64,
                tcp_flags={"SYN": True, "ACK": False},
                summary="SYN Flood packet"
            )
            alert = detector.analyze_packet(pkt)
            if alert and alert.alert_type == "SYN_FLOOD":
                alert_triggered = True
                break
                
        self.assertTrue(alert_triggered, "SYN Flood tespit edilmeliydi!")

    def test_api_endpoints(self):
        client = TestClient(app)
        
        # State kontrolü
        res = client.get("/api/state")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("metrics", data)
        self.assertIn("mode", data)
        
        # Saldırı tetikleme
        res_attack = client.post("/api/trigger-attack", json={"attack_type": "PORT_SCAN", "target_ip": "192.168.1.1", "target_port": 80})
        self.assertEqual(res_attack.status_code, 200)
        self.assertEqual(res_attack.json()["status"], "success")

        # PCAP Oynatma
        res_pcap = client.post("/api/replay-sample-pcap")
        self.assertEqual(res_pcap.status_code, 200)
        self.assertEqual(res_pcap.json()["status"], "success")

        # CSV Rapor Dışa Aktarma
        res_csv = client.get("/api/export-csv")
        self.assertEqual(res_csv.status_code, 200)
        self.assertIn("Paket_No", res_csv.text)

if __name__ == "__main__":
    unittest.main()
