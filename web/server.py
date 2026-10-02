import asyncio
import json
import time
from typing import List, Set, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from core.models import PacketRecord, AlertRecord, TrafficMetrics
from core.sniffer import NetworkSniffer

app = FastAPI(title="SentinelCore - Ağ Trafiği & Saldırı Tespit Sistemi (IDS)")

# Son 150 paketi ve son 50 alarmı bellekte tut
recent_packets: List[dict] = []
recent_alerts: List[dict] = []
active_connections: Set[WebSocket] = set()

# Asenkron olay döngüsü referansı
loop: asyncio.AbstractEventLoop = None

def packet_callback(pkt: PacketRecord, alert: Optional[AlertRecord]):
    pkt_dict = pkt.model_dump()
    recent_packets.append(pkt_dict)
    if len(recent_packets) > 200:
        recent_packets.pop(0)
        
    alert_dict = None
    if alert:
        alert_dict = alert.model_dump()
        recent_alerts.append(alert_dict)
        if len(recent_alerts) > 100:
            recent_alerts.pop(0)
            
    # Aktif WebSocket istemcilerine yay (broadcast)
    if active_connections and loop and loop.is_running():
        msg = {
            "type": "NEW_PACKET",
            "packet": pkt_dict,
            "alert": alert_dict,
            "metrics": sniffer.metrics.model_dump()
        }
        asyncio.run_coroutine_threadsafe(broadcast_message(msg), loop)

sniffer = NetworkSniffer(on_packet_callback=packet_callback)

async def broadcast_message(message: dict):
    dead_connections = set()
    text = json.dumps(message)
    for conn in active_connections:
        try:
            await conn.send_text(text)
        except Exception:
            dead_connections.add(conn)
    for dead in dead_connections:
        active_connections.remove(dead)

@app.on_event("startup")
async def startup_event():
    global loop
    loop = asyncio.get_event_loop()
    # Varsayılan olarak Simülasyon modunda başlat
    sniffer.start(mode="SIMULATION")

@app.on_event("shutdown")
def shutdown_event():
    sniffer.stop()

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("web/templates/index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/api/state")
async def get_state():
    return {
        "metrics": sniffer.metrics.model_dump(),
        "recent_packets": recent_packets[-40:],
        "recent_alerts": recent_alerts[-20:],
        "mode": sniffer.mode
    }

class AttackRequest(BaseModel):
    attack_type: str  # PORT_SCAN, SYN_FLOOD, ICMP_FLOOD, XMAS_SCAN
    target_ip: str = "192.168.1.100"
    target_port: int = 80

@app.post("/api/trigger-attack")
async def trigger_attack(req: AttackRequest):
    sniffer.trigger_attack(req.attack_type, req.target_ip, req.target_port)
    return {"status": "success", "message": f"{req.attack_type} tatbikat saldırısı başlatıldı!"}

class ModeRequest(BaseModel):
    mode: str  # SIMULATION, LIVE

@app.post("/api/switch-mode")
async def switch_mode(req: ModeRequest):
    sniffer.start(mode=req.mode)
    return {"status": "success", "current_mode": req.mode}

@app.post("/api/replay-sample-pcap")
async def replay_sample_pcap():
    import os
    pcap_file = os.path.join("pcaps", "sample_attack.pcap")
    if not os.path.exists(pcap_file):
        from core.pcap_engine import PcapEngine
        PcapEngine.create_sample_pcap(pcap_file)
    sniffer.start(mode="PCAP", pcap_path=pcap_file)
    return {"status": "success", "message": "sample_attack.pcap dosyası oynatılıyor..."}

@app.get("/api/export-csv")
async def export_csv():
    import io, csv
    from fastapi.responses import Response
    from datetime import datetime

    output = io.StringIO()
    # Excel Türkçe karakter uyumu için UTF-8 BOM ekle
    output.write('\ufeff')
    writer = csv.writer(output, delimiter=';')
    
    # Başlık satırı
    writer.writerow([
        "Paket_No", "Zaman", "Protokol", "Kaynak_IP", "Kaynak_Ulke", "Kaynak_Port",
        "Hedef_IP", "Hedef_Ulke", "Hedef_Port", "Boyut_Byte", "Tehdit_Mi", "Tehdit_Tipi", "Ozet"
    ])
    
    for p in recent_packets:
        ts_str = datetime.fromtimestamp(p.get("timestamp", time.time())).strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([
            p.get("id"),
            ts_str,
            p.get("protocol"),
            p.get("src_ip"),
            p.get("src_country", "Yerel"),
            p.get("src_port", ""),
            p.get("dst_ip"),
            p.get("dst_country", "Genel"),
            p.get("dst_port", ""),
            p.get("length"),
            "EVET" if p.get("is_threat") else "HAYIR",
            p.get("threat_type") or "-",
            p.get("summary", "")
        ])
        
    csv_content = output.getvalue()
    return Response(
        content=csv_content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=sentinelcore_audit_{int(time.time())}.csv"}
    )

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    
    # İlk bağlantıda mevcut metrikleri ve son paketleri gönder
    initial_payload = {
        "type": "INITIAL_STATE",
        "metrics": sniffer.metrics.model_dump(),
        "recent_packets": recent_packets[-30:],
        "recent_alerts": recent_alerts[-15:],
        "mode": sniffer.mode
    }
    await websocket.send_text(json.dumps(initial_payload))
    
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)
    except Exception:
        if websocket in active_connections:
            active_connections.remove(websocket)
