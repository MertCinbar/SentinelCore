import uvicorn
import argparse
import sys
import os

# Kök dizini sys.path'e ekle
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

def main():
    parser = argparse.ArgumentParser(description="SentinelCore - Otonom Ağ Trafiği & Saldırı Tespit Sistemi (IDS)")
    parser.add_argument("--host", default="127.0.0.1", help="Sunucu dinleme IP adresi (varsayılan: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8050, help="Sunucu portu (varsayılan: 8050)")
    parser.add_argument("--reload", action="store_true", help="Geliştirici otomatik yeniden yükleme modu")
    args = parser.parse_args()

    print("=================================================================")
    print("🛡️  SENTINELCORE — Otonom Ağ Trafiği & Saldırı Tespit Sistemi")
    print(f"📡  SOC Kontrol Kokpiti: http://{args.host}:{args.port}")
    print("🎯  Ağ Analizörü & Tehdit Tespit Motoru Aktif")
    print("=================================================================")

    uvicorn.run("web.server:app", host=args.host, port=args.port, reload=args.reload)

if __name__ == "__main__":
    main()
