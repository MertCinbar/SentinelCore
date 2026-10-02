<div align="center">

# 🛡️ SentinelCore
### Otonom Ağ Trafiği İzleme, Paket Analizörü & Saldırı Tespit Sistemi (IDS)
**Cisco Packet Tracer Teorisini Gerçek Hayatta Canlı Savunma Kokpitine Dönüştüren Hibrit Ağ Motoru**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![WebSockets](https://img.shields.io/badge/WebSockets-Real--Time-010101?style=for-the-badge&logo=socketdotio&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API)
[![Network](https://img.shields.io/badge/TCP%2FIP-Raw_Sockets-0284c7?style=for-the-badge)](https://en.wikipedia.org/wiki/Internet_protocol_suite)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

<p align="center">
  <img src="https://img.shields.io/badge/Durum-Canl%C4%B1%20ve%20Aktif-10b981?style=flat-square" alt="Status" />
  <img src="https://img.shields.io/badge/Kapsama-%20IPv4%20|%20TCP%20|%20UDP%20|%20ICMP-blue?style=flat-square" alt="Protocols" />
  <img src="https://img.shields.io/badge/Tehditler-SYN%20Flood%20|%20Port%20Scan%20|%20Xmas%20Scan-red?style=flat-square" alt="Threats" />
</p>

</div>

---

## 📌 Proje Genel Bakış

**SentinelCore**, fiziksel veya sanal ağ arayüzlerini dinleyerek geçen TCP/IP paketlerini bit seviyesinde ayrıştıran, kural ve anomali tabanlı siber saldırı modellerini (SYN Flood, Nmap Port Taramaları, ICMP Sweep, Gizli Xmas/Null Taramaları) milisaniyeler içinde yakalayan ve **WebSockets** üzerinden canlı bir Güvenlik Operasyon Merkezi (SOC) kokpitine aktaran otonom bir **Saldırı Tespit Sistemidir (IDS)**.

Üniversite **Bilgisayar Ağları** dersindeki teorik ağ protokollerini, Cisco Packet Tracer PDU kapsülleme modellerini ve router/switch kurallarını gerçek dünyada çalışan profesyonel bir yazılım mimarisine dönüştürmek amacıyla geliştirilmiştir.

---

## 🏛️ Mimari ve İstek Akışı (Request Lifecycle)

```mermaid
flowchart TD
    subgraph INGESTION["1. Paket Giriş & Yakalama Katmanı"]
        LiveNIC["⚡ Canlı Ağ Kartı (Raw Socket / SIO_RCVALL)"]
        Simulator["🎯 Gerçek Zamanlı Trafik & Tatbikat Motoru"]
        PcapReplay["📂 PCAP / Wireshark Dosya Oynatıcı"]
    end

    subgraph PARSER["2. İkili Protokol Çözümleme (Bitmask Parser)"]
        IP["IPv4 Başlığı (RFC 791) - Version, IHL, TTL, Checksum"]
        TCP["TCP Başlığı (RFC 793) - Seq/Ack, Flags: SYN, ACK, FIN, RST, PSH, URG"]
        UDP["UDP Başlığı (RFC 768) - Portlar ve Boyut"]
        ICMP["ICMP Başlığı (RFC 792) - Echo Request / Reply"]
    end

    subgraph DETECTION["3. Kural & Anomali Tespit Motoru (IDS)"]
        PS["🎯 Nmap Port Taraması (Sliding Window Analizi)"]
        SF["⚡ SYN Flood DoS (Cevapsız SYN Eşik Denetimi)"]
        ST["🎄 Stealth Xmas & Null Tree Taraması"]
        RP["🚨 Kritik / Hassas Port Erişimi (Telnet 23, SMB 445, RDP 3389)"]
    end

    subgraph DISPATCH["4. Gerçek Zamanlı İletim & Görselleştirme"]
        WSHub["WebSocket Hub (Asenkron Yayıncı)"]
        Dashboard["🖥️ Canlı SOC Kokpiti (Dark Radar UI)"]
        PDUModal["🔍 OSI / PDU Katman İnceleme Modalı"]
    end

    LiveNIC --> IP
    Simulator --> IP
    PcapReplay --> IP

    IP --> TCP
    IP --> UDP
    IP --> ICMP

    TCP --> DETECTION
    UDP --> DETECTION
    ICMP --> DETECTION

    DETECTION --> WSHub
    WSHub --> Dashboard
    Dashboard --> PDUModal
```

---

## 🎓 Cisco Packet Tracer & Akademik Kesişim Tablosu

| Ağ Kavramı (Teori) | Cisco Packet Tracer | SentinelCore Uygulaması |
| :--- | :--- | :--- |
| **PDU & Kapsülleme (Encapsulation)** | Simülasyon modunda statik zarf başlıkları (In/Out Layers) | `struct.unpack` ile ağ kartından gelen ham baytların bit bit çözümlenmesi. |
| **ACL (Access Control List)** | Router üzerinde statik paket engelleme kuralları (`access-list`) | Kayan zaman pencereli (Sliding Time Window) dinamik siber anomali analizi. |
| **Switch & MAC Güvenliği** | `show mac-address-table` tablosu | Dinamik ARP ve IP eşleşmelerinin anomali kontrolü. |
| **Taşıma Katmanı Güvenliği** | TCP el sıkışmasının (Handshake) simülasyonu | Tek taraflı SYN flood ve yetkisiz port taramalarının otomatik engelleme alarmları. |

---

## ⚡ Temel Özellikler

- **Çoklu Çalışma Modu:**
  - **Simülasyon & Tatbikat Modu:** Ağ kartı sürücüsü gerekmeden tek tıkla test saldırıları (SYN Flood, Port Scan) üretip görselleştirme.
  - **Canlı Ağ Kartı Modu (Live Raw Socket):** Fiziksel kartı dinleyerek gerçek internet trafiğini analiz etme.
- **İnteraktif OSI / PDU İnceleme Modalı:** Tablodaki herhangi bir pakete tıklandığında Katman 2 (Ethernet), Katman 3 (IPv4), Katman 4 (TCP/UDP) ve Katman 7 (Payload) dökümünü canlı gösterir.
- **Canlı SOC Telemetrisi:** Anlık Paket/Saniye (PPS), Bant Genişliği (Kbps) ve Tehdit Alarmları sayacı.

---

## 🚀 Hızlı Başlangıç

### 1. Kurulum ve Çalıştırma

```bash
# Proje dizinine git
cd C:\Users\pc\Desktop\DERS\SentinelCore

# Sunucuyu başlat
python main.py --port 8050
```

Tarayıcında aç:  
👉 **`http://127.0.0.1:8050`**

### 2. Otomatik Testleri Çalıştırma

```bash
python test_sentinel.py
```

---

## 🛡️ Güvenlik ve Etik Kullanım Bildirimi

Bu yazılım yalnızca eğitim, akademik araştırma ve savunma amaçlı ağ güvenliği analizleri için tasarlanmıştır. Yalnızca izin verilen yerel ağlar veya simülasyon ortamlarında kullanılmalıdır.
