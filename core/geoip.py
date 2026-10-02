from typing import Dict, Any

class GeoIPResolver:
    """
    Yerel ve Harici IP Adreslerini Hızlıca Ayrıştıran ve Bayrak/Ülke Bilgisi Ekleyen Modül.
    Harici ağır kütüphaneler olmadan hızlı bir sınıflandırma yapar.
    """

    @staticmethod
    def resolve(ip: str) -> Dict[str, Any]:
        if not ip:
            return {"country": "Bilinmeyen", "flag": "🌐", "is_local": False}

        # 1. Localhost
        if ip.startswith("127.") or ip == "::1":
            return {"country": "Yerel Makine (Localhost)", "flag": "💻", "is_local": True}

        # 2. Yerel Ağ (Private RFC 1918)
        if ip.startswith("192.168.") or ip.startswith("10."):
            return {"country": "Yerel Ağ (LAN)", "flag": "🏠", "is_local": True}
            
        if ip.startswith("172."):
            try:
                second_octet = int(ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    return {"country": "Yerel Kurumsal Ağ (LAN)", "flag": "🏢", "is_local": True}
            except Exception:
                pass

        # 3. Bilinen Global Servisler ve Ülkeler
        if ip in ["8.8.8.8", "8.8.4.4"] or ip.startswith("142.250.") or ip.startswith("172.217."):
            return {"country": "Amerika Birleşik Devletleri (Google)", "flag": "🇺🇸", "is_local": False}

        if ip in ["1.1.1.1", "1.0.0.1"] or ip.startswith("104.16.") or ip.startswith("104.244."):
            return {"country": "Amerika Birleşik Devletleri (Cloudflare)", "flag": "🇺🇸", "is_local": False}

        if ip.startswith("212.") or ip.startswith("195.175.") or ip.startswith("78.188."):
            return {"country": "Türkiye (Ulusal Ağ / TTNet)", "flag": "🇹🇷", "is_local": False}

        if ip.startswith("185.") or ip.startswith("194."):
            return {"country": "Almanya / Hollanda (AB Omurgası)", "flag": "🇩🇪", "is_local": False}

        if ip.startswith("188.") or ip.startswith("95."):
            return {"country": "Doğu Avrupa / Avrasya", "flag": "🇪🇺", "is_local": False}

        return {"country": "Genel İnternet (Global WAN)", "flag": "🌐", "is_local": False}
