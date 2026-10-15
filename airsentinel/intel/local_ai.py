"""Local AI & Heuristic Intelligence Debrief Engine (Apple Silicon M4 Optimized)."""
import json
import logging
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional
from airsentinel.config import settings

logger = logging.getLogger("airsentinel.ai")


class LocalAiAnalyzer:
    def __init__(self, ollama_url: Optional[str] = None, model: Optional[str] = None):
        self.ollama_url = ollama_url or settings.ollama_url
        self.model = model or settings.ollama_model

    def is_ollama_available(self) -> bool:
        """Checks if local Ollama instance is reachable."""
        try:
            req = urllib.request.Request(f"{self.ollama_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def generate_ai_debrief(self, context_summary: Dict[str, Any]) -> str:
        """Generates a situation debrief in clear Turkish using local Ollama or analytical engine."""
        if self.is_ollama_available():
            try:
                return self._call_ollama(context_summary)
            except Exception as e:
                logger.warning(f"Ollama call failed ({e}), falling back to analytical intelligence engine.")

        return self._generate_heuristic_debrief(context_summary)

    def _call_ollama(self, context_summary: Dict[str, Any]) -> str:
        prompt = f"""Sen AirSentinel Kablosuz Güvenlik Analistisin. Aşağıdaki çevresel RF (Bluetooth ve Wi-Fi) özetini incele ve kullanıcıya çok anlaşılır, net bir TÜRKÇE durum raporu (AIRSENTINEL DURUM RAPORU) hazırla:
{json.dumps(context_summary, indent=2)}

Rapor şu 5 başlığı içermeli:
1. Genel Güvenlik Durumu (Güvenli / Dikkat / Kritik Tehdit)
2. Hava Sahası ve Drone Analizi
3. Gizli Takip Cihazı (AirTag / SmartTag) Kontrolü
4. Siber Saldırı ve Sinyal Boğma (Flipper Zero / Spam) Kontrolü
5. Kullanıcı İçin Somut Öneriler"""

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.ollama_url}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30.0) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            text = result.get("response", "Analiz tamamlandı.")
            if "AIRSENTINEL" not in text.upper():
                text = "# AIRSENTINEL — YAPAY ZEKA DURUM RAPORU\n\n" + text
            return text

    def _generate_heuristic_debrief(self, summary: Dict[str, Any]) -> str:
        """Clear, human-friendly Turkish analytical debrief when local LLM is offline."""
        drones = summary.get("drones", [])
        trackers = summary.get("trackers", [])
        alerts = summary.get("alerts", [])
        total_devices = summary.get("total_devices", 0)

        threat_level = "🟢 YEŞİL — GÜVENLİ (NORMAL ORTAM)"
        threat_color = "normal"
        if len(alerts) > 0 or len(drones) > 0:
            threat_level = "🟡 SARI — DİKKAT (İNCELEME GEREKTİREN SİNYAL VAR)"
            threat_color = "elevated"
        critical_alerts = [a for a in alerts if a.get("level") in ("HIGH", "CRITICAL")]
        if len(critical_alerts) >= 2 or any(a.get("category") == "STALKING_CO_TRAVEL" for a in alerts):
            threat_level = "🔴 KIRMIZI — KRİTİK TEHDİT (AKTİF SALDIRI VEYA TAKİP ŞÜPHESİ)"
            threat_color = "critical"

        report_lines = [
            "# AIRSENTINEL — ÇEVRESEL GÜVENLİK VE SİNYAL ÖZETİ",
            f"**Genel Tehdit Seviyesi:** {threat_level}\n",
            "### 1. Çevrendeki Kablosuz Yoğunluk Özeti",
            f"- Şu An Algılanan Toplam Cihaz Sayısı: **{total_devices}** (Telefon, Bilgisayar, Modem ve BLE cihazları)",
            f"- Kaydedilen Güvenlik Uyarısı Sayısı: **{len(alerts)}**",
            f"- Yüksek / Kritik Seviyeli Alarm: **{len(critical_alerts)}**\n",
            "### 2. Hava Sahası ve Drone (İHA) Kontrolü",
        ]

        if drones:
            report_lines.append(f"- ⚠️ **Yakın Hava Sahasında {len(drones)} Adet Drone Tespit Edildi:**")
            for d in drones:
                mfg = d.get("manufacturer", "Bilinmeyen Üretici")
                alt = d.get("altitude_m", "Bilinmiyor")
                spd = d.get("speed_mps", "0")
                uas_id = d.get("uas_id", "Bilinmiyor")
                p_lat = d.get("pilot_lat")
                p_lon = d.get("pilot_lon")
                pilot_str = f"{p_lat}, {p_lon}" if p_lat and p_lon else "Bilinmiyor"
                report_lines.append(
                    f"  * **{mfg} Drone** (Seri No: `{uas_id}`) — Yükseklik: `{alt} m`, Hız: `{spd} m/sn`, Pilot Konumu: `{pilot_str}`"
                )
        else:
            report_lines.append(
                "- ✅ Yakın çevrede uçan herhangi bir Drone (Remote ID sinyali) tespit edilmedi. Hava sahası temiz."
            )

        report_lines.append("\n### 3. Gizli Takip Cihazı (AirTag / SmartTag / Tile) Kontrolü")
        if trackers:
            report_lines.append(f"- 🔍 **Yakında {len(trackers)} Adet Takip Etiketi Sinyali Algılandı:**")
            for t in trackers:
                rssi = t.get("last_rssi", -80)
                dist_hint = "Çok Yakın (~1-3m)" if rssi >= -50 else ("Yakın (~3-10m)" if rssi >= -70 else "Uzak (>10m)")
                report_lines.append(
                    f"  * `{t.get('name') or t.get('matched_fleet') or 'AirTag / Takip Cihazı'}` "
                    f"(Kimlik: `{t.get('mac_or_uuid')[:18]}`) — Sinyal Gücü: `{rssi} dBm` ({dist_hint})"
                )
            report_lines.append(
                "  * *Not: Bu AirTag sana veya evdeki birine ait değilse, 'Sinyal Avcısı (Geiger)' sekmesinden cihazın yerini bulabilirsin.*"
            )
        else:
            report_lines.append(
                "- ✅ Yakın çevrede aktif bir AirTag, Tile veya SmartTag takip cihazı tespit edilmedi."
            )

        report_lines.append("\n### 4. Siber Saldırı ve Sinyal Boğma (Flipper Zero / Spam) Kontrolü")
        floods = [a for a in alerts if "FLOOD" in a.get("category", "")]
        if floods:
            report_lines.append(
                f"- 🚨 **UYARI:** {len(floods)} adet kablosuz spam / eşleşme saldırısı (Flipper Zero vb.) tespit edildi!"
            )
        else:
            report_lines.append(
                "- ✅ Bluetooth eşleşme yağmuru (Flipper Zero spam) veya sahte Wi-Fi ağ saldırısı yok. Radyo spektrumu temiz."
            )

        report_lines.append("\n### 5. Ne Yapmalısın? (Öneriler)")
        if threat_color == "critical":
            report_lines.append("1. **Hemen Kontrol Et:** 'Tehdit ve Saldırı Kayıtları' sekmesindeki kırmızı uyarıları incele.")
            report_lines.append("2. Şüpheli takip cihazını bulmak için **'Sinyal Avcısı (Geiger)'** sekmesini açıp sesli aramayı başlat.")
            report_lines.append("3. Bluetooth spam saldırısı varsa kişisel telefonunun Bluetooth'unu geçici olarak kapat.")
        elif threat_color == "elevated":
            report_lines.append("1. 'Drone Hava Sahası' veya 'Tehdit Kayıtları' sekmesinden tespit edilen sinyalin detayına bak.")
            report_lines.append("2. Şüpheli cihazın üzerine tıklayıp **'★ İzlemeye Al'** butonuyla işaretleyerek hareketini takip et.")
        else:
            report_lines.append("1. Şu an ortam tamamen güvenli. Herhangi bir müdahaleye gerek yok.")
            report_lines.append("2. Evden çıkarken veya gece yatarken **'Ortam Karşılaştırma'** sekmesinden bir kayıt başlatarak sen yokken ortama yeni bir cihaz girip girmediğini kontrol edebilirsin.")

        return "\n".join(report_lines)


# Singleton instance
ai_analyzer = LocalAiAnalyzer()
