"""Exporters for WiGLE CSV, GPX, KML, and Sit-Reps.

Includes CSV formula-injection defense (Fieldwatch CsvCells.kt port) and
Google Earth / ATAK KML Placemark generation.
"""
import csv
import hashlib
import html
import io
import json
from datetime import datetime, timezone
from typing import List
from airsentinel.models import Alert, TrackedDevice, DeviceClass, RadioType


def sanitize_csv_cell(val: str) -> str:
    """Prevents CSV formula injection (=, +, -, @, tab, CR) per OWASP & Fieldwatch CsvCells.kt."""
    if not val:
        return ""
    s = str(val).replace("\r", " ").replace("\n", " ")
    if s and s[0] in ("=", "+", "-", "@", "\t"):
        return "'" + s
    return s


class DataExporter:
    @staticmethod
    def export_wigle_csv(devices: List[TrackedDevice]) -> str:
        """Exports devices into WiGLE standard wardriving CSV format with formula-injection protection."""
        out = io.StringIO()
        out.write("WigleWifi-1.4,appRelease=AirSentinel-2.0,model=MacMiniM4,release=macOS,device=Mac\n")
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow([
            "MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
            "CurrentLatitude", "CurrentLongitude", "AltitudeMeters", "AccuracyMeters", "Type"
        ])

        for d in devices:
            mac = sanitize_csv_cell(d.mac_or_uuid)
            ssid = sanitize_csv_cell(d.name or "")
            auth = "[WPA2-PSK-CCMP]" if d.radio == RadioType.WIFI else "[BLE]"
            first_seen = d.first_seen.strftime("%Y-%m-%d %H:%M:%S")
            channel = sanitize_csv_cell(str(d.channel_or_freq or "1"))
            rssi = str(d.last_rssi)
            lat = "0.0"
            lon = "0.0"
            alt = "0.0"
            if d.drone_info and d.drone_info.aircraft_lat is not None:
                lat = str(d.drone_info.aircraft_lat)
                lon = str(d.drone_info.aircraft_lon)
                alt = str(d.drone_info.altitude_m or 0.0)

            dev_type = "WIFI" if d.radio == RadioType.WIFI else "BLE"
            writer.writerow([mac, ssid, auth, first_seen, channel, rssi, lat, lon, alt, "5.0", dev_type])

        return out.getvalue()

    @staticmethod
    def export_gpx(devices: List[TrackedDevice]) -> str:
        """Exports Drone and GPS-tagged devices to GPX 1.1 format."""
        now_iso = datetime.now(timezone.utc).isoformat()
        gpx_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<gpx version="1.1" creator="AirSentinel Core" xmlns="http://www.topografix.com/GPX/1/1">',
            f'  <metadata><time>{now_iso}</time></metadata>',
        ]

        for d in devices:
            if d.drone_info and d.drone_info.aircraft_lat is not None and d.drone_info.aircraft_lon is not None:
                lat = d.drone_info.aircraft_lat
                lon = d.drone_info.aircraft_lon
                ele = d.drone_info.altitude_m or 0.0
                name = html.escape(f"{d.drone_info.manufacturer} ({d.drone_info.uas_id})")
                desc = html.escape(f"Speed: {d.drone_info.speed_mps} m/s, Status: {d.drone_info.status}")

                gpx_lines.append(f'  <wpt lat="{lat}" lon="{lon}">')
                gpx_lines.append(f'    <ele>{ele}</ele>')
                gpx_lines.append(f'    <name>{name}</name>')
                gpx_lines.append(f'    <desc>{desc}</desc>')
                gpx_lines.append('  </wpt>')

        gpx_lines.append('</gpx>')
        return "\n".join(gpx_lines)

    @staticmethod
    def export_kml(devices: List[TrackedDevice]) -> str:
        """Exports Drone, Operator, and RF targets to KML 2.2 format for Google Earth / iTAK."""
        kml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<kml xmlns="http://www.opengis.net/kml/2.2">',
            '  <Document>',
            '    <name>AirSentinel Core RF &amp; UAS Overlay</name>',
        ]

        for d in devices:
            if d.drone_info and d.drone_info.aircraft_lat is not None and d.drone_info.aircraft_lon is not None:
                lat = d.drone_info.aircraft_lat
                lon = d.drone_info.aircraft_lon
                alt = d.drone_info.altitude_m or 0.0
                name = html.escape(f"UAS: {d.drone_info.manufacturer} ({d.drone_info.uas_id})")
                desc = html.escape(
                    f"MAC: {d.mac_or_uuid} | RSSI: {d.last_rssi} dBm | "
                    f"Speed: {d.drone_info.speed_mps} m/s | Status: {d.drone_info.status}"
                )
                kml_lines.extend([
                    '    <Placemark>',
                    f'      <name>{name}</name>',
                    f'      <description>{desc}</description>',
                    '      <Point>',
                    '        <altitudeMode>relativeToGround</altitudeMode>',
                    f'        <coordinates>{lon},{lat},{alt}</coordinates>',
                    '      </Point>',
                    '    </Placemark>',
                ])
                if d.drone_info.pilot_lat is not None and d.drone_info.pilot_lon is not None:
                    op_name = html.escape(f"PILOT: {d.drone_info.uas_id}")
                    kml_lines.extend([
                        '    <Placemark>',
                        f'      <name>{op_name}</name>',
                        f'      <description>Drone Operator Ground Station ({html.escape(d.mac_or_uuid)})</description>',
                        '      <Point>',
                        f'        <coordinates>{d.drone_info.pilot_lon},{d.drone_info.pilot_lat},0</coordinates>',
                        '      </Point>',
                        '    </Placemark>',
                    ])

        kml_lines.extend([
            '  </Document>',
            '</kml>',
        ])
        return "\n".join(kml_lines)

    @staticmethod
    def export_forensic_report_html(devices: List[TrackedDevice], alerts: List[Alert]) -> str:
        """Generates a self-contained Turkish TSCM Forensic Evidence Report (HTML) with a SHA-256 integrity hash."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        evidence_payload = {
            "generated_at": now_utc,
            "devices": [
                {
                    "mac": d.mac_or_uuid,
                    "radio": d.radio.value,
                    "name": d.name,
                    "class": d.device_class.value,
                    "rssi": d.last_rssi,
                    "risk_score": d.risk_score,
                    "role_hint": d.role_hint,
                    "decoded_fields": d.decoded_fields,
                }
                for d in devices
            ],
            "alerts": [
                {
                    "timestamp": a.timestamp.isoformat(),
                    "level": a.level.value,
                    "category": a.category.value,
                    "title": a.title,
                    "device_id": a.device_id,
                }
                for a in alerts
            ],
        }
        canonical_json = json.dumps(evidence_payload, sort_keys=True, ensure_ascii=False)
        sha256_digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest().upper()

        rows_html = []
        for d in sorted(devices, key=lambda x: (-x.risk_score, -x.last_rssi)):
            fields_str = " · ".join(
                f"{html.escape(str(f.get('label', '')))}: {html.escape(str(f.get('value', '')))}"
                for f in (d.decoded_fields or [])
                if isinstance(f, dict)
            )
            rows_html.append(
                f"<tr>"
                f"<td><code>{html.escape(d.mac_or_uuid)}</code></td>"
                f"<td>{html.escape(d.radio.value)}</td>"
                f"<td><strong>{html.escape(d.name or 'İsimsiz Verici')}</strong><br><small>{html.escape(d.role_hint or '')}</small></td>"
                f"<td>{html.escape(d.device_class.value)}</td>"
                f"<td>{d.last_rssi} dBm ({d.estimated_distance_m or '?'}m)</td>"
                f"<td><strong>{d.risk_score}/100</strong></td>"
                f"<td><small>{fields_str}</small></td>"
                f"</tr>"
            )

        alert_rows = []
        for a in alerts:
            alert_rows.append(
                f"<li><strong>[{html.escape(a.level.value)} · {html.escape(a.category.value)}]</strong> "
                f"{html.escape(a.title)} — {html.escape(a.description)} "
                f"(Cihaz: <code>{html.escape(a.device_id or '-')}</code>)</li>"
            )

        return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>AirSentinel TSCM Adli Kanıt Raporu</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:#0b1220; color:#e2e8f0; padding:24px; }}
h1, h2 {{ color:#38bdf8; }}
.hash-box {{ background:#111c33; border:1px solid #38bdf8; padding:12px; border-radius:8px; font-family:monospace; margin-bottom:20px; }}
table {{ width:100%; border-collapse:collapse; margin-top:12px; background:#111c33; }}
th, td {{ border:1px solid #1e293b; padding:8px 10px; text-align:left; font-size:13px; }}
th {{ background:#1e293b; color:#93c5fd; }}
code {{ color:#f8fafc; }}
</style>
</head>
<body>
<h1>ADLİ BİLİŞİM VE KARŞI-İSTİHBARAT (TSCM) KANIT RAPORU</h1>
<p><strong>Üretim Zamanı:</strong> {now_utc} | <strong>Platform:</strong> AirSentinel Core (MacBook Air M2 Saha Kiti)</p>
<div class="hash-box">
  <strong>KRİPTOGRAFİK BÜTÜNLÜK MÜHRÜ (SHA-256):</strong><br>
  {sha256_digest}
</div>
<h2>1. Güvenlik ve Saldırı Alarmları ({len(alerts)})</h2>
<ul>
{''.join(alert_rows) if alert_rows else '<li>Kayıtlı kritik alarm bulunmuyor.</li>'}
</ul>
<h2>2. Tespit Edilen RF / Wi-Fi / BLE Cihaz Envanteri ({len(devices)})</h2>
<table>
<thead>
<tr><th>MAC / UUID</th><th>Radyo</th><th>Cihaz Adı &amp; Rolü</th><th>Sınıf</th><th>Sinyal &amp; Mesafe</th><th>Risk</th><th>Donanım / Protokol İstihbaratı</th></tr>
</thead>
<tbody>
{''.join(rows_html)}
</tbody>
</table>
</body>
</html>"""
