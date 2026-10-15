"""macOS Native Wi-Fi Spectrum Scanner using CoreWLAN & Local ARP Telemetry.

Uses Apple's CoreWLAN framework via PyObjC for fast, non-blocking 802.11 scans
(2.4GHz, 5GHz, 6GHz bands, RSSI, noise, SNR, Information Elements) and enriches
local gateway/wireless peers via the macOS ARP table.
"""
import asyncio
import logging
import re
import socket
import struct
import subprocess
from time import monotonic
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from airsentinel.config import DATA_DIR, settings
from airsentinel.models import Observation, RadioType
from airsentinel.signatures.catalog import SignatureCatalog

logger = logging.getLogger("airsentinel.scanner.wifi")
ObservationCallback = Callable[[Observation], Coroutine[Any, Any, None]]

BAND_MAP = {
    1: "2.4GHz",
    2: "5GHz",
    3: "6GHz",
}

WIDTH_MAP = {
    1: "20MHz",
    2: "40MHz",
    3: "80MHz",
    4: "160MHz",
}

CAMERA_STREAM_PORTS: Dict[int, str] = {
    554: "RTSP Canlı Video (Port 554)",
    8554: "RTSP Video Akışı (Port 8554)",
    81: "ESP32-CAM / MJPEG Kamera Akışı (Port 81)",
    8000: "Hikvision Kamera Servisi (Port 8000)",
    37777: "Dahua Kamera Servisi (Port 37777)",
    8899: "ONVIF Kamera Kontrolü (Port 8899)",
    6668: "Tuya Akıllı Kamera / IoT (Port 6668)",
    1935: "RTMP Canlı Video (Port 1935)",
    8090: "P2P / IP Kamera Yayını (Port 8090)",
}

CAMERA_BANNER_KEYWORDS = (
    "hikvision",
    "dahua",
    "ipcamera",
    "ipc-",
    "v380",
    "reolink",
    "esp32-cam",
    "go2rtc",
    "live555",
    "onvif",
    "amcrest",
    "webcam",
    "mjpeg",
    "netcam",
)

SPYCAM_SSID_KEYWORDS = (
    "v380",
    "lookcam",
    "hdwificam",
    "jxlcam",
    "bvcam",
    "carecam",
    "icam365",
    "hidvcam",
    "yoosee",
    "p2pcam",
    "ipc-",
    "batcam",
    "accq-",
    "ayscam",
    "dgcam",
    "wificam",
    "minicam",
)

# High-risk Camera & IoT Radio Silicon OUI Database (first 3 bytes of MAC)
HARDWARE_OUI_INTEL: Dict[str, str] = {
    "EC:3D:FD": "Shenzhen Bilian (LB-LINK Gizli Kamera / Wi-Fi Modülü)",
    "14:6B:9C": "Shenzhen Bilian (LB-LINK Kamera / IoT Radyo Çipi)",
    "E8:AB:FA": "Shenzhen Bilian (LB-LINK Kablosuz Kamera Modülü)",
    "F4:B8:5E": "Shenzhen Bilian (LB-LINK Wi-Fi Modülü)",
    "24:0A:C4": "Espressif Systems (ESP32-CAM / IoT Mikrodenetleyici)",
    "30:AE:A4": "Espressif Systems (ESP32 / ESP8266 Kamera Modülü)",
    "A0:20:A6": "Espressif Systems (ESP8266 / ESP32 Wi-Fi Çipi)",
    "84:F3:EB": "Espressif Systems (ESP32-S / Kamera Modülü)",
    "00:E0:FC": "HiSilicon Technologies (IP Kamera Video SoC)",
    "28:57:BE": "Hangzhou Hikvision (IP Kamera / NVR Üreticisi)",
    "44:19:B6": "Hangzhou Hikvision (IP Kamera Üreticisi)",
    "C0:56:E3": "Hangzhou Hikvision (IP Kamera Üreticisi)",
    "3C:EF:8C": "Zhejiang Dahua (IP Kamera / Kayıt Cihazı)",
    "90:02:A9": "Zhejiang Dahua (IP Kamera Üreticisi)",
    "E0:50:8B": "Zhejiang Dahua (IP Kamera Üreticisi)",
    "D8:1F:12": "Tuya Smart (Akıllı Kamera / IoT Modülü)",
    "10:D5:61": "Tuya Smart (Akıllı Ev / Kamera Çipi)",
    "70:89:76": "Tuya Smart (Kablosuz IoT Modülü)",
    "EC:71:DB": "Reolink Innovation (Güvenlik Kamerası)",
    "2C:AA:8E": "Wyze Labs (Kablosuz Kamera)",
    "7C:78:B2": "Xiaomi Chuangmi / Aqara (Akıllı Kamera / Hub)",
    "54:EF:44": "Xiaomi Lumi / Aqara (Akıllı Kamera / Sensör)",
}


class WifiScanner:
    def __init__(self, callback: ObservationCallback):
        self.callback = callback
        self.is_running = False
        self._task: Optional[asyncio.Task] = None
        self._cw_iface = None
        # ip -> (timestamp_mono, hostname, open_camera_ports, banner_or_upnp)
        self._peer_intel_cache: Dict[str, Tuple[float, Optional[str], List[str], Optional[str]]] = {}
        self._ssdp_cache: Dict[str, str] = {}
        self._onvif_cache: Dict[str, str] = {}
        self._last_subnet_sweep: float = 0.0
        self._init_corewlan()

    @staticmethod
    def lookup_oui_intel(mac: Optional[str]) -> Optional[str]:
        """Returns hardware manufacturer & camera-chip intelligence if MAC matches known Camera/IoT OUIs."""
        if not mac or len(mac) < 8:
            return None
        prefix = mac[:8].upper()
        return HARDWARE_OUI_INTEL.get(prefix)

    @staticmethod
    def _detect_spycam_or_hidden_ap(
        ssid: Optional[str],
        rssi: int,
        ch_num: int,
        is_hidden: bool = False,
    ) -> Dict[str, Any]:
        """Detects covert SpyCam SoftAP SSIDs (V380, LookCam, HDWiFiCam, etc.) and close-range hidden Wi-Fi APs."""
        clean_ssid = (ssid or "").strip()
        low_ssid = clean_ssid.lower()
        decoded_fields: List[Dict[str, str]] = []

        if clean_ssid and any(k in low_ssid for k in SPYCAM_SSID_KEYWORDS):
            decoded_fields.append({
                "label": "Casus Kamera Ağı (SoftAP)",
                "value": f"Bilinen gizli kamera doğrudan Wi-Fi kalıbı ({clean_ssid})",
            })
            return {
                "is_spycam_ap": True,
                "is_hidden_room_ap": False,
                "display_name": clean_ssid,
                "role_hint": "Gizli Kamera Doğrudan Wi-Fi Yayını (SpyCam SoftAP)",
                "decoded_fields": decoded_fields,
            }

        if is_hidden and not clean_ssid and rssi >= -62:
            disp = f"<Gizli Wi-Fi Ağı> [Ch {ch_num}]"
            decoded_fields.append({
                "label": "Gizli SSID Uyarısı",
                "value": f"Oda içinde ({rssi} dBm) ismini gizleyen Wi-Fi vericisi",
            })
            return {
                "is_spycam_ap": False,
                "is_hidden_room_ap": True,
                "display_name": disp,
                "role_hint": "Oda İçi Gizli (İsimsiz) Wi-Fi Vericisi",
                "decoded_fields": decoded_fields,
            }

        return {
            "is_spycam_ap": False,
            "is_hidden_room_ap": False,
            "display_name": clean_ssid or f"Wi-Fi AP [Ch {ch_num}]",
            "role_hint": None,
            "decoded_fields": decoded_fields,
        }

    @staticmethod
    def _parse_onvif_ws_discovery_response(xml_bytes: bytes) -> Optional[str]:
        """Extracts ONVIF camera name, hardware model, and XAddrs service URL from WS-Discovery XML response."""
        text = xml_bytes.decode("utf-8", errors="ignore")
        if "ProbeMatch" not in text and "NetworkVideoTransmitter" not in text and "onvif" not in text.lower():
            return None
        name_m = re.search(r"onvif://www\.onvif\.org/name/([^\s<\"']+)", text, re.IGNORECASE)
        hw_m = re.search(r"onvif://www\.onvif\.org/hardware/([^\s<\"']+)", text, re.IGNORECASE)
        xaddr_m = re.search(r"<[^:>]*:?XAddrs[^>]*>([^<]+)</", text, re.IGNORECASE)

        parts = []
        if name_m:
            parts.append(name_m.group(1).strip())
        if hw_m:
            parts.append(f"({hw_m.group(1).strip()})")
        if xaddr_m:
            first_url = xaddr_m.group(1).strip().split()[0]
            parts.append(f"[{first_url}]")
        return "ONVIF Kamera: " + (" ".join(parts) if parts else "Aktif Video Vericisi")

    def _discover_onvif_devices(self, timeout: float = 0.35):
        """Broadcasts ONVIF WS-Discovery XML SOAP Probe on 239.255.255.250:3702 to uncover hidden IP cameras."""
        probe_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
            b'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            b'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
            b'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
            b"<e:Header><w:MessageID>uuid:84ede3de-7dec-11d0-c360-F01234567890</w:MessageID>"
            b'<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
            b"<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>"
            b"<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>"
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
                s.settimeout(timeout)
                s.sendto(probe_xml, ("239.255.255.250", 3702))
                deadline = monotonic() + timeout
                while monotonic() < deadline:
                    try:
                        data, addr = s.recvfrom(4096)
                        ip = addr[0]
                        parsed = self._parse_onvif_ws_discovery_response(data)
                        if parsed:
                            self._onvif_cache[ip] = parsed
                    except socket.timeout:
                        break
                    except Exception:
                        break
        except Exception:
            pass

    @staticmethod
    def _parse_dahua_dhip_response(pkt: bytes) -> Optional[str]:
        """Parses Dahua DHIP (UDP 37810) JSON discovery response to extract camera model and serial."""
        text = pkt.decode("utf-8", errors="ignore")
        if "DHIP" not in text and "DeviceType" not in text:
            return None
        dev_m = re.search(r'"DeviceType"\s*:\s*"([^"]+)"', text)
        sn_m = re.search(r'"SerialNo"\s*:\s*"([^"]+)"', text)
        if not dev_m and not sn_m:
            return None
        model = dev_m.group(1).strip() if dev_m else "IP Kamera"
        sn = f" (SN: {sn_m.group(1).strip()})" if sn_m else ""
        return f"Dahua Kamera: {model}{sn}"

    @staticmethod
    def _parse_hikvision_sadp_response(xml_bytes: bytes) -> Optional[str]:
        """Parses Hikvision SADP (UDP 37020) XML ProbeMatch response to extract camera model and serial."""
        text = xml_bytes.decode("utf-8", errors="ignore")
        if "DeviceDescription" not in text and "ProbeMatch" not in text:
            return None
        desc_m = re.search(r"<DeviceDescription[^>]*>([^<]+)</DeviceDescription>", text, re.IGNORECASE)
        sn_m = re.search(r"<DeviceSN[^>]*>([^<]+)</DeviceSN>", text, re.IGNORECASE)
        if not desc_m and not sn_m:
            return None
        desc = desc_m.group(1).strip() if desc_m else "IP Kamera"
        sn = f" (SN: {sn_m.group(1).strip()})" if sn_m else ""
        return f"Hikvision SADP Kamera: {desc}{sn}"

    def _discover_proprietary_cameras(self, timeout: float = 0.25):
        """Broadcasts Dahua DHIP (UDP 37810) and Hikvision SADP (UDP 37020) multicast probes."""
        dahua_body = b'{"method":"DHDiscover.search","params":{"mac":"","uni":1}}\n'
        dahua_hdr = b"\x20\x00\x00\x00DHIP\x00\x00\x00\x00\x00\x00\x00\x00" + struct.pack("<I", len(dahua_body)) + b"\x00\x00\x00\x00" + struct.pack("<I", len(dahua_body)) + b"\x00\x00\x00\x00"
        sadp_probe = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b"<Probe><Uuid>AirSentinel-SADP-Probe</Uuid><Types>inquiry</Types></Probe>"
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
                s.settimeout(timeout)
                try:
                    s.sendto(dahua_hdr + dahua_body, ("239.255.255.251", 37810))
                except Exception:
                    pass
                try:
                    s.sendto(sadp_probe, ("239.255.255.250", 37020))
                except Exception:
                    pass
                deadline = monotonic() + timeout
                while monotonic() < deadline:
                    try:
                        data, addr = s.recvfrom(4096)
                        ip = addr[0]
                        parsed = self._parse_dahua_dhip_response(data) or self._parse_hikvision_sadp_response(data)
                        if parsed:
                            self._onvif_cache[ip] = parsed
                    except socket.timeout:
                        break
                    except Exception:
                        break
        except Exception:
            pass

    @staticmethod
    def _is_private_or_loopback_ipv4(ip: str) -> bool:
        parts = ip.strip().split(".")
        if len(parts) != 4:
            return False
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return False
        if octets[0] in (0, 10, 127):
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        if octets[0] == 169 and octets[1] == 254:
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        return False

    @classmethod
    def evaluate_dns_resolution_anomaly(cls, domain: str, resolved_ips: List[str]) -> Optional[Dict[str, str]]:
        """Detects DNS Hijacking / Phishing Captive Portal when a global canary domain resolves to a private/local IP."""
        hijacked_ips = [ip for ip in resolved_ips if cls._is_private_or_loopback_ipv4(ip)]
        if not hijacked_ips:
            return None
        ips_str = ", ".join(hijacked_ips)
        return {
            "type": "DNS_PRIVATE_IP_HIJACK",
            "domain": domain,
            "ips": ips_str,
            "title": f"DNS Zehirleme / Sahte Ağ Yönlendirmesi: {domain} -> {ips_str}",
            "description": (
                f"Küresel alan adı '{domain}', yerel/özel bir IP adresine ({ips_str}) yönlendiriliyor! "
                f"Bulunduğunuz ağda DNS Hijacking (Araya Girme) veya sahte giriş sayfası (Phishing) saldırısı olabilir."
            ),
        }

    @classmethod
    def check_live_dns_hijack(cls) -> List[Dict[str, str]]:
        """Resolves global canary domains to verify the local Wi-Fi router is not hijacking DNS to private IPs."""
        anomalies: List[Dict[str, str]] = []
        for canary in ("www.apple.com", "one.one.one.one"):
            try:
                infos = socket.getaddrinfo(canary, 443, socket.AF_INET, socket.SOCK_STREAM)
                ips = sorted({info[4][0] for info in infos if info and len(info) >= 5 and info[4]})
                anom = cls.evaluate_dns_resolution_anomaly(canary, ips)
                if anom:
                    anomalies.append(anom)
            except Exception:
                pass
        return anomalies

    def _init_corewlan(self):
        """Loads native macOS CoreWLAN framework if available."""
        try:
            import objc
            from Foundation import NSBundle

            bundle = NSBundle.bundleWithPath_("/System/Library/Frameworks/CoreWLAN.framework")
            if bundle and bundle.load():
                CWWiFiClient = objc.lookUpClass("CWWiFiClient")
                client = CWWiFiClient.sharedWiFiClient()
                if client:
                    self._cw_iface = client.interface()
        except Exception as e:
            logger.debug(f"CoreWLAN init fallback: {e}")

    @staticmethod
    def _get_local_subnet_prefix() -> Optional[str]:
        """Returns the local /24 subnet prefix (e.g. '192.168.1.') if connected to IPv4 LAN."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
            parts = ip.split(".")
            if len(parts) == 4 and not ip.startswith("127."):
                return f"{parts[0]}.{parts[1]}.{parts[2]}."
        except Exception:
            pass
        return None

    def _wake_local_subnet(self):
        """Sends non-blocking UDP probes across local /24 subnet so silent cameras/peers enter macOS ARP table."""
        prefix = self._get_local_subnet_prefix()
        if not prefix:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setblocking(False)
                for host_id in range(1, 255):
                    try:
                        s.sendto(b"\x00", (f"{prefix}{host_id}", 5353))
                    except Exception:
                        pass
        except Exception:
            pass

    def _discover_ssdp_devices(self, timeout: float = 0.35):
        """Broadcasts UPnP/SSDP M-SEARCH (UDP 1900) and maps responding LAN IPs to their server/device strings."""
        msg = (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b'MAN: "ssdp:discover"\r\n'
            b"MX: 1\r\n"
            b"ST: ssdp:all\r\n\r\n"
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
                s.settimeout(timeout)
                s.sendto(msg, ("239.255.255.250", 1900))
                deadline = monotonic() + timeout
                while monotonic() < deadline:
                    try:
                        data, addr = s.recvfrom(1024)
                        ip = addr[0]
                        text = data.decode("utf-8", errors="ignore")
                        server_m = re.search(r"(?im)^SERVER:\s*(.+)$", text)
                        if server_m:
                            srv = server_m.group(1).strip()[:70]
                            if srv:
                                self._ssdp_cache[ip] = srv
                    except socket.timeout:
                        break
                    except Exception:
                        break
        except Exception:
            pass

    @staticmethod
    def _resolve_mdns_hostname(ip: str, timeout: float = 0.16) -> Optional[str]:
        """Queries mDNS (UDP 5353) reverse PTR or local reverse DNS for a LAN peer's Bonjour hostname."""
        try:
            rev_parts = list(reversed(ip.split("."))) + ["in-addr", "arpa"]
            qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in rev_parts) + b"\x00"
            pkt = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(pkt, (ip, 5353))
                resp, _ = s.recvfrom(512)
                if len(resp) > 12:
                    m = re.search(rb"([A-Za-z0-9\-_]{2,40})\x05local", resp)
                    if m:
                        return m.group(1).decode("utf-8", errors="ignore") + ".local"
        except Exception:
            pass
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            if host and host != ip:
                return host
        except Exception:
            pass
        return None

    @staticmethod
    def _grab_http_or_rtsp_banner(ip: str, port: int, timeout: float = 0.22) -> Optional[str]:
        """Reads RTSP OPTIONS Server header or HTTP Server/<title> banner from an open port."""
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                if port in (554, 8554):
                    req = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode("ascii")
                else:
                    req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: AirSentinel/4.0\r\n\r\n".encode("ascii")
                s.sendall(req)
                raw = s.recv(1024).decode("utf-8", errors="ignore")
                if not raw:
                    return None
                srv_m = re.search(r"(?im)^Server:\s*(.+)$", raw)
                title_m = re.search(r"(?is)<title[^>]*>(.*?)</title>", raw)
                parts = []
                if srv_m:
                    parts.append(srv_m.group(1).strip()[:45])
                if title_m:
                    t_clean = re.sub(r"\s+", " ", title_m.group(1)).strip()[:45]
                    if t_clean:
                        parts.append(t_clean)
                return " · ".join(parts) if parts else None
        except Exception:
            return None

    @classmethod
    def _probe_camera_ports(cls, ip: str, timeout: float = 0.15) -> List[str]:
        """Probes a LAN peer IP for open RTSP / ONVIF / Hikvision / Dahua / ESP32-CAM / Tuya streaming ports."""
        open_services: List[str] = []
        for port, label in CAMERA_STREAM_PORTS.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        banner = cls._grab_http_or_rtsp_banner(ip, port, timeout=0.2) if port in (554, 8554, 81) else None
                        open_services.append(f"{label} [{banner}]" if banner else label)
            except Exception:
                pass
        return open_services

    def _inspect_lan_peer(self, ip: str, force: bool = False) -> Tuple[Optional[str], List[str], Optional[str]]:
        """Returns (bonjour_hostname, open_camera_ports, banner_or_upnp) with a 60s cache per IP."""
        now_m = monotonic()
        cached = self._peer_intel_cache.get(ip)
        if not force and cached and (now_m - cached[0]) < 60.0:
            return cached[1], cached[2], cached[3]

        hostname = self._resolve_mdns_hostname(ip)
        cam_ports = [] if ip.endswith(".1") else self._probe_camera_ports(ip)
        onvif_hit = self._onvif_cache.get(ip)
        if onvif_hit and onvif_hit not in cam_ports:
            cam_ports.insert(0, onvif_hit)

        banner_info = self._ssdp_cache.get(ip) or onvif_hit
        if not ip.endswith(".1") and not banner_info:
            for http_port in (80, 8080):
                b = self._grab_http_or_rtsp_banner(ip, http_port, timeout=0.18)
                if b:
                    banner_info = f"HTTP:{http_port} ({b})"
                    if any(k in b.lower() for k in CAMERA_BANNER_KEYWORDS):
                        cam_ports.append(f"Kamera Web Arayüzü ({banner_info})")
                    break

        self._peer_intel_cache[ip] = (now_m, hostname, cam_ports, banner_info)
        return hostname, cam_ports, banner_info

    @classmethod
    def _read_arp_neighbors(cls) -> List[Tuple[str, str, str]]:
        """Reads local wireless MAC addresses (IP, normalized_mac, interface) from arp -an or platform cache."""
        neighbors: List[Tuple[str, str, str]] = []
        try:
            out = subprocess.check_output(["/usr/sbin/arp", "-an"], timeout=6.0).decode("utf-8", errors="ignore")
            if not out.strip():
                cache_file = DATA_DIR / "arp_cache.txt"
                if cache_file.exists():
                    out = cache_file.read_text(encoding="utf-8", errors="ignore")
            for line in out.splitlines():
                if " permanent " in line.lower():
                    continue
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)\s+on\s+(\w+)", line)
                if not m:
                    continue
                ip, raw_mac, iface = m.group(1), m.group(2), m.group(3)
                if (
                    ip.startswith("224.")
                    or ip.startswith("239.")
                    or ip.startswith("169.254.")
                    or ip.endswith(".255")
                ):
                    continue
                norm_mac = SignatureCatalog._normalize_mac(raw_mac)
                if norm_mac == "FF:FF:FF:FF:FF:FF":
                    continue
                neighbors.append((ip, norm_mac, iface))
        except Exception:
            pass
        return neighbors

    @staticmethod
    def _parse_wps_tlvs(wps_bytes: bytes) -> Dict[str, str]:
        """Parses big-endian Microsoft WPS (00:50:F2:04) TLV attributes from a Wi-Fi Beacon/Probe IE."""
        out: Dict[str, str] = {}
        idx = 0
        while idx + 4 <= len(wps_bytes):
            attr_type, attr_len = struct.unpack(">HH", wps_bytes[idx : idx + 4])
            val = wps_bytes[idx + 4 : idx + 4 + attr_len]
            idx += 4 + attr_len
            if attr_type in (0x1021, 0x1023, 0x1024, 0x1011, 0x1042) and val:
                txt = val.decode("utf-8", errors="ignore").strip("\x00").strip()
                if not txt:
                    continue
                if attr_type == 0x1021:
                    out["wps_manufacturer"] = txt
                elif attr_type == 0x1023:
                    out["wps_model"] = txt
                elif attr_type == 0x1024:
                    out["wps_model_number"] = txt
                elif attr_type == 0x1011:
                    out["wps_device_name"] = txt
                elif attr_type == 0x1042:
                    out["wps_serial"] = txt
        return out

    @classmethod
    def _parse_ie_intelligence(cls, ie_bytes: bytes) -> Dict[str, Any]:
        """Extracts deep 802.11 IE telemetry: SSID, WPS device identity, RSN security, Wi-Fi 4/5/6 gen, Country, and ODID."""
        info: Dict[str, Any] = {
            "ssid": None,
            "vendor_ouis": [],
            "odid_payload": None,
            "country": None,
            "security": "AÇIK (Şifresiz Ağ)",
            "wifi_standard": "802.11a/b/g",
            "wps_manufacturer": None,
            "wps_model": None,
            "wps_model_number": None,
            "wps_device_name": None,
            "wps_serial": None,
        }
        has_rsn = False
        has_wpa1 = False
        has_ht = False
        has_vht = False
        has_he = False

        idx = 0
        while idx + 2 <= len(ie_bytes):
            tag = ie_bytes[idx]
            length = ie_bytes[idx + 1]
            val = ie_bytes[idx + 2 : idx + 2 + length]
            idx += 2 + length

            if tag == 0 and val:
                decoded = val.decode("utf-8", errors="ignore").strip("\x00").strip()
                if decoded and decoded != "<redacted>":
                    info["ssid"] = decoded
            elif tag == 7 and len(val) >= 2:
                cc = val[:2].decode("ascii", errors="ignore").strip()
                if len(cc) == 2 and cc.isalpha():
                    info["country"] = cc.upper()
            elif tag == 45:
                has_ht = True
            elif tag == 48 and len(val) >= 2:
                has_rsn = True
                # Check for WPA3 SAE AKM suite (00:0F:AC:08)
                if b"\x00\x0f\xac\x08" in val:
                    info["security"] = "WPA3-SAE Şifreli"
                else:
                    info["security"] = "WPA2/WPA3 Şifreli"
            elif tag == 191:
                has_vht = True
            elif tag == 255 and len(val) >= 1 and val[0] == 35:
                has_he = True
            elif tag == 221 and len(val) >= 3:
                oui = f"{val[0]:02X}:{val[1]:02X}:{val[2]:02X}"
                if oui not in info["vendor_ouis"]:
                    info["vendor_ouis"].append(oui)
                if oui == "FA:0B:BC" and len(val) > 4 and val[3] == 0x0D:
                    info["odid_payload"] = val[4:]
                elif oui == "00:50:F2" and len(val) >= 4:
                    sub = val[3]
                    if sub == 0x01:
                        has_wpa1 = True
                    elif sub == 0x04 and len(val) > 4:
                        wps_data = cls._parse_wps_tlvs(val[4:])
                        info.update(wps_data)

        if not has_rsn and has_wpa1:
            info["security"] = "WPA1 (Eski Şifreleme)"

        if has_he:
            info["wifi_standard"] = "Wi-Fi 6 (802.11ax)"
        elif has_vht:
            info["wifi_standard"] = "Wi-Fi 5 (802.11ac)"
        elif has_ht:
            info["wifi_standard"] = "Wi-Fi 4 (802.11n)"

        return info

    @classmethod
    def _parse_ie_bytes(cls, ie_bytes: bytes) -> Tuple[Optional[str], List[str], Optional[bytes]]:
        """Backwards-compatible tuple wrapper around _parse_ie_intelligence."""
        info = cls._parse_ie_intelligence(ie_bytes)
        return info["ssid"], info["vendor_ouis"], info["odid_payload"]

    def _scan_corewlan_sync(self, force_deep: bool = False) -> List[Observation]:
        """Runs synchronous CoreWLAN scan + active subnet/SSDP/ONVIF/ARP/camera/mDNS correlation in a worker thread."""
        observations: List[Observation] = []
        now_m = monotonic()
        if force_deep or (now_m - self._last_subnet_sweep) >= 45.0:
            self._last_subnet_sweep = now_m
            self._wake_local_subnet()
            self._discover_ssdp_devices(timeout=0.35 if force_deep else 0.2)
            self._discover_onvif_devices(timeout=0.35 if force_deep else 0.2)
            self._discover_proprietary_cameras(timeout=0.25 if force_deep else 0.15)

        arp_peers = self._read_arp_neighbors()
        gateway_mac = next((mac for ip, mac, _ in arp_peers if ip.endswith(".1")), None)

        if self._cw_iface is not None:
            try:
                curr_chan_obj = self._cw_iface.wlanChannel()
                curr_chan = curr_chan_obj.channelNumber() if curr_chan_obj else None
                curr_rssi = int(self._cw_iface.rssiValue() or -60)

                nets, _ = self._cw_iface.scanForNetworksWithName_error_(None, None)
                if nets:
                    chan_totals: Dict[Tuple[int, int, int], int] = {}
                    for n in nets:
                        c_obj = n.wlanChannel()
                        k = (
                            int(c_obj.channelNumber()) if c_obj else 0,
                            int(c_obj.channelBand()) if c_obj else 1,
                            int(c_obj.channelWidth()) if c_obj else 1,
                        )
                        chan_totals[k] = chan_totals.get(k, 0) + 1

                    seen_synthetic_keys = set()
                    sorted_nets = sorted(
                        list(nets),
                        key=lambda n: -int(n.rssiValue() or -99),
                    )
                    for net in sorted_nets:
                        ch_obj = net.wlanChannel()
                        ch_num = int(ch_obj.channelNumber()) if ch_obj else 0
                        band_id = int(ch_obj.channelBand()) if ch_obj else 1
                        width_id = int(ch_obj.channelWidth()) if ch_obj else 1
                        band_str = BAND_MAP.get(band_id, "Wi-Fi")
                        width_str = WIDTH_MAP.get(width_id, "20MHz")
                        chan_desc = f"Ch {ch_num} ({band_str}" + (f", {width_str})" if width_str else ")")

                        rssi = int(net.rssiValue() or -75)
                        noise = int(net.noiseMeasurement() or -95)
                        snr = (rssi - noise) if noise < 0 else None

                        raw_ssid = net.ssid()
                        raw_bssid = net.bssid()

                        ie_data = net.informationElementData()
                        ie_bytes = bytes(ie_data) if ie_data else b""
                        ie_info = self._parse_ie_intelligence(ie_bytes)
                        ie_ssid = ie_info["ssid"]
                        vendor_ouis = ie_info["vendor_ouis"]
                        odid_bytes = ie_info["odid_payload"]

                        ssid = raw_ssid if (raw_ssid and raw_ssid != "<redacted>") else ie_ssid
                        bssid = SignatureCatalog._normalize_mac(raw_bssid) if raw_bssid else None

                        if not bssid and curr_chan and ch_num == int(curr_chan) and abs(rssi - curr_rssi) <= 6 and gateway_mac:
                            bssid = gateway_mac
                            if not ssid:
                                ssid = f"Connected Gateway AP ({chan_desc})"

                        is_synthetic = False
                        key = (ch_num, band_id, width_id)
                        ap_count_on_chan = chan_totals.get(key, 1)
                        if not bssid:
                            if key in seen_synthetic_keys and not odid_bytes:
                                continue
                            seen_synthetic_keys.add(key)
                            is_synthetic = True
                            bssid = f"00:57:46:{ch_num & 0xFF:02X}:{band_id & 0xFF:02X}:{width_id & 0xFF:02X}"

                        wps_label_parts = [
                            p
                            for p in (
                                ie_info.get("wps_manufacturer"),
                                ie_info.get("wps_model"),
                                ie_info.get("wps_device_name"),
                            )
                            if p
                        ]
                        spy_meta = self._detect_spycam_or_hidden_ap(
                            ssid=ssid,
                            rssi=rssi,
                            ch_num=ch_num,
                            is_hidden=(ssid is None and not is_synthetic),
                        )
                        if not ssid:
                            if wps_label_parts:
                                ssid = f"{' '.join(wps_label_parts[:2])} [{chan_desc}]"
                            elif spy_meta["is_hidden_room_ap"]:
                                ssid = spy_meta["display_name"]
                            else:
                                ssid = f"Wi-Fi AP [{chan_desc}]"

                        decoded_fields = list(spy_meta["decoded_fields"])
                        if ie_bytes:
                            decoded_fields.append({"label": "Wi-Fi Güvenliği", "value": ie_info["security"]})
                            decoded_fields.append({"label": "Wi-Fi Standardı", "value": ie_info["wifi_standard"]})
                        if wps_label_parts:
                            decoded_fields.append({"label": "WPS Donanım Kimliği", "value": " · ".join(wps_label_parts)})
                        if ie_info.get("country"):
                            decoded_fields.append({"label": "Bölge Kodu (802.11d)", "value": ie_info["country"]})

                        role_str = spy_meta["role_hint"] or (
                            f"Wi-Fi Erişim Noktası ({ap_count_on_chan} Modem Bu Kanalda)"
                            if ap_count_on_chan > 1 and is_synthetic
                            else "Wi-Fi Erişim Noktası (Modem / Router)"
                        )

                        obs = Observation(
                            radio=RadioType.WIFI,
                            mac_or_uuid=bssid,
                            name=ssid,
                            rssi=rssi,
                            snr=snr,
                            channel_or_freq=chan_desc,
                            role_hint=role_str,
                            vendor_ie_ouis=vendor_ouis,
                            decoded_fields=decoded_fields,
                            manufacturer_data_hex=odid_bytes.hex().upper() if odid_bytes else None,
                            service_uuids=["fffa"] if odid_bytes else [],
                            is_randomized_mac=(not is_synthetic) and SignatureCatalog.is_locally_administered_mac(bssid),
                        )
                        observations.append(obs)
            except Exception as e:
                logger.debug(f"CoreWLAN scan error: {e}")

        # Emit active wireless LAN peers discovered in ARP and inspect for Bonjour, UPnP/SSDP, HTTP, and RTSP/ONVIF cameras
        for ip, mac, iface in arp_peers:
            if any(o.mac_or_uuid == mac for o in observations):
                continue
            is_rand = SignatureCatalog.is_locally_administered_mac(mac)
            hostname, cam_ports, banner_info = self._inspect_lan_peer(ip, force=force_deep)
            decoded_fields = []
            if hostname:
                decoded_fields.append({"label": "Bonjour / Ağ Adı", "value": hostname})
            if banner_info:
                decoded_fields.append({"label": "Ağ Servis / UPnP Kimliği", "value": banner_info})

            if cam_ports:
                peer_name = f"IP Kamera ({hostname or ip})"
                role_hint = "Ağda Canlı Video Yayını Yapan Kamera (RTSP/ONVIF)"
                decoded_fields.append({"label": "Açık Kamera Portu", "value": ", ".join(cam_ports)})
            elif ip.endswith(".1"):
                peer_name = "Gateway Router"
                role_hint = "Ana Modem / Gateway"
            else:
                peer_name = f"{hostname} ({ip})" if hostname else f"LAN Wireless Peer ({ip})"
                role_hint = f"Yerel Ağ Cihazı ({ip})"

            observations.append(
                Observation(
                    radio=RadioType.WIFI,
                    mac_or_uuid=mac,
                    name=peer_name,
                    rssi=-45 if ip.endswith(".1") else -55,
                    channel_or_freq=f"LAN ({iface} · {ip})",
                    role_hint=role_hint,
                    decoded_fields=decoded_fields,
                    is_randomized_mac=is_rand,
                )
            )

        return observations

    async def run_deep_camera_scan(self) -> Dict[str, Any]:
        """Forces an immediate active /24 subnet wake-up + SSDP + mDNS + RTSP/ONVIF/HTTP camera sweep."""
        obs_list = await asyncio.to_thread(self._scan_corewlan_sync, True)
        cameras_found = []
        peers_checked = 0
        for obs in obs_list:
            await self.callback(obs)
            if obs.channel_or_freq and obs.channel_or_freq.startswith("LAN"):
                peers_checked += 1
            if obs.role_hint and "Kamera" in obs.role_hint:
                cameras_found.append({"mac_or_uuid": obs.mac_or_uuid, "name": obs.name, "role": obs.role_hint})
        return {
            "peers_checked": peers_checked,
            "cameras_found_count": len(cameras_found),
            "cameras": cameras_found,
        }

    async def _scan_once(self):
        """Runs a single non-blocking pass of Wi-Fi discovery and ARP Spoofing / MITM verification."""
        try:
            obs_list = await asyncio.to_thread(self._scan_corewlan_sync)
            for obs in obs_list:
                await self.callback(obs)
            arp_peers = await asyncio.to_thread(self._read_arp_neighbors)
            if arp_peers:
                from airsentinel.correlation.engine import correlation_engine
                await correlation_engine.process_arp_table(arp_peers)
        except Exception as e:
            logger.debug(f"Wi-Fi scan iteration error: {e}")

    async def _scan_loop(self):
        """Continuous polling loop for Wi-Fi access points."""
        logger.info("macOS CoreWLAN Wi-Fi observer loop started.")
        while self.is_running:
            await self._scan_once()
            await asyncio.sleep(settings.wifi_scan_interval_sec)

    async def start(self):
        """Starts scanning for Wi-Fi APs."""
        if self.is_running:
            return
        self.is_running = True
        self._task = asyncio.create_task(self._scan_loop())
        logger.info("macOS CoreWLAN Wi-Fi scanner initialized and scheduled.")

    async def stop(self):
        """Stops the Wi-Fi scanner."""
        if not self.is_running:
            return
        logger.info("Stopping Wi-Fi scanner...")
        self.is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
