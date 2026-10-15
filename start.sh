#!/bin/zsh
# AirSentinel Core v3 — Portable Launcher for Apple Silicon (MacBook Air M2 / Mac mini M4)
set -e
cd "$(dirname "$0")"
mkdir -p data

# Auto-bootstrap Python virtual environment when freshly cloned on MacBook Air M2
if [ ! -x ".venv/bin/python" ]; then
  echo "⚙️  [AirSentinel] İlk kurulum tespit edildi: .venv oluşturuluyor..."
  python3 -m venv .venv
  .venv/bin/pip install --upgrade pip >/dev/null
  echo "📦 [AirSentinel] Apple Silicon (CoreWLAN & CoreBluetooth) bağımlılıkları yükleniyor..."
  .venv/bin/pip install -r requirements.txt
fi

# Ensure no stale instance is holding port 8080
lsof -ti :8080 | xargs kill -9 2>/dev/null || true

# Refresh platform ARP cache in background (bypasses macOS non-platform binary NET_RT_FLAGS restriction)
(
  while true; do
    /usr/sbin/arp -an 2>/dev/null | grep -v incomplete > data/.arp_cache.tmp && mv data/.arp_cache.tmp data/arp_cache.txt
    sleep 5
  done
) &
ARP_PID=$!
trap "kill $ARP_PID 2>/dev/null || true" EXIT INT TERM

/usr/sbin/arp -an 2>/dev/null | grep -v incomplete > data/arp_cache.txt || true

LAN_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "127.0.0.1")
echo "🚀 AirSentinel Core v3 başlatılıyor..."
echo "   💻 Mac Tarayıcı Arayüzü : http://127.0.0.1:8080"
echo "   📱 Telefon (Aynı Wi-Fi) : http://${LAN_IP}:8080"
.venv/bin/python run.py "$@"
