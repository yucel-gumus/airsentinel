/**
 * AirSentinel Taktik Radar, Adli Sinyal Çözücü ve Geiger Sinyal Avcısı Kontrolcüsü (Türkçe Arayüz).
 */

// Durum Değişkenleri
let ws = null;
let devicesMap = new Map();
let alertsList = [];
let audioAlertEnabled = true;
let geigerAudioEnabled = false;
let nightMode = false;
let currentTab = "radar";
let selectedModalMac = null;

// Sinyal Avcısı (Geiger) Durumu
let huntTargetMac = "";
let huntPollTimer = null;
let geigerTickTimer = null;
let currentHuntTickMs = null;

// Ses Motoru (Web Audio API)
let audioCtx = null;

function initAudio() {
  if (!audioCtx) {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  }
}

// --- Türkçe Çeviri ve Açıklama Yardımcıları ---

const CLASS_TR = {
  PHONE: "📱 Telefon / Mobil Cihaz",
  PC: "💻 Bilgisayar",
  TRACKER: "📍 Takip Cihazı (AirTag vb.)",
  DRONE: "🛸 Drone (Hava Aracı)",
  WEARABLE: "⌚ Kulaklık / Akıllı Saat",
  SURVEILLANCE: "📹 Kamera / Gözetleme",
  ATTACK_TOOL: "🚨 Siber Saldırı Aracı",
  INFRASTRUCTURE: "📡 Modem / Wi-Fi Ağı",
  IOT: "🏠 Akıllı Ev / Sensör",
  UNKNOWN: "📻 Kablosuz Verici",
};

const HUNT_CUE_TR = {
  VERY_CLOSE: "🎯 ÇOK YAKIN! (Cihaz Hemen Yanında · <1.5m)",
  CLOSER: "🔥 YAKLAŞIYORSUN (Sinyal Güçleniyor)",
  FURTHER: "❄️ UZAKLAŞIYORSUN (Sinyal Zayıflıyor)",
  SAME: "⚖️ MESAFE SABİT (Sinyal Değişmedi)",
  WAITING: "⏳ ÖLÇÜLÜYOR (Yön Bulmak İçin Biraz Yürüyün)",
  QUIET: "🔇 SESSİZ (Son 10 Saniyedir Sinyal Gelmedi)",
  GONE: "❌ MENZİL DIŞI (Cihaz Sinyali Kesildi)",
};

function rssiToDistanceTr(rssi, estDistM) {
  if (rssi === null || rssi === undefined) return "Mesafe Bilinmiyor";
  const mStr = (estDistM !== null && estDistM !== undefined) ? `~${estDistM}m` : null;
  if (rssi >= -45) return `🟢 Çok Yakın (${mStr || "~1-2m"} · ${rssi} dBm)`;
  if (rssi >= -62) return `🟡 Yakın (${mStr || "~3-7m"} · ${rssi} dBm)`;
  if (rssi >= -76) return `🟠 Orta Mesafe (${mStr || "~8-15m"} · ${rssi} dBm)`;
  return `⚪ Uzak / Yan Daire (${mStr ? mStr + " · " : ""}${rssi} dBm)`;
}

function translateDeviceName(rawName, fleet) {
  let s = rawName || fleet || "Tanımlanmamış Kablosuz Cihaz";
  s = s
    .replace("Connected Gateway AP", "Bağlı Olduğun Modem")
    .replace("LAN Wireless Peer", "Ağdaki Kablosuz Cihaz")
    .replace("Gateway Router", "Ana Modem / Router")
    .replace("Wi-Fi AP", "Çevredeki Wi-Fi Ağı")
    .replace("Windows 10/11 Desktop", "Windows 10/11 Masaüstü Bilgisayar")
    .replace("Windows 10/11 Laptop", "Windows 10/11 Dizüstü Bilgisayar")
    .replace("Apple AirTags", "Apple AirTag / Bul Takipçisi")
    .replace("Apple Device", "Apple Cihazı (iPhone/iPad/Mac)")
    .replace("Microsoft Device", "Microsoft / Windows Cihazı");
  return s;
}

function translateRoleHint(role) {
  if (!role) return "";
  return role
    .replace("iPhone / iPad / Mac (Find My Nearby)", "Apple iPhone / iPad / Mac (Sahibinin Yanında)")
    .replace("iPhone / iPad / Mac (AirDrop)", "Apple iPhone / iPad / Mac (AirDrop Açık)")
    .replace("iPhone / iPad / Mac", "Apple iPhone / iPad / Mac")
    .replace("Apple HomeKit Accessory", "Apple HomeKit Akıllı Ev Cihazı")
    .replace("Apple Watch (Magic Switch)", "Apple Watch (Akıllı Saat)")
    .replace("Windows 10/11 Desktop", "Windows 10/11 Masaüstü PC")
    .replace("Windows 10/11 Laptop", "Windows 10/11 Dizüstü PC")
    .replace("Apple AirTag / Find My Tracker", "Apple AirTag / Kayıp Eşya Takipçisi")
    .replace("Apple Find My Tracker / AirTag", "Apple AirTag / Takip Etiketi")
    .replace("Google Find Hub Tracker", "Google Find Hub Takip Etiketi")
    .replace("Tile Bluetooth Tracker", "Tile Bluetooth Takip Etiketi")
    .replace("Samsung SmartTag Tracker", "Samsung SmartTag Takip Etiketi")
    .replace("Chipolo Bluetooth Tracker", "Chipolo Bluetooth Takip Etiketi")
    .replace("Xiaomi MiBeacon Smart Device", "Xiaomi Mi Home Akıllı Cihaz")
    .replace("SwitchBot Smart Home Device", "SwitchBot Akıllı Ev Cihazı")
    .replace("DJI Drone / Gimbal BLE", "DJI Drone / Gimbal Kumandası")
    .replace("GoPro Action Camera", "GoPro Aksiyon Kamerası")
    .replace("Govee Smart Thermo-Hygrometer", "Govee Akıllı Sıcaklık/Nem Sensörü")
    .replace("Axon Body-Worn Camera", "Axon Yaka Kamerası")
    .replace("RuuviTag Environmental Sensor", "RuuviTag Ortam Sensörü")
    .replace("Tesla Vehicle / Phone Key", "Tesla Araç / Telefon Anahtarı")
    .replace("Swift Pair Accessory", "Windows Hızlı Eşleşme Aksesuarı");
}

function translateDecodedText(txt) {
  if (!txt) return "";
  return String(txt)
    .replace("Apple Continuity State", "Apple Cihaz Durumu")
    .replace("Find My Network (0x12)", "Apple Bul Ağı")
    .replace("Find My Service (FD44)", "Apple Bul Aksesuar Servisi")
    .replace("Google Find Hub (FEAA)", "Google Cihazımı Bul Ağı")
    .replace("Tile Tracker (FEED)", "Tile Takip Etiketi")
    .replace("Samsung SmartTag (FD5A)", "Samsung SmartTag Durumu")
    .replace("Chipolo Tracker (FE65)", "Chipolo Takip Etiketi")
    .replace("Xiaomi MiBeacon (FE95)", "Xiaomi MiBeacon Paketi")
    .replace("SwitchBot (FD3D)", "SwitchBot Durumu")
    .replace("SwitchBot BLE", "SwitchBot Telemetri")
    .replace("DJI BLE", "DJI BLE Telemetri")
    .replace("Proximity Pairing", "Yakın Eşleşme (Kulaklık)")
    .replace("Microsoft CDP", "Windows Yakın Paylaşım")
    .replace("Microsoft Swift Pair", "Windows Hızlı Eşleşme")
    .replace("Google Fast Pair", "Android Hızlı Eşleşme")
    .replace("Ruuvi Telemetry", "Sensör Ölçümü")
    .replace("Govee Telemetry", "Govee Sensör Ölçümü")
    .replace("GoPro Status", "GoPro Kamera Durumu")
    .replace("Instant Hotspot", "Kişisel Erişim Noktası")
    .replace("Nearby Action", "Yakın Etkileşim")
    .replace("AirPlay target discovery", "AirPlay Hedef Yayını")
    .replace("Idle (screen locked)", "Boşta (Ekran Kilitli)")
    .replace("Active (screen on)", "Aktif Kullanımda (Ekran Açık)")
    .replace("Screen on (video playing)", "Ekran Açık (Video Oynatılıyor)")
    .replace("Audio playing (screen locked)", "Ses Çalıyor (Ekran Kilitli)")
    .replace("Active phone / FaceTime call", "Aktif Telefon / FaceTime Görüşmesinde")
    .replace("Recent user interaction", "Kısa Süre Önce Kullanıldı")
    .replace("User is driving", "Sürüş Modunda")
    .replace("Apple Watch on wrist & unlocked", "Apple Watch Bilekte ve Açık")
    .replace("Activity reporting disabled", "Etkinlik Paylaşımı Kapalı")
    .replace("Activity unknown", "Etkinlik Bilinmiyor")
    .replace("Primary iCloud device", "Birincil iCloud Cihazı")
    .replace("AirDrop receiving ON", "AirDrop Alımı Açık")
    .replace("Wi-Fi ON", "Wi-Fi Açık")
    .replace("AirPods connected", "AirPods Bağlı")
    .replace("Watch locked", "Apple Watch Kilitli")
    .replace("Separated from owner", "Sahibinden Uzakta (Yalnız)")
    .replace("Owner nearby (maintained)", "Sahibinin Yanında")
    .replace("Battery: Full", "Pil: Dolu")
    .replace("Battery: Medium", "Pil: Orta")
    .replace("Battery: Low", "Pil: Düşük")
    .replace("Battery: Critical", "Pil: Kritik")
    .replace("Windows 10/11 Desktop (Near Share / Cross-Device)", "Windows 10/11 Masaüstü PC (Yakın Paylaşım Açık)")
    .replace("Recording active", "Kayıt Yapıyor")
    .replace("Idle / Standby", "Beklemede")
    .replace("Case:", "Kutu:");
}

function playRadarPing(isThreat = false) {
  if (!audioAlertEnabled) return;
  try {
    initAudio();
    if (audioCtx.state === "suspended") audioCtx.resume();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);

    if (isThreat) {
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(880, audioCtx.currentTime);
      osc.frequency.setValueAtTime(440, audioCtx.currentTime + 0.1);
      gain.gain.setValueAtTime(0.15, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.25);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.25);
    } else {
      osc.type = "sine";
      osc.frequency.setValueAtTime(1200, audioCtx.currentTime);
      gain.gain.setValueAtTime(0.04, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.3);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.3);
    }
  } catch (e) {
    console.debug("Audio error", e);
  }
}

function playGeigerClick(proximityPct = 50) {
  if (!geigerAudioEnabled) return;
  try {
    initAudio();
    if (audioCtx.state === "suspended") audioCtx.resume();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);

    osc.type = "square";
    const freq = 900 + (proximityPct / 100) * 1400;
    osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
    gain.gain.setValueAtTime(0.12, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.028);
    osc.start();
    osc.stop(audioCtx.currentTime + 0.03);
  } catch (e) {
    console.debug("Geiger click error", e);
  }
}

// WebSocket Bağlantısı
function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    document.getElementById("wsStatusDot").style.backgroundColor = "var(--accent-color)";
    document.getElementById("wsStatusText").textContent = "CANLI TARAMA AKTİF";
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleMessage(msg);
    } catch (e) {
      console.error("WS mesaj hatası", e);
    }
  };

  ws.onclose = () => {
    document.getElementById("wsStatusDot").style.backgroundColor = "var(--danger-color)";
    document.getElementById("wsStatusText").textContent = "YENİDEN BAĞLANIYOR...";
    setTimeout(connectWebSocket, 2000);
  };
}

let uiRefreshTimer = null;

function scheduleUiRefresh() {
  if (uiRefreshTimer) return;
  uiRefreshTimer = setTimeout(() => {
    uiRefreshTimer = null;
    pruneStaleDevices();
    updateTargetList();
    updateHuntDropdown();
    updateMetricsCount();
  }, 750);
}

function pruneStaleDevices() {
  const nowMs = Date.now();
  devicesMap.forEach((d, key) => {
    if (d.is_bookmarked || d.is_trusted || d.is_threat) return;
    if (d.last_seen) {
      const ageSec = (nowMs - new Date(d.last_seen).getTime()) / 1000.0;
      if (ageSec > 180) {
        devicesMap.delete(key);
      }
    }
  });
}

setInterval(() => {
  pruneStaleDevices();
  updateMetricsCount();
}, 10000);

function updateSentryUi(isActive) {
  const btn = document.getElementById("btnSentryMode");
  if (!btn) return;
  btn.classList.toggle("active", Boolean(isActive));
  btn.style.borderColor = isActive ? "var(--danger-color)" : "";
  btn.style.color = isActive ? "var(--danger-color)" : "";
  btn.textContent = isActive ? "🛡️ Bekçi Modu: AÇIK (Nöbette)" : "🛡️ Bekçi Modu: KAPALI";
}

function handleMessage(msg) {
  if (msg.type === "INITIAL_STATE") {
    const { stats, sentry_mode, alerts, devices } = msg.data;
    devicesMap.clear();
    updateStats(stats);
    if (sentry_mode !== undefined) updateSentryUi(sentry_mode);
    (devices || []).forEach((d) => devicesMap.set(d.mac_or_uuid, d));
    alertsList = alerts || [];
    renderAllViews();
  } else if (msg.type === "SENTRY_STATE") {
    updateSentryUi(msg.data.sentry_mode);
  } else if (msg.type === "OBSERVATION") {
    const dev = msg.data;
    const isNew = !devicesMap.has(dev.mac_or_uuid);
    devicesMap.set(dev.mac_or_uuid, dev);
    if (dev.device_class === "DRONE") renderDronesView();
    if (isNew && (dev.device_class === "DRONE" || dev.device_class === "TRACKER")) {
      playRadarPing(dev.is_threat);
    }
    scheduleUiRefresh();
  } else if (msg.type === "ALERT") {
    const alert = msg.data;
    alertsList.unshift(alert);
    if (alertsList.length > 100) alertsList.pop();
    renderAlerts();
    playRadarPing(true);
    if (alert.level === "CRITICAL" || alert.level === "HIGH") {
      speakTurkishAlert(translateAlertTitle(alert.title));
    }
    updateMetricsCount();
  }
}

// Radar Canvas Çizici
const canvas = document.getElementById("radarCanvas");
const ctx = canvas.getContext("2d");
let radarAngle = 0;

function resizeCanvas() {
  const size = Math.min(canvas.parentElement.clientWidth - 40, 520);
  canvas.width = size;
  canvas.height = size;
}
window.addEventListener("resize", resizeCanvas);

function drawRadar() {
  const w = canvas.width;
  const h = canvas.height;
  const cx = w / 2;
  const cy = h / 2;
  const radius = cx - 10;

  ctx.fillStyle = nightMode ? "rgba(10, 3, 4, 0.12)" : "rgba(8, 11, 17, 0.12)";
  ctx.fillRect(0, 0, w, h);

  const rings = [0.25, 0.5, 0.75, 1.0];
  ctx.strokeStyle = nightMode ? "rgba(255, 51, 68, 0.2)" : "rgba(13, 240, 138, 0.2)";
  ctx.lineWidth = 1;

  rings.forEach((rRatio) => {
    ctx.beginPath();
    ctx.arc(cx, cy, radius * rRatio, 0, Math.PI * 2);
    ctx.stroke();
  });

  ctx.beginPath();
  ctx.moveTo(cx, cy - radius);
  ctx.lineTo(cx, cy + radius);
  ctx.moveTo(cx - radius, cy);
  ctx.lineTo(cx + radius, cy);
  ctx.stroke();

  radarAngle = (radarAngle + 0.025) % (Math.PI * 2);

  ctx.save();
  ctx.translate(cx, cy);
  ctx.rotate(radarAngle);

  const grad = ctx.createLinearGradient(0, 0, radius, 0);
  const accentRGB = nightMode ? "255, 51, 68" : "13, 240, 138";
  grad.addColorStop(0, `rgba(${accentRGB}, 0.6)`);
  grad.addColorStop(1, `rgba(${accentRGB}, 0.0)`);

  ctx.beginPath();
  ctx.moveTo(0, 0);
  ctx.arc(0, 0, radius, -0.4, 0);
  ctx.fillStyle = grad;
  ctx.fill();

  ctx.beginPath();
  ctx.moveTo(0, 0);
  ctx.lineTo(radius, 0);
  ctx.strokeStyle = `rgb(${accentRGB})`;
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.restore();

  const now = Date.now();

  devicesMap.forEach((dev) => {
    const rssi = Math.max(-95, Math.min(-30, dev.last_rssi));
    const distRatio = (rssi - (-30)) / (-95 - (-30));
    const dDist = Math.max(0.12, Math.min(0.95, distRatio)) * radius;

    let macHash = 0;
    for (let i = 0; i < dev.mac_or_uuid.length; i++) {
      macHash = (macHash * 31 + dev.mac_or_uuid.charCodeAt(i)) % 10000;
    }
    const angle = (macHash / 10000.0) * Math.PI * 2;

    const bx = cx + Math.cos(angle) * dDist;
    const by = cy + Math.sin(angle) * dDist;

    let blipColor = nightMode ? "#ff6677" : "#0df08a";
    let blipRadius = 4;

    if (dev.device_class === "DRONE") {
      blipColor = "#00d2ff";
      blipRadius = 6;
    } else if (dev.device_class === "TRACKER") {
      blipColor = "#ffaa00";
      blipRadius = 5;
    } else if (dev.is_threat || dev.device_class === "ATTACK_TOOL") {
      blipColor = "#ff3355";
      blipRadius = 7;
    }

    ctx.beginPath();
    ctx.arc(bx, by, blipRadius, 0, Math.PI * 2);
    ctx.fillStyle = blipColor;
    ctx.shadowColor = blipColor;
    ctx.shadowBlur = 10;
    ctx.fill();
    ctx.shadowBlur = 0;

    if (dev.is_threat || dev.device_class === "DRONE" || dev.mac_or_uuid === huntTargetMac) {
      const pulse = (now / 400) % 2;
      ctx.beginPath();
      ctx.arc(bx, by, blipRadius + pulse * 6, 0, Math.PI * 2);
      ctx.strokeStyle = blipColor;
      ctx.lineWidth = 1;
      ctx.stroke();
    }
  });

  requestAnimationFrame(drawRadar);
}

// Görünümleri Güncelle
function renderAllViews() {
  updateMetricsCount();
  updateTargetList();
  updateHuntDropdown();
  renderDronesView();
  renderAlerts();
}

function updateMetricsCount() {
  let drones = 0;
  let trackers = 0;
  let threats = 0;
  let trusted = 0;

  devicesMap.forEach((d) => {
    if (d.device_class === "DRONE") drones++;
    if (d.device_class === "TRACKER") trackers++;
    if (d.is_threat) threats++;
    if (d.is_trusted) trusted++;
  });

  const unackedAlerts = alertsList.filter((a) => !a.acknowledged).length;
  document.getElementById("metricTotal").textContent = devicesMap.size;
  document.getElementById("metricDrones").textContent = drones;
  document.getElementById("metricTrackers").textContent = trackers;
  document.getElementById("metricThreats").textContent = threats + unackedAlerts;
  const trBadge = document.getElementById("trustedCountBadge");
  if (trBadge) trBadge.textContent = `${trusted} CİHAZ`;
}

function updateStats(stats) {
  if (!stats) return;
  document.getElementById("metricTotal").textContent = stats.total_devices || 0;
  document.getElementById("metricDrones").textContent = stats.drones_count || 0;
  document.getElementById("metricTrackers").textContent = stats.trackers_count || 0;
  document.getElementById("metricThreats").textContent = (stats.threats_count || 0) + (stats.alerts_count || 0);
  const trBadge = document.getElementById("trustedCountBadge");
  if (trBadge && stats.trusted_count !== undefined) trBadge.textContent = `${stats.trusted_count} CİHAZ`;
}

function escapeHtml(s) {
  if (!s) return "";
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function updateTargetList() {
  const container = document.getElementById("radarTargetsList");
  const spectrumContainer = document.getElementById("spectrumList");
  if (!container && !spectrumContainer) return;

  const filter = document.getElementById("classFilter") ? document.getElementById("classFilter").value : "ALL";
  const searchVal = (document.getElementById("searchInput") ? document.getElementById("searchInput").value : "").trim().toLowerCase();
  const sorted = Array.from(devicesMap.values()).sort((a, b) => b.last_rssi - a.last_rssi);

  const renderCard = (dev) => {
    const rScore = dev.risk_score || 0;
    const isThreatClass = (dev.is_threat || rScore >= 70) ? "threat" : "";
    const bookmarkStar = dev.is_bookmarked ? "★ " : "";
    const trustedIcon = dev.is_trusted ? "🏠 " : "";
    const nameStr = escapeHtml(translateDeviceName(dev.name, dev.matched_fleet));
    const classTr = CLASS_TR[dev.device_class] || dev.device_class;
    const distTr = rssiToDistanceTr(dev.last_rssi, dev.estimated_distance_m);
    const roleTr = translateRoleHint(dev.role_hint);

    const trustPill = dev.is_trusted ? `<span class="role-pill" style="background:rgba(13,240,138,0.18); border-color:var(--accent-color);">🏠 Ev Halkı (Güvenli)</span>` : "";
    let riskPill = "";
    if (!dev.is_trusted && rScore >= 70) {
      riskPill = `<span class="role-pill" style="background:rgba(255,51,85,0.22); border-color:var(--danger-color); color:#ff7788;">🚨 Risk: ${rScore}/100</span>`;
    } else if (!dev.is_trusted && rScore >= 30) {
      riskPill = `<span class="role-pill" style="background:rgba(255,170,0,0.18); border-color:var(--warning-color); color:#ffcc44;">⚠️ Risk: ${rScore}/100</span>`;
    }
    const mobPill = dev.mobility_profile ? `<span class="decoded-pill">${escapeHtml(dev.mobility_profile)}</span>` : "";
    const rolePill = roleTr ? `<span class="role-pill">${escapeHtml(roleTr)}</span>` : "";
    const decodedPills = (dev.decoded_fields || [])
      .slice(0, 3)
      .map((f) => {
        const rawTxt = typeof f === "object" ? `${f.label}: ${f.value}` : f;
        return `<span class="decoded-pill">${escapeHtml(translateDecodedText(rawTxt))}</span>`;
      })
      .join("");
    const pillsRow = (trustPill || riskPill || mobPill || rolePill || decodedPills)
      ? `<div class="dev-decoded-pills">${trustPill}${riskPill}${mobPill}${rolePill}${decodedPills}</div>`
      : "";

    return `
      <div class="device-card ${isThreatClass}" onclick="openDeviceModal('${escapeHtml(dev.mac_or_uuid)}')">
        <div class="dev-top">
          <span class="dev-name">${trustedIcon}${bookmarkStar}${nameStr}</span>
          <span class="dev-rssi">${distTr}</span>
        </div>
        <div class="dev-bottom">
          <span>${dev.radio === "BLE" ? "Bluetooth" : "Wi-Fi"} · ${classTr}${dev.channel_or_freq ? " · " + escapeHtml(dev.channel_or_freq) : ""}</span>
          <span>Kimlik: ${escapeHtml(dev.mac_or_uuid.substring(0, 17))}</span>
        </div>
        ${pillsRow}
      </div>
    `;
  };

  if (container) {
    container.innerHTML = sorted.slice(0, 25).map(renderCard).join("");
  }
  if (spectrumContainer) {
    const filtered = sorted.filter((d) => {
      if (filter === "HIGH_RISK" && !d.is_threat && (d.risk_score || 0) < 30) return false;
      if (filter === "STATIONARY" && !(d.mobility_profile && d.mobility_profile.includes("Sabit"))) return false;
      if (filter === "TRUSTED" && !d.is_trusted) return false;
      if (filter === "UNTRUSTED" && d.is_trusted) return false;
      if (filter === "BOOKMARKED" && !d.is_bookmarked) return false;
      if (!["ALL", "HIGH_RISK", "STATIONARY", "TRUSTED", "UNTRUSTED", "BOOKMARKED"].includes(filter) && d.device_class !== filter) return false;
      if (searchVal) {
        const nameTr = translateDeviceName(d.name, d.matched_fleet).toLowerCase();
        const roleTr = translateRoleHint(d.role_hint).toLowerCase();
        const macLow = (d.mac_or_uuid || "").toLowerCase();
        const chanLow = (d.channel_or_freq || "").toLowerCase();
        const mobLow = (d.mobility_profile || "").toLowerCase();
        const decLow = (d.decoded_fields || []).map((f) => translateDecodedText(typeof f === "object" ? `${f.label} ${f.value}` : f)).join(" ").toLowerCase();
        if (!nameTr.includes(searchVal) && !roleTr.includes(searchVal) && !macLow.includes(searchVal) && !chanLow.includes(searchVal) && !mobLow.includes(searchVal) && !decLow.includes(searchVal)) {
          return false;
        }
      }
      return true;
    });
    spectrumContainer.innerHTML = filtered.length > 0
      ? filtered.map(renderCard).join("")
      : `<div style="color:var(--text-muted); padding:20px; font-family:var(--font-mono);">Seçilen filtreye uygun cihaz bulunamadı.</div>`;
  }
}

// Cihaz Kimlik ve Adli İnceleme Penceresi (Modal)
async function openDeviceModal(mac) {
  selectedModalMac = mac;
  const modal = document.getElementById("deviceModal");
  const title = document.getElementById("modalTitle");
  const subtitle = document.getElementById("modalSubtitle");
  const body = document.getElementById("modalBody");
  modal.style.display = "flex";
  title.textContent = mac;
  subtitle.textContent = "Cihaz kimlik ve sinyal paketleri çözümleniyor...";
  body.innerHTML = "Veritabanından geçmiş kayıtlar okunuyor...";

  try {
    const res = await fetch(`/api/devices/${encodeURIComponent(mac)}`);
    const data = await res.json();
    const d = data.device;
    const sightings = data.sightings || [];
    const hunt = data.hunt || {};

    title.textContent = translateDeviceName(d.name, d.matched_fleet);
    const classTr = CLASS_TR[d.device_class] || d.device_class;
    subtitle.textContent = `${d.radio === "BLE" ? "Bluetooth LE" : "Wi-Fi"} · ${classTr} · Kimlik: ${d.mac_or_uuid}`;

    const btnBm = document.getElementById("btnModalBookmark");
    btnBm.textContent = d.is_bookmarked ? "★ İzleme Listesinde (Çıkar)" : "☆ İzlemeye Al (Favori)";

    const btnTr = document.getElementById("btnModalTrust");
    if (btnTr) {
      btnTr.textContent = d.is_trusted ? "🏠 Ev Halkı Listesinde (Çıkar)" : "🏠 Ev Halkı (Güvenli) Yap";
      btnTr.classList.toggle("active", Boolean(d.is_trusted));
    }

    const btnGatt = document.getElementById("btnModalGatt");
    if (btnGatt) {
      btnGatt.style.display = d.radio === "BLE" ? "inline-flex" : "none";
      btnGatt.textContent = "🔍 İçini Sorgula (GATT Model/Pil Oku)";
    }

    const decodedHtml = (d.decoded_fields && d.decoded_fields.length > 0)
      ? d.decoded_fields.map((f) => {
          const rawTxt = typeof f === "object" ? `${f.label}: ${f.value}` : f;
          return `<span class="decoded-pill">${escapeHtml(translateDecodedText(rawTxt))}</span>`;
        }).join(" ")
      : `<span style="color:var(--text-muted);">Bu cihaz özel bir durum bilgisi yayınlamıyor. Bluetooth ise aşağıdaki <strong>'🔍 İçini Sorgula (GATT)'</strong> butonuna basarak içinden marka/model okuyabilirsiniz.</span>`;

    const sightingsHtml = sightings.slice(0, 8).map((s) =>
      `<div>[${new Date(s.timestamp).toLocaleTimeString()}] Sinyal: <strong>${rssiToDistanceTr(s.rssi)}</strong></div>`
    ).join("");

    const cueTr = HUNT_CUE_TR[hunt.cue] || hunt.cue || "Bekleniyor";
    const trustStatusHtml = d.is_trusted
      ? `<span style="color:var(--accent-color); font-weight:700;">🏠 Evet — Ev Halkı (Güvenli Cihaz)</span>`
      : `<span style="color:var(--warning-color);">❓ Hayır — Tanınmayan / Dış Cihaz</span>`;

    const rScore = d.risk_score || 0;
    const rReasons = (d.risk_reasons && d.risk_reasons.length > 0)
      ? d.risk_reasons.map((r) => escapeHtml(r)).join(" · ")
      : "Şüpheli bir sinyal veya port tespit edilmedi";
    const rColor = rScore >= 70 ? "var(--danger-color)" : (rScore >= 30 ? "var(--warning-color)" : "var(--accent-color)");

    body.innerHTML = `
      <div class="guide-banner" style="margin-bottom:8px;">
        <strong>📌 Bu Cihaz Nedir?</strong><br>
        Bu kart, seçtiğin cihazın kimlik bilgisini, risk puanını, sabit/hareketli profilini, sana olan metre cinsinden uzaklığını ve çözümlenmiş paketlerini gösterir.
      </div>
      <div><strong>Ev Halkı (Güvenli Liste) Durumu:</strong> ${trustStatusHtml}</div>
      <div><strong>Çok Faktörlü Risk Puanı:</strong> <strong style="color:${rColor};">${rScore} / 100</strong> (${rReasons})</div>
      <div><strong>Fiziksel Hareketlilik Profili:</strong> ${escapeHtml(d.mobility_profile || "⏳ Ölçülüyor (En az 4 sinyal örneği bekleniyor)")}</div>
      <div><strong>Marka / Kategori Eşleşmesi:</strong> ${escapeHtml((d.all_fleets && d.all_fleets.join(", ")) || d.matched_fleet || "Standart Cihaz")}</div>
      <div><strong>Cihazın Rolü / Tipi:</strong> ${escapeHtml(translateRoleHint(d.role_hint) || classTr)}</div>
      <div><strong>Tahmini Mesafe ve Sinyal Gücü:</strong> ${rssiToDistanceTr(d.last_rssi, d.estimated_distance_m)} | Ortalama: ${d.avg_rssi} dBm | Görülme Sayısı: ${d.hit_count} kez</div>
      <div><strong>Yön Bulucu Durumu:</strong> ${escapeHtml(cueTr)} (Yakınlık: %${hunt.proximity_pct || 0})</div>
      <div><strong>Çözümlenen Canlı Durum, IE ve GATT Bilgileri:</strong><div class="dev-decoded-pills" style="margin-top:6px;" id="modalDecodedPills">${decodedHtml}</div></div>
      <div id="modalGattStatus" style="display:none; padding:8px; border:1px solid var(--border-color); border-radius:6px; font-size:0.8rem;"></div>
      <div><strong>Son Sinyal Geçmişi (Zaman Çizelgesi):</strong><div style="margin-top:4px; color:var(--text-muted);">${sightingsHtml}</div></div>
    `;
  } catch (e) {
    body.innerHTML = `İnceleme verisi yüklenemedi: ${e}`;
  }
}

function closeDeviceModal() {
  document.getElementById("deviceModal").style.display = "none";
  selectedModalMac = null;
}

async function toggleModalBookmark() {
  if (!selectedModalMac) return;
  const res = await fetch(`/api/devices/${encodeURIComponent(selectedModalMac)}/bookmark`, { method: "POST" });
  const data = await res.json();
  const dev = devicesMap.get(selectedModalMac);
  if (dev) dev.is_bookmarked = data.is_bookmarked;
  document.getElementById("btnModalBookmark").textContent = data.is_bookmarked
    ? "★ İzleme Listesinde (Çıkar)"
    : "☆ İzlemeye Al (Favori)";
  updateTargetList();
}

async function toggleModalTrust() {
  if (!selectedModalMac) return;
  const res = await fetch(`/api/devices/${encodeURIComponent(selectedModalMac)}/trust`, { method: "POST" });
  const data = await res.json();
  const dev = devicesMap.get(selectedModalMac);
  if (dev) {
    dev.is_trusted = data.is_trusted;
    if (data.is_trusted) dev.is_threat = false;
  }
  await openDeviceModal(selectedModalMac);
  updateTargetList();
  updateMetricsCount();
}

async function inspectModalGatt() {
  if (!selectedModalMac) return;
  const statusEl = document.getElementById("modalGattStatus");
  const btn = document.getElementById("btnModalGatt");
  if (statusEl) {
    statusEl.style.display = "block";
    statusEl.innerHTML = "⏳ Mac mini Bluetooth üzerinden cihaza bağlanıyor ve GATT iç kayıtlarını (Marka/Model/Pil) okuyor...";
  }
  if (btn) btn.textContent = "⏳ Sorgulanıyor...";

  try {
    const res = await fetch(`/api/devices/${encodeURIComponent(selectedModalMac)}/gatt`, { method: "POST" });
    const data = await res.json();
    if (data.connected) {
      if (data.device) {
        devicesMap.set(selectedModalMac, data.device);
      }
      await openDeviceModal(selectedModalMac);
      const refreshedStatus = document.getElementById("modalGattStatus");
      if (refreshedStatus) {
        refreshedStatus.style.display = "block";
        refreshedStatus.style.borderColor = "var(--accent-color)";
        const summaryParts = [
          data.manufacturer ? `Üretici: <strong>${escapeHtml(data.manufacturer)}</strong>` : "",
          data.model ? `Model: <strong>${escapeHtml(data.model)}</strong>` : "",
          data.battery_pct !== null && data.battery_pct !== undefined ? `Pil: <strong>%${data.battery_pct}</strong>` : "",
          data.services && data.services.length ? `Servisler: ${escapeHtml(data.services.join(", "))}` : "",
        ].filter(Boolean);
        refreshedStatus.innerHTML = `✅ <strong>GATT Bağlantısı Başarılı!</strong> ${summaryParts.join(" · ") || "Cihaz servisleri okundu."}`;
      }
      updateTargetList();
    } else {
      if (statusEl) {
        statusEl.style.borderColor = "var(--warning-color)";
        statusEl.innerHTML = `ℹ️ ${escapeHtml(data.error || "Cihaza bağlanılamadı.")}`;
      }
      if (btn) btn.textContent = "🔍 İçini Sorgula (GATT Model/Pil Oku)";
    }
  } catch (e) {
    if (statusEl) statusEl.innerHTML = `Hata: ${e}`;
    if (btn) btn.textContent = "🔍 İçini Sorgula (GATT Model/Pil Oku)";
  }
}

function launchHuntFromModal() {
  if (!selectedModalMac) return;
  const target = selectedModalMac;
  closeDeviceModal();
  switchTab("hunt");
  const sel = document.getElementById("huntTargetSelect");
  updateHuntDropdown();
  sel.value = target;
  startHuntPolling(target);
}

// Sinyal Avcısı (Geiger Sayacı) Modu
function updateHuntDropdown(force = false) {
  const sel = document.getElementById("huntTargetSelect");
  if (!sel) return;
  if (!force && document.activeElement === sel) return;
  const currentVal = sel.value || huntTargetMac;
  const sorted = Array.from(devicesMap.values()).sort((a, b) => b.last_rssi - a.last_rssi);

  sel.innerHTML = `<option value="">-- Yerini Bulmak İstediğiniz Cihazı Seçin (${sorted.length} aktif cihaz) --</option>` +
    sorted.map((d) => {
      const label = translateDeviceName(d.name, d.matched_fleet);
      const selAttr = d.mac_or_uuid === currentVal ? "selected" : "";
      return `<option value="${escapeHtml(d.mac_or_uuid)}" ${selAttr}>[${d.last_rssi} dBm] ${escapeHtml(label)} (${escapeHtml(d.mac_or_uuid.substring(0, 12))})</option>`;
    }).join("");
}

function startHuntPolling(mac) {
  huntTargetMac = mac;
  if (huntPollTimer) clearInterval(huntPollTimer);
  if (!mac) {
    document.getElementById("huntTargetLabel").textContent = "Henüz Hedef Seçilmedi (Yukarıdan Seçin)";
    return;
  }
  pollHuntTelemetry();
  huntPollTimer = setInterval(pollHuntTelemetry, 700);
}

async function pollHuntTelemetry() {
  if (!huntTargetMac) return;
  try {
    const res = await fetch(`/api/hunt/${encodeURIComponent(huntTargetMac)}`);
    const data = await res.json();
    const h = data.hunt;
    const d = data.device;
    const label = d ? translateDeviceName(d.name, d.matched_fleet) : huntTargetMac;

    document.getElementById("huntTargetLabel").textContent = `${label} (${huntTargetMac.substring(0, 17)})`;
    document.getElementById("huntCueBadge").textContent = HUNT_CUE_TR[h.cue] || h.cue;
    document.getElementById("huntGaugeBar").style.width = `${h.proximity_pct || 0}%`;
    const rssiVal = h.recent_avg_dbm !== null && h.recent_avg_dbm !== undefined ? h.recent_avg_dbm : h.last_rssi;
    document.getElementById("huntSmoothedRssi").textContent = rssiVal !== null && rssiVal !== undefined ? `${rssiVal} dBm` : "-- dBm";
    document.getElementById("huntProximityPct").textContent = `${h.proximity_pct || 0}%`;
    const dVal = h.delta_db !== null && h.delta_db !== undefined ? h.delta_db : 0.0;
    document.getElementById("huntDeltaDb").textContent = `${dVal > 0 ? "+" : ""}${dVal} dB`;
    document.getElementById("huntTickMs").textContent = h.tick_ms ? `${h.tick_ms} ms` : "SESSİZ";

    currentHuntTickMs = h.tick_ms;
    scheduleGeigerLoop(h.tick_ms, h.proximity_pct || 0);
  } catch (e) {
    console.debug("Hunt poll error", e);
  }
}

function scheduleGeigerLoop(tickMs, proximityPct) {
  if (geigerTickTimer) {
    clearTimeout(geigerTickTimer);
    geigerTickTimer = null;
  }
  if (!geigerAudioEnabled || !tickMs) return;

  const loop = () => {
    if (!geigerAudioEnabled || !currentHuntTickMs) return;
    playGeigerClick(proximityPct);
    geigerTickTimer = setTimeout(loop, currentHuntTickMs);
  };
  geigerTickTimer = setTimeout(loop, Math.min(tickMs, 350));
}

function toggleGeigerAudio() {
  geigerAudioEnabled = !geigerAudioEnabled;
  const btn = document.getElementById("btnGeigerAudio");
  btn.classList.toggle("active", geigerAudioEnabled);
  btn.textContent = geigerAudioEnabled ? "🔊 Geiger Sesi: AÇIK (Ötüyor)" : "🔊 Geiger Sesi: KAPALI";
  if (geigerAudioEnabled && currentHuntTickMs) {
    scheduleGeigerLoop(currentHuntTickMs, 60);
  }
}

// Ortam Karşılaştırma (Sits & SitDiff)
async function loadSits() {
  try {
    const res = await fetch("/api/sits");
    const sits = await res.json();
    const listEl = document.getElementById("sitsListContainer");
    const baseSel = document.getElementById("sitBaseSelect");
    const targetSel = document.getElementById("sitTargetSelect");

    if (sits.length === 0) {
      listEl.innerHTML = `<div style="color:var(--text-muted); font-family:var(--font-mono); font-size:0.84rem; padding:10px 0;">Henüz alınmış bir ortam kaydı yok. Yukarıdaki <strong>'📸 Yeni Ortam Kaydı Al'</strong> butonuna basarak şu an odadaki tüm cihazların listesini kaydedebilirsin.</div>`;
      return;
    }

    listEl.innerHTML = sits.map((s) => `
      <div class="device-card" style="cursor:default; margin-bottom:8px;">
        <div class="dev-top">
          <span class="dev-name">Kayıt #${s.id}: ${escapeHtml(s.name)}</span>
          <span>
            ${!s.is_active
              ? `<span class="badge">TAMAMLANDI · ${s.device_count} CİHAZ KAYDEDİLDİ</span>`
              : `<button class="btn active" onclick="stopSit(${s.id})">⏹ Kaydı Bitir ve Mühürle (#${s.id})</button>`}
          </span>
        </div>
        <div class="dev-bottom">
          <span>Başlangıç: ${new Date(s.start_time).toLocaleTimeString()}</span>
          <span>${s.end_time ? "Bitiş: " + new Date(s.end_time).toLocaleTimeString() : "ŞU AN KAYIT AÇIK..."}</span>
        </div>
      </div>
    `).join("");

    const opts = sits.map((s) => `<option value="${s.id}">Kayıt #${s.id} (${escapeHtml(s.name)} - ${s.device_count} cihaz)</option>`).join("");
    baseSel.innerHTML = opts;
    targetSel.innerHTML = opts;
    if (sits.length >= 2) {
      baseSel.value = sits[1].id;
      targetSel.value = sits[0].id;
    }
  } catch (e) {
    console.error("Sits yükleme hatası", e);
  }
}

async function startSit() {
  const input = document.getElementById("sitLabelInput");
  const label = (input && input.value.trim()) ? input.value.trim() : `Ortam Kaydı (${new Date().toLocaleTimeString()})`;
  await fetch("/api/sits/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label }),
  });
  if (input) input.value = "";
  await loadSits();
}

async function stopSit(sitId) {
  await fetch(`/api/sits/${sitId}/stop`, { method: "POST" });
  await loadSits();
}

async function compareSits() {
  const baseId = document.getElementById("sitBaseSelect").value;
  const targetId = document.getElementById("sitTargetSelect").value;
  const out = document.getElementById("sitDiffOutput");
  if (!baseId || !targetId) return;

  const res = await fetch(`/api/sits/diff?base_id=${baseId}&target_id=${targetId}`);
  const diff = await res.json();
  const fmtDev = (d) => `• ${escapeHtml(translateDeviceName(d.name, d.matched_fleet))} (${escapeHtml(d.mac_or_uuid.substring(0, 14))})`;

  out.innerHTML = `
    <div class="metrics-grid" style="margin-top:12px;">
      <div class="metric-card">
        <span class="metric-title">🚨 ORTAMA YENİ GİREN YABANCI CİHAZLAR</span>
        <span class="metric-val threat">${diff.new_count}</span>
        <span class="metric-sub">1. kayıtta olmayıp 2. kayıtta ortama yeni giren cihazlar</span>
        <div style="font-family:var(--font-mono); font-size:0.76rem; color:var(--text-primary); margin-top:8px;">
          ${(diff.new_devices || []).slice(0, 12).map(fmtDev).join("<br>") || "Yeni giren cihaz yok"}
        </div>
      </div>
      <div class="metric-card">
        <span class="metric-title">📤 ORTAMDAN AYRILAN CİHAZLAR</span>
        <span class="metric-val" style="color:var(--warning-color);">${diff.gone_count}</span>
        <span class="metric-sub">1. kayıtta ortamda olup sonradan uzaklaşan/kapanan cihazlar</span>
        <div style="font-family:var(--font-mono); font-size:0.76rem; color:var(--text-primary); margin-top:8px;">
          ${(diff.gone_devices || []).slice(0, 12).map(fmtDev).join("<br>") || "Ayrılan cihaz yok"}
        </div>
      </div>
      <div class="metric-card">
        <span class="metric-title">✅ SABİT KALAN (EVDEKİ) CİHAZLAR</span>
        <span class="metric-val" style="color:var(--accent-color);">${diff.stayed_count}</span>
        <span class="metric-sub">Her iki kayıtta da ortamda bulunan tanıdık cihazlar</span>
        <div style="font-family:var(--font-mono); font-size:0.76rem; color:var(--text-primary); margin-top:8px;">
          ${(diff.stayed_devices || []).slice(0, 12).map(fmtDev).join("<br>") || "Sabit cihaz yok"}
        </div>
      </div>
    </div>
  `;
}

function renderDronesView() {
  const container = document.getElementById("dronesList");
  if (!container) return;

  const drones = Array.from(devicesMap.values()).filter((d) => d.device_class === "DRONE");

  if (drones.length === 0) {
    container.innerHTML = `<div style="color: var(--text-muted); padding: 20px; font-family: var(--font-mono);">✅ Hava sahası temiz. Şu an çevrede Drone Remote ID sinyali algılanmadı.</div>`;
    return;
  }

  container.innerHTML = drones
    .map((d) => {
      const info = d.drone_info || {};
      return `
      <div class="drone-card" onclick="openDeviceModal('${escapeHtml(d.mac_or_uuid)}')" style="cursor:pointer;">
        <div class="drone-header">
          <span style="font-weight:700; color:var(--info-color);">🛸 ${escapeHtml(info.manufacturer || info.model_name || "İHA")} Drone</span>
          <span class="badge" style="border-color:var(--info-color);">${escapeHtml(info.status === "Airborne" ? "HAVADA UÇUYOR" : (info.status || "Uçuşta"))}</span>
        </div>
        <div style="font-size:0.8rem; font-family:var(--font-mono); color:var(--text-muted);">Seri Numarası (CTA-2063): ${escapeHtml(info.uas_id || d.mac_or_uuid)}</div>
        <div class="drone-telemetry-row">
          <div>
            <div class="telemetry-val">${info.altitude_m !== null && info.altitude_m !== undefined ? info.altitude_m + " m" : "--"}</div>
            <div class="telemetry-lbl">YÜKSEKLİK</div>
          </div>
          <div>
            <div class="telemetry-val">${info.speed_mps !== null && info.speed_mps !== undefined ? info.speed_mps + " m/sn" : "--"}</div>
            <div class="telemetry-lbl">UÇUŞ HIZI</div>
          </div>
          <div>
            <div class="telemetry-val">${info.heading_deg !== null && info.heading_deg !== undefined ? info.heading_deg + "°" : "--"}</div>
            <div class="telemetry-lbl">YÖN AÇISI</div>
          </div>
        </div>
        <div style="font-size:0.76rem; font-family:var(--font-mono); color:var(--text-muted);">
          📍 Drone GPS Konumu: ${info.aircraft_lat || "0.0"}, ${info.aircraft_lon || "0.0"}<br>
          🧑 Pilotun Yerdeki Konumu: ${info.pilot_lat || "0.0"}, ${info.pilot_lon || "0.0"}
        </div>
      </div>
    `;
    })
    .join("");
}

function translateAlertTitle(title) {
  if (!title) return "";
  return title
    .replace("Persistent Tracker Detected (Possible Stalker / Co-Travel)", "Israrcı Takip Cihazı Tespit Edildi (Olası Gizli Takip / AirTag)")
    .replace("Bluetooth Pairing Flood Attack Detected", "Bluetooth Eşleşme Saldırısı Tespit Edildi (Flipper Zero / Spam)")
    .replace("Wi-Fi Beacon Flood Detected", "Sahte Wi-Fi Ağ Yağmuru Saldırısı Tespit Edildi")
    .replace("Unmanned Aircraft Detected", "Hava Sahasında Drone (İHA) Tespit Edildi");
}

function translateAlertDesc(desc) {
  if (!desc) return "";
  return desc
    .replace(/A (.+) \((.+)\) has been detected continuously in close proximity \(avg signal (.+) dBm\) over the past (.+) minutes\./,
      "Yakın çevrede bir $1 ($2) cihazı son $4 dakikadır kesintisiz olarak (ortalama $3 dBm sinyal gücüyle) algılanıyor.")
    .replace(/Detected (\d+) distinct BLE addresses advertising (.+) within (.+)s \(median (.+) dBm\)\. Characteristic of Flipper Zero or ESP32 BLE spam tools\./,
      "$3 saniye içinde $1 farklı sahte Bluetooth adresinden ($2) eşleşme saldırısı algılandı (Ortalama: $4 dBm). Flipper Zero veya ESP32 saldırı cihazı belirtisi.")
    .replace(/Drone Remote ID broadcast detected \((.+)\)(.*)\./,
      "Drone Remote ID uçuş yayını yakalandı (Seri No: $1)$2.");
}

function renderAlerts() {
  const container = document.getElementById("alertsList");
  if (!container) return;

  if (alertsList.length === 0) {
    container.innerHTML = `<div style="color: var(--text-muted); padding: 20px; font-family: var(--font-mono);">✅ Aktif güvenlik uyarısı yok. Kablosuz ortam güvenli.</div>`;
    return;
  }

  container.innerHTML = alertsList
    .map(
      (a) => `
    <div class="alert-entry ${a.level}" style="${a.acknowledged ? "opacity:0.55;" : ""}">
      <div class="alert-head">
        <span>[${a.level === "HIGH" || a.level === "CRITICAL" ? "YÜKSEK TEHDİT" : a.level}] ${escapeHtml(translateAlertTitle(a.title))}</span>
        <div style="display:flex; gap:8px; align-items:center;">
          <span style="font-size:0.72rem; color:var(--text-muted); font-family:var(--font-mono);">${new Date(a.timestamp).toLocaleTimeString()}</span>
          ${!a.acknowledged && a.id ? `<button class="btn" style="padding:2px 8px; font-size:0.7rem;" onclick="ackAlert(${a.id})">✓ Okundu</button>` : `<span style="font-size:0.7rem; color:var(--text-muted);">✓ İncelendi</span>`}
        </div>
      </div>
      <div class="alert-desc">${escapeHtml(translateAlertDesc(a.description))}</div>
    </div>
  `
    )
    .join("");
}

async function ackAlert(alertId) {
  try {
    await fetch(`/api/alerts/${alertId}/ack`, { method: "POST" });
    const item = alertsList.find((x) => x.id === alertId);
    if (item) item.acknowledged = true;
    renderAlerts();
  } catch (e) {
    console.error("Ack error", e);
  }
}

async function resetData() {
  try {
    await fetch("/api/reset", { method: "POST" });
    devicesMap.clear();
    alertsList = [];
    renderAllViews();
  } catch (e) {
    console.error("Reset error", e);
  }
}

async function toggleSentryMode() {
  try {
    const res = await fetch("/api/sentry/toggle", { method: "POST" });
    const data = await res.json();
    updateSentryUi(data.sentry_mode);
  } catch (e) {
    console.error("Sentry toggle error", e);
  }
}

async function trustAllHousehold() {
  const btn = document.getElementById("btnTrustAll");
  if (btn) btn.textContent = "⏳ Kaydediliyor...";
  try {
    const res = await fetch("/api/sentry/trust-all", { method: "POST" });
    const data = await res.json();
    devicesMap.forEach((d) => {
      if (!d.is_threat) d.is_trusted = true;
    });
    updateTargetList();
    updateMetricsCount();
    if (btn) {
      btn.textContent = `✅ ${data.trusted_updated || devicesMap.size} Cihaz Güvenli Kaydedildi`;
      setTimeout(() => {
        btn.textContent = "🏠 Evdekileri Güvenli Kaydet";
      }, 3000);
    }
  } catch (e) {
    console.error("Trust all error", e);
    if (btn) btn.textContent = "🏠 Evdekileri Güvenli Kaydet";
  }
}

let voiceAlertEnabled = true;

function speakTurkishAlert(messageText) {
  if (!voiceAlertEnabled || !("speechSynthesis" in window)) return;
  try {
    window.speechSynthesis.cancel();
    const utter = new SpeechSynthesisUtterance(`Dikkat! ${messageText}`);
    utter.lang = "tr-TR";
    utter.rate = 1.02;
    utter.pitch = 1.0;
    window.speechSynthesis.speak(utter);
  } catch (e) {
    console.debug("TTS error", e);
  }
}

function toggleVoiceAlert() {
  voiceAlertEnabled = !voiceAlertEnabled;
  const btn = document.getElementById("btnVoiceAlert");
  if (!btn) return;
  btn.classList.toggle("active", voiceAlertEnabled);
  btn.textContent = voiceAlertEnabled ? "🗣️ Sesli Anons: AÇIK" : "🗣️ Sesli Anons: KAPALI";
  if (voiceAlertEnabled) {
    speakTurkishAlert("Sesli güvenlik anonsu aktif edildi.");
  }
}

function closeAuditModal() {
  const m = document.getElementById("auditModal");
  if (m) m.style.display = "none";
}

async function trustDeviceFromAudit(mac) {
  try {
    await fetch(`/api/devices/${encodeURIComponent(mac)}/trust`, { method: "POST" });
    await runRoomAudit();
  } catch (e) {
    console.error("Trust from audit error", e);
  }
}

function huntDeviceFromAudit(mac) {
  closeAuditModal();
  switchTab("hunt");
  const sel = document.getElementById("huntTargetSelect");
  if (sel) {
    sel.value = mac;
  }
  startHunting(mac);
}

async function runRoomAudit() {
  const modal = document.getElementById("auditModal");
  const body = document.getElementById("auditModalBody");
  const btn = document.getElementById("btnRoomAudit");
  if (modal) modal.style.display = "flex";
  if (btn) btn.textContent = "⏳ Oda Denetleniyor...";
  if (body) {
    body.innerHTML = `
      <div style="padding:18px; font-family:var(--font-mono); color:var(--accent-color);">
        ⏳ <strong>5 Aşamalı Otel / Bungalov Oda Denetimi Çalışıyor...</strong><br><br>
        1. Yerel ağ (/24) cihazları uyandırılıyor...<br>
        2. ONVIF (UDP 3702), Dahua DHIP (37810), Hikvision SADP (37020), UPnP ve 10 kamera portu taranıyor...<br>
        3. ARP tablosu, DNS Zehirleme ve MITM / Sahte Baz İstasyonu kontrol ediliyor...<br>
        4. Oda içi Gizli SSID, Casus Kamera SoftAP ve AirTag/SmartTag/Tile sinyalleri inceleniyor...
      </div>
    `;
  }

  try {
    const res = await fetch("/api/audit/room", { method: "POST" });
    const data = await res.json();
    if (btn) btn.textContent = "🏨 Oda Güvenlik Denetimi";

    const vColor = data.verdict === "TEHLİKELİ"
      ? "var(--danger-color)"
      : (data.verdict === "ŞÜPHELİ" ? "var(--warning-color)" : "var(--accent-color)");

    const checksHtml = (data.checks || []).map((c) => {
      const badgeColor = c.status === "TEHLİKELİ"
        ? "var(--danger-color)"
        : (c.status === "ŞÜPHELİ" ? "var(--warning-color)" : "var(--accent-color)");
      return `
        <div style="padding:8px 10px; border:1px solid var(--border-color); border-radius:6px; margin-bottom:6px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong>${escapeHtml(c.title)}</strong>
            <span class="badge" style="border-color:${badgeColor}; color:${badgeColor};">${escapeHtml(c.status)}</span>
          </div>
          <div style="font-size:0.78rem; color:var(--text-muted); margin-top:4px;">${escapeHtml(c.detail)}</div>
        </div>
      `;
    }).join("");

    const suspHtml = (data.suspicious_devices && data.suspicious_devices.length > 0)
      ? data.suspicious_devices.map((d) => {
          const allReasons = [
            ...(d.audit_flags || []),
            ...(d.risk_reasons || []),
          ];
          const uniqueReasons = [...new Set(allReasons)];
          const reasonsHtml = uniqueReasons.length > 0
            ? uniqueReasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")
            : `<li>${escapeHtml(d.role_hint || "Yakın mesafede tanımlanmamış verici")}</li>`;

          const decodedHtml = (d.decoded_fields && d.decoded_fields.length > 0)
            ? d.decoded_fields.map((f) => `
                <div style="font-size:0.76rem; padding:3px 6px; background:rgba(255,255,255,0.04); border-radius:4px;">
                  <strong style="color:var(--info-color);">${escapeHtml(f.label || "")}:</strong> ${escapeHtml(f.value || "")}
                </div>
              `).join("")
            : `<div style="font-size:0.75rem; color:var(--text-muted);">Ek protokol verisi yayınlamıyor (Pasif/Sessiz Verici — "İçini Sorgula" veya "Geiger" kullanın).</div>`;

          const firstTime = d.first_seen ? new Date(d.first_seen).toLocaleTimeString() : "-";
          const lastTime = d.last_seen ? new Date(d.last_seen).toLocaleTimeString() : "-";
          const borderCol = d.risk_score >= 70 ? "var(--danger-color)" : "var(--warning-color)";

          return `
            <div style="border:1px solid ${borderCol}; border-radius:8px; padding:12px; margin-bottom:10px; background:rgba(15,23,42,0.75);">
              <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:8px; flex-wrap:wrap;">
                <div>
                  <div style="font-size:0.96rem; font-weight:700; color:var(--text-primary);">
                    ${escapeHtml(translateDeviceName(d.name, d.matched_fleet))}
                    <span class="badge" style="margin-left:6px;">${escapeHtml(CLASS_TR[d.device_class] || d.device_class)}</span>
                  </div>
                  <div style="font-size:0.76rem; font-family:var(--font-mono); color:var(--text-muted); margin-top:2px;">
                    Tam Kimlik (MAC/UUID): <strong style="color:var(--text-primary);">${escapeHtml(d.mac_or_uuid)}</strong>
                  </div>
                </div>
                <span class="badge" style="border-color:${borderCol}; color:${borderCol}; font-size:0.8rem;">
                  Risk: ${d.risk_score}/100 · ${rssiToDistanceTr(d.last_rssi, d.estimated_distance_m)}
                </span>
              </div>

              <div style="margin-top:8px; padding:8px; background:rgba(245,158,11,0.1); border-left:3px solid ${borderCol}; border-radius:4px;">
                <div style="font-size:0.76rem; font-weight:700; color:${borderCol};">⚠️ Neden Şüpheli Listesinde? (Tespit Gerekçeleri):</div>
                <ul style="margin:4px 0 0 18px; font-size:0.78rem; color:var(--text-primary);">${reasonsHtml}</ul>
              </div>

              <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(210px, 1fr)); gap:6px; margin-top:8px; font-size:0.76rem; font-family:var(--font-mono);">
                <div>📡 <strong>Radyo &amp; Kanal/IP:</strong> ${escapeHtml(d.radio)} · ${escapeHtml(d.channel_or_freq || "BLE 2.4GHz")}</div>
                <div>🏭 <strong>Üretici / Rol:</strong> ${escapeHtml(d.matched_fleet || "Bilinmiyor")} (${escapeHtml(d.role_hint || "Genel Verici")})</div>
                <div>📏 <strong>Sinyal &amp; Mesafe:</strong> Son: ${d.last_rssi} dBm / Ort: ${d.avg_rssi} dBm (~${d.estimated_distance_m ?? "?"} metre)</div>
                <div>🧭 <strong>Hareketlilik:</strong> ${escapeHtml(d.mobility_profile || "Ölçülüyor")} (${d.hit_count} kez görüldü: ${firstTime} - ${lastTime})</div>
              </div>

              <div style="margin-top:8px;">
                <div style="font-size:0.75rem; font-weight:700; color:var(--text-muted); margin-bottom:4px;">🔬 Çözümlenen Donanım / Protokol İstihbaratı:</div>
                <div style="display:flex; flex-direction:column; gap:4px;">${decodedHtml}</div>
              </div>

              <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; padding-top:8px; border-top:1px solid var(--border-color);">
                <button class="btn active" onclick="huntDeviceFromAudit('${escapeHtml(d.mac_or_uuid)}')">🎯 Geiger Sayacı ile Odada Yerini Bul</button>
                <button class="btn" onclick="closeAuditModal(); openDeviceModal('${escapeHtml(d.mac_or_uuid)}');">🔍 Tam Adli İnceleme &amp; GATT Sorgula</button>
                <button class="btn" onclick="trustDeviceFromAudit('${escapeHtml(d.mac_or_uuid)}')">🏠 Benim Cihazım (Güvenli İşaretle)</button>
              </div>
            </div>
          `;
        }).join("")
      : `<div style="color:var(--accent-color); font-size:0.82rem;">✅ Yüksek riskli veya şüpheli bir cihaz tespit edilmedi.</div>`;

    const recHtml = (data.recommendations || []).map((r) => `<div style="margin-bottom:4px;">${escapeHtml(r)}</div>`).join("");

    if (body) {
      body.innerHTML = `
        <div style="padding:12px; border:2px solid ${vColor}; border-radius:8px; background:rgba(0,0,0,0.25);">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-size:1.05rem; font-weight:700; color:${vColor};">GENEL ODA GÜVENLİK KARARI: ${escapeHtml(data.verdict)}</span>
            <span style="font-family:var(--font-mono); font-weight:700; color:${vColor};">En Yüksek Risk Puanı: ${data.overall_risk_score} / 100</span>
          </div>
        </div>
        <div><strong>5 Aşamalı Denetim Sonuçları:</strong><div style="margin-top:6px;">${checksHtml}</div></div>
        <div><strong>İncelenmesi Gereken Şüpheli Cihazların Tam Adli Dosyası (${(data.suspicious_devices || []).length} Cihaz):</strong><div style="margin-top:6px;">${suspHtml}</div></div>
        <div><strong>Önerilen Güvenlik Adımları:</strong><div style="margin-top:6px; color:var(--text-primary);">${recHtml}</div></div>
      `;
    }

    if (data.verdict === "TEHLİKELİ") {
      speakTurkishAlert("Oda denetiminde yüksek riskli tehdit tespit edildi.");
    }
  } catch (e) {
    if (btn) btn.textContent = "🏨 Oda Güvenlik Denetimi";
    if (body) body.innerHTML = `Denetim sırasında hata oluştu: ${e}`;
  }
}

async function runDeepCameraScan() {
  const btn = document.getElementById("btnDeepCamScan");
  if (btn) btn.textContent = "⏳ Ağdaki Portlar Taranıyor...";
  try {
    const res = await fetch("/api/wifi/deep-scan", { method: "POST" });
    const data = await res.json();
    if (btn) {
      if (data.cameras_found_count > 0) {
        btn.textContent = `🚨 ${data.cameras_found_count} Kamera Bulundu!`;
        switchTab("alerts");
      } else {
        btn.textContent = `✅ Temiz (${data.peers_checked || 0} Ağ Cihazı Tarandı)`;
      }
      setTimeout(() => {
        btn.textContent = "📹 Ağda Gizli Kamera Tara";
      }, 4000);
    }
  } catch (e) {
    console.error("Deep camera scan error", e);
    if (btn) btn.textContent = "📹 Ağda Gizli Kamera Tara";
  }
}

async function loadDebrief() {
  const box = document.getElementById("debriefOutput");
  box.textContent = "Çevredeki sinyaller analiz ediliyor ve Türkçe güvenlik raporu hazırlanıyor...";
  try {
    const res = await fetch("/api/intel/debrief");
    const data = await res.json();
    box.textContent = data.debrief_markdown;
  } catch (e) {
    box.textContent = "Rapor oluşturulurken hata oluştu: " + e;
  }
}

function toggleNightMode() {
  nightMode = !nightMode;
  document.body.classList.toggle("night-mode", nightMode);
  const btn = document.getElementById("btnNightMode");
  btn.classList.toggle("active", nightMode);
  localStorage.setItem("airsentinel_nightmode", nightMode ? "1" : "0");
}

function switchTab(tabId) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));

  const tabBtn = document.querySelector(`[data-tab="${tabId}"]`);
  if (tabBtn) tabBtn.classList.add("active");
  const pane = document.getElementById(`tab-${tabId}`);
  if (pane) pane.classList.add("active");
  currentTab = tabId;

  if (tabId === "debrief") loadDebrief();
  if (tabId === "sits") loadSits();
  if (tabId === "hunt") updateHuntDropdown();
}

document.addEventListener("DOMContentLoaded", () => {
  resizeCanvas();

  if (localStorage.getItem("airsentinel_nightmode") === "1") {
    toggleNightMode();
  }

  document.getElementById("btnNightMode").addEventListener("click", toggleNightMode);
  const btnReset = document.getElementById("btnResetData");
  if (btnReset) btnReset.addEventListener("click", resetData);
  const btnSentry = document.getElementById("btnSentryMode");
  if (btnSentry) btnSentry.addEventListener("click", toggleSentryMode);
  const btnVoice = document.getElementById("btnVoiceAlert");
  if (btnVoice) btnVoice.addEventListener("click", toggleVoiceAlert);
  const btnAudit = document.getElementById("btnRoomAudit");
  if (btnAudit) btnAudit.addEventListener("click", runRoomAudit);
  const btnCloseAudit = document.getElementById("btnCloseAuditModal");
  if (btnCloseAudit) btnCloseAudit.addEventListener("click", closeAuditModal);
  const btnTrustAll = document.getElementById("btnTrustAll");
  if (btnTrustAll) btnTrustAll.addEventListener("click", trustAllHousehold);
  const btnCamScan = document.getElementById("btnDeepCamScan");
  if (btnCamScan) btnCamScan.addEventListener("click", runDeepCameraScan);
  document.getElementById("btnRefreshDebrief").addEventListener("click", loadDebrief);

  // Modal butonları
  document.getElementById("btnCloseModal").addEventListener("click", closeDeviceModal);
  document.getElementById("btnModalBookmark").addEventListener("click", toggleModalBookmark);
  const btnModalTrust = document.getElementById("btnModalTrust");
  if (btnModalTrust) btnModalTrust.addEventListener("click", toggleModalTrust);
  const btnModalGatt = document.getElementById("btnModalGatt");
  if (btnModalGatt) btnModalGatt.addEventListener("click", inspectModalGatt);
  document.getElementById("btnModalHunt").addEventListener("click", launchHuntFromModal);
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeDeviceModal();
      closeAuditModal();
    }
  });

  // Sinyal Avcısı butonları
  document.getElementById("huntTargetSelect").addEventListener("change", (e) => {
    startHuntPolling(e.target.value);
  });
  document.getElementById("btnGeigerAudio").addEventListener("click", toggleGeigerAudio);

  // Ortam Karşılaştırma butonları
  document.getElementById("btnStartSit").addEventListener("click", startSit);
  document.getElementById("btnCompareSits").addEventListener("click", compareSits);

  // Sekme geçişleri
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      switchTab(e.currentTarget.getAttribute("data-tab"));
    });
  });

  const filterSelect = document.getElementById("classFilter");
  if (filterSelect) {
    filterSelect.addEventListener("change", updateTargetList);
  }
  const searchInput = document.getElementById("searchInput");
  if (searchInput) {
    searchInput.addEventListener("input", updateTargetList);
  }

  window.addEventListener("click", () => initAudio(), { once: true });

  connectWebSocket();
  requestAnimationFrame(drawRadar);
});
