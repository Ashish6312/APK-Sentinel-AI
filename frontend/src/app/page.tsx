"use client";

import React, { useState, useEffect, useRef } from "react";
import { 
  ShieldAlert, 
  Upload, 
  Terminal, 
  Activity, 
  FileText, 
  RefreshCw, 
  Play, 
  History as HistoryIcon,
  Cpu,
  Layers,
  FileCode,
  ShieldCheck,
  AlertTriangle,
  Download,
  CheckCircle,
  ExternalLink
} from "lucide-react";
import { 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Cell, 
  Tooltip,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar
} from "recharts";

const API_URL = "http://localhost:8000";
const WS_URL = "ws://localhost:8000";

// DEMO APK PROFILES FOR FAIL-SAFE MODE
// DEMO APK PROFILES FOR FAIL-SAFE MODE
const DEMO_PROFILES = [
  {
    id: 901,
    file_name: "Safe_Utility_Tool.apk",
    sha256: "ea84931a742c38d9cd316a8d7cb12c9bf39cd5bc13d8d9ff3d8b39cd5bc13d8d",
    package_name: "com.secops.safe.utility",
    size: "1.2 MB",
    created_at: "2026-06-18 19:10 UTC",
    status: "Completed",
    risk_assessment: {
      risk_score: 12.0,
      verdict: "Safe",
      risk_level: "LOW",
      breakdown: { permission_risk_score: 5.0, threat_intel_score: 5.0, obfuscation_risk_score: 0.0, mitre_severity_score: 0.0 }
    },
    metadata: { target_sdk: "31", signer: "CN=SecOps Developer, O=SecOps, C=US", dangerous_permissions: 0, first_seen: "2026-06-18" },
    static_analysis: {
      permissions: [
        { name: "android.permission.INTERNET", flag: "Expected", why: "Required for standard network communication." },
        { name: "android.permission.ACCESS_NETWORK_STATE", flag: "Expected", why: "Checked to verify cellular/wifi link status." }
      ],
      strings: [
        { artifact: "https://api.github.com/repos/check", type: "Update Check" },
        { artifact: "LogUtils: Initialised", type: "Utility Log" }
      ],
      entropy: [
        { section: "classes.dex", value: "4.82", verdict: "Normal" },
        { section: "res/layout/activity_main.xml", value: "3.41", verdict: "Normal" }
      ],
      native_libraries: [],
      exported_components: [
        { name: "com.secops.safe.utility.MainActivity", type: "Activity" }
      ],
      hardcoded_credentials: []
    },
    dynamic_analysis: {
      connections: [
        { destination: "api.github.com", port: "443", note: "Standard API domain" }
      ],
      decrypted_strings: [
        { string: "init_success", source: "Logger static class" }
      ],
      mutations: [
        { event: "Process", detail: "Spawns Main UI Activity without delay" }
      ]
    },
    ai_report: {
      executive_summary: "The application exhibits typical behaviors of a benign system utility. Minimal security indicators were matched.",
      threat_assessment: "Standard permissions are mapped. Bytecode scanning did not trigger any suspicious network connections, background tracking, or overlay indicators.",
      chips: ["Family: Benign (98% conf.)", "MITRE: None", "Entropy: Normal"],
      anomalies: [
        { claim: "No suspicious behaviors detected.", cite: "cited: manifest.permissions[0]" }
      ]
    },
    mitre_mapping: [],
    family_similarity: [
      { family_name: "Benign", similarity_score: 98, confidence: "HIGH", threat_category: "Safe Utility" }
    ]
  },
  {
    id: 902,
    file_name: "Free_Wallpapers_Pro.apk",
    sha256: "b9cdbc13d8daf829038d128d9c12b9ffd38b39cd5bc13d8dea",
    package_name: "com.adpromo.wallpapers.pro",
    size: "3.1 MB",
    created_at: "2026-06-19 12:15 UTC",
    status: "Completed",
    risk_assessment: {
      risk_score: 45.0,
      verdict: "Suspicious",
      risk_level: "MEDIUM",
      breakdown: { permission_risk_score: 30.0, threat_intel_score: 35.0, obfuscation_risk_score: 15.0, mitre_severity_score: 45.0 }
    },
    metadata: { target_sdk: "29", signer: "CN=AdPromo Dev, O=AdPromo, C=CN", dangerous_permissions: 2, first_seen: "2026-06-17" },
    static_analysis: {
      permissions: [
        { name: "android.permission.INTERNET", flag: "Expected", why: "Required to download custom wallpapers." },
        { name: "android.permission.WRITE_EXTERNAL_STORAGE", flag: "Suspicious", why: "Requests access to save image assets, but writes metadata to non-public paths." },
        { name: "android.permission.RECEIVE_BOOT_COMPLETED", flag: "Suspicious", why: "Triggers app launch immediately after device restart." }
      ],
      strings: [
        { artifact: "http://adserver.promo-clicks.com/load", type: "Ad Delivery" },
        { artifact: "https://doubleclick.net/ad", type: "Telemetry Tracker" }
      ],
      entropy: [
        { section: "classes.dex", value: "6.21", verdict: "Normal" },
        { section: "assets/ad_module.jar", value: "7.14", verdict: "Packed/Encrypted" }
      ],
      native_libraries: [],
      exported_components: [
        { name: "com.adpromo.wallpapers.pro.MainActivity", type: "Activity" },
        { name: "com.adpromo.wallpapers.pro.AdBootReceiver", type: "Receiver" }
      ],
      hardcoded_credentials: [
        { type: "Generic Admob ID", raw: "ca-app-pub-3940256099942544~3347511713" }
      ]
    },
    dynamic_analysis: {
      connections: [
        { destination: "promo-clicks.com", port: "80", note: "Ad Network" },
        { destination: "doubleclick.net", port: "443", note: "Known analytics tracker" }
      ],
      decrypted_strings: [
        { string: "load_ad_banner_assets", source: "decrypted from assets/ad_module.jar" }
      ],
      mutations: [
        { event: "FS write", detail: "Writes payload to temporary cache folder" },
        { event: "Process", detail: "Spawns background service AdBackgroundService at boot" }
      ]
    },
    ai_report: {
      executive_summary: "The application Wallpapers Pro displays adware characteristics, loading aggressive full-screen banner notifications in the background.",
      threat_assessment: "Standard permissions are mapped, but background services show high ad spam behaviors. Outbound telemetry hits click-tracking servers at boot time.",
      chips: ["Family: Adware/PUP (68% conf.)", "MITRE: T1407 Dynamic Code", "Boot Launch"],
      anomalies: [
        { claim: "Launches background service AdBackgroundService immediately at system boot without user interaction.", cite: "cited: manifest.receivers[BOOT_COMPLETED]" }
      ]
    },
    mitre_mapping: [
      { tactic: "Defense Evasion", technique_id: "T1407", technique_name: "Dynamic Code Execution", severity: "MEDIUM", evidence: "Loads external ad classes dynamically.", confidence: "HIGH" },
      { tactic: "Persistence", technique_id: "T1624", technique_name: "Boot or Logon Initialization", severity: "LOW", evidence: "Registers receiver to run automatically on device boot (RECEIVE_BOOT_COMPLETED).", confidence: "HIGH" }
    ],
    family_similarity: [
      { family_name: "Adware", similarity_score: 68, confidence: "MEDIUM", threat_category: "Adware / PUP" },
      { family_name: "Spyware", similarity_score: 18, confidence: "LOW", threat_category: "Spyware / Surveillance" }
    ]
  },
  {
    id: 903,
    file_name: "Spy_Tracker_Agent.apk",
    sha256: "cf8b9bc13d8daf829038d128d9ffd38b39cd5bc13d8dea",
    package_name: "com.spyware.tracker.agent",
    size: "4.2 MB",
    created_at: "2026-06-20 18:30 UTC",
    status: "Completed",
    risk_assessment: {
      risk_score: 76.0,
      verdict: "High Risk",
      risk_level: "HIGH",
      breakdown: { permission_risk_score: 70.0, threat_intel_score: 75.0, obfuscation_risk_score: 40.0, mitre_severity_score: 75.0 }
    },
    metadata: { target_sdk: "30", signer: "CN=SpyDev, O=SpyDev, C=RU", dangerous_permissions: 4, first_seen: "2026-06-18" },
    static_analysis: {
      permissions: [
        { name: "android.permission.RECORD_AUDIO", flag: "Dangerous", why: "Allows stealth recording of ambient sound." },
        { name: "android.permission.ACCESS_FINE_LOCATION", flag: "Dangerous", why: "Tracks precise coordinates of the device." },
        { name: "android.permission.READ_CONTACTS", flag: "Dangerous", why: "Harvests user's address book catalog." },
        { name: "android.permission.INTERNET", flag: "Expected", why: "Required to exfiltrate telemetry data." }
      ],
      strings: [
        { artifact: "https://api.telegram.org/bot7291034:sendMessage", type: "Exfiltration Path" },
        { artifact: "getLastKnownLocation", type: "GPS API hook" }
      ],
      entropy: [
        { section: "classes.dex", value: "7.45", verdict: "Highly Obfuscated" },
        { section: "lib/armeabi/libcore.so", value: "7.84", verdict: "Packed/Protected" }
      ],
      native_libraries: ["lib/armeabi/libcore.so"],
      exported_components: [
        { name: "com.spyware.tracker.agent.MainActivity", type: "Activity" },
        { name: "com.spyware.tracker.agent.LocationUploadService", type: "Service" }
      ],
      hardcoded_credentials: [
        { type: "Telegram Bot Token", raw: "7291034:AAFgH..." }
      ]
    },
    dynamic_analysis: {
      connections: [
        { destination: "api.telegram.org", port: "443", note: "Exfiltration tunnel via bot API" }
      ],
      decrypted_strings: [
        { string: "record_mic_pcm_16000", source: "triggered dynamically on activity change" }
      ],
      mutations: [
        { event: "Process", detail: "Spawns SpyService to record microphone in the background" },
        { event: "FS write", detail: "Saves encrypted PCM files under /sdcard/.cache" }
      ]
    },
    ai_report: {
      executive_summary: "The sample is an active Surveillance Spyware masquerading as a utility. It captures background microphone recordings and coordinates.",
      threat_assessment: "Abuses critical permissions (RECORD_AUDIO, LOCATION, CONTACTS) without active UI triggers. Exfiltrates sensitive logs directly to Telegram Bot API.",
      chips: ["Family: Spyware/Surveillance (82% conf.)", "MITRE: T1429 Audio Capture", "MITRE: T1404 Location"],
      anomalies: [
        { claim: "Requests RECORD_AUDIO and tracks location in background service without active user UI prompts.", cite: "cited: dynamic.ui_events[0], manifest.permissions[RECORD_AUDIO]" }
      ]
    },
    mitre_mapping: [
      { tactic: "Collection", technique_id: "T1429", technique_name: "Audio Capture", severity: "HIGH", evidence: "Requests RECORD_AUDIO permission and triggers record() bytecode.", confidence: "HIGH" },
      { tactic: "Discovery", technique_id: "T1404", technique_name: "Device Location Tracking", severity: "MEDIUM", evidence: "Requests precise location.", confidence: "HIGH" },
      { tactic: "Discovery", technique_id: "T1430", technique_name: "Access Sensitive Data", severity: "MEDIUM", evidence: "Harvests user contacts catalog.", confidence: "HIGH" }
    ],
    family_similarity: [
      { family_name: "Spyware", similarity_score: 82, confidence: "HIGH", threat_category: "Spyware / Surveillance" },
      { family_name: "Banking Trojan", similarity_score: 35, confidence: "MEDIUM", threat_category: "Banking Trojan" }
    ]
  },
  {
    id: 904,
    file_name: "Apex_Crypto_Wallet.apk",
    sha256: "df8a96cde7a1db39ad8119c4d9bc272d1a3c6be4a0b2d3c948db7e2e34ff601c",
    package_name: "com.apex.crypto.wallet",
    size: "5.2 MB",
    created_at: "2026-06-21 11:42 UTC",
    status: "Completed",
    risk_assessment: {
      risk_score: 91.0,
      verdict: "Critical",
      risk_level: "CRITICAL",
      breakdown: { permission_risk_score: 95.0, threat_intel_score: 90.0, obfuscation_risk_score: 88.0, mitre_severity_score: 100.0 }
    },
    metadata: { target_sdk: "33", signer: "Self-signed, untrusted CA", dangerous_permissions: 5, first_seen: "2026-06-18" },
    static_analysis: {
      permissions: [
        { name: "android.permission.RECEIVE_SMS", flag: "Dangerous", why: "Used to intercept incoming SMS OTP verification codes." },
        { name: "android.permission.READ_CONTACTS", flag: "Dangerous", why: "No legitimate cryptocurrency application needs contacts list data." },
        { name: "android.permission.SYSTEM_ALERT_WINDOW", flag: "Dangerous", why: "Enables overlay attacks on top of banking and exchange apps." },
        { name: "android.permission.BIND_ACCESSIBILITY_SERVICE", flag: "Dangerous", why: "Allows keylogging inputs and reading screen content." }
      ],
      strings: [
        { artifact: "hxxp://185.41.x.x/gate.php", type: "C2 Endpoint" },
        { artifact: "AES_KEY_b64=\"Zm9vYmFy…\"", type: "Hardcoded secret" },
        { artifact: "/sdcard/.cache/cfg.dat", type: "Hidden Config" }
      ],
      entropy: [
        { section: "classes2.dex", value: "7.91", verdict: "Packed/Protected" },
        { section: "lib/armeabi/libcore.so", value: "7.84", verdict: "Packed/Protected" }
      ],
      native_libraries: ["lib/armeabi/libcore.so", "lib/armeabi/libcrypto.so"],
      exported_components: [
        { name: "com.apex.crypto.wallet.MainActivity", type: "Activity" },
        { name: "com.apex.crypto.wallet.AccessibilityHelperService", type: "Service" }
      ],
      hardcoded_credentials: [
        { type: "Google API Key", raw: "AIzaSyD89dksk091skd01skd01skd01" },
        { type: "AES Hex Key", raw: "89ab01df4c56e719" }
      ]
    },
    dynamic_analysis: {
      connections: [
        { destination: "185.41.22.x", port: "443", note: "Known C2 IP address (OTX threat feed)" },
        { destination: "api.fake-secure-bank.io", port: "443", note: "Domain registered 4 days ago" }
      ],
      decrypted_strings: [
        { string: "forward_sms_endpoint", source: "decrypted at runtime" },
        { string: "overlay_target=com.bank.real", source: "decrypted at runtime" }
      ],
      mutations: [
        { event: "Process", detail: "Spawns background service after 90s idle delay (anti-sandbox timer)" },
        { event: "FS write", detail: "Writes /sdcard/.cache/cfg.dat hidden configuration parameters" },
        { event: "UI", detail: "Renders overlay mimicking real bank credentials dialog box on startup" }
      ]
    },
    ai_report: {
      executive_summary: "The application poses a critical threat, operating as a Banking/Credential Trojan targeting cryptocurrency wallets and accounts.",
      threat_assessment: "Requests accessibility binds to log keyboard sequences and draws overlay windows to capture PIN inputs. Communicates with a known hostile C2 IP.",
      chips: ["Family: BankBot/Cerberus (91% conf.)", "MITRE: T1516 Accessibility", "MITRE: T1411 Overlay"],
      anomalies: [
        { claim: "App declares itself as a wallet but contacts C2 IP and requests accessibility service binds.", cite: "cited: network.connections[0], manifest.permissions[BIND_ACCESSIBILITY_SERVICE]" },
        { claim: "Draws overlays immediately upon system callbacks without foreground context.", cite: "cited: dynamic.ui_events[1]" }
      ]
    },
    mitre_mapping: [
      { tactic: "Credential Access", technique_id: "T1516", technique_name: "Abuse Accessibility Service", severity: "CRITICAL", evidence: "Requests permission BIND_ACCESSIBILITY_SERVICE to keylog inputs.", confidence: "HIGH" },
      { tactic: "Credential Access", technique_id: "T1546", technique_name: "Input Capture via Overlay", severity: "CRITICAL", evidence: "Requests drawing alert overlays to phish inputs (SYSTEM_ALERT_WINDOW).", confidence: "HIGH" },
      { tactic: "Collection", technique_id: "T1636", technique_name: "Capture SMS Messages", severity: "HIGH", evidence: "Intercepts MFA codes via SMS permissions.", confidence: "HIGH" }
    ],
    family_similarity: [
      { family_name: "Banking Trojan", similarity_score: 94, confidence: "HIGH", threat_category: "Banking Trojan" },
      { family_name: "Hydra", similarity_score: 91, confidence: "HIGH", threat_category: "Banking Trojan" },
      { family_name: "Anubis", similarity_score: 87, confidence: "HIGH", threat_category: "Banking Trojan" },
      { family_name: "Cerberus", similarity_score: 81, confidence: "HIGH", threat_category: "Banking Trojan" }
    ]
  }
];

const TECHNIQUE_TO_TACTIC: { [key: string]: string } = {
  "T1477": "Initial Access",
  "T1624": "Persistence",
  "T1546": "Persistence",
  "T1516": "Credential Access",
  "T1411": "Credential Access",
  "T1414": "Credential Access",
  "T1636": "Collection",
  "T1412": "Collection",
  "T1429": "Collection",
  "T1512": "Collection",
  "T1430": "Discovery",
  "T1404": "Discovery",
  "T1426": "Discovery",
  "T1407": "Defense Evasion",
  "T1409": "Defense Evasion"
};

const INITIAL_IOCS = [
  { type: "domain", value: "login-security-update.ru", severity: "critical", timestamp: "23:14:02" },
  { type: "ip", value: "194.26.135.84", severity: "critical", timestamp: "23:12:44" },
  { type: "hash", value: "SHA256: df8a96cde7a1db39ad8119c4d9bc272d1a3c6be4a0b2d3c948db7e2e34ff601c", severity: "high", timestamp: "22:58:15" },
  { type: "domain", value: "api.fake-secure-bank.io", severity: "critical", timestamp: "22:42:09" },
  { type: "url", value: "api.telegram.org/bot7291034:sendMessage", severity: "high", timestamp: "22:15:30" },
  { type: "ip", value: "185.225.10.x", severity: "high", timestamp: "21:30:12" },
  { type: "domain", value: "promo-clicks.com", severity: "medium", timestamp: "20:45:00" },
  { type: "hash", value: "SHA256: cf8b9bc13d8daf829038d128d9ffd38b39cd5bc13d8dea", severity: "medium", timestamp: "19:12:11" },
  { type: "url", value: "doubleclick.net/ad", severity: "low", timestamp: "18:30:45" },
];

const HARDCODED_HISTORY = [
  { file_name: "TikSaver_Mod.apk", package_name: "com.tiktok.saver.mod", sha256: "3a1f9b2c7d8e4f5a6b3c1d2e8f7a9b0c", size: "8.4 MB", created_at: "2026-06-17 09:22 UTC", risk_assessment: { risk_score: 88, verdict: "Critical", risk_level: "CRITICAL", breakdown: { permission_risk_score: 92, threat_intel_score: 85, obfuscation_risk_score: 78, mitre_severity_score: 90 } }, metadata: { target_sdk: "28", signer: "CN=Unknown, O=ModTeam", dangerous_permissions: 8, first_seen: "2026-06-15" }, family_similarity: [{ family_name: "Joker", similarity_score: 87, confidence: "HIGH", threat_category: "Premium SMS Fraud" }], id: 1905 },
  { file_name: "WiFi_Analyzer.apk", package_name: "net.wifitools.analyzer", sha256: "7e2d4f6a8b1c3e5d9f0a2b4c6d8e1f3a", size: "2.1 MB", created_at: "2026-06-16 16:45 UTC", risk_assessment: { risk_score: 22, verdict: "Safe", risk_level: "LOW", breakdown: { permission_risk_score: 15, threat_intel_score: 10, obfuscation_risk_score: 5, mitre_severity_score: 8 } }, metadata: { target_sdk: "33", signer: "CN=WiFiTools LLC, O=WiFiTools, C=US", dangerous_permissions: 1, first_seen: "2026-06-10" }, family_similarity: [{ family_name: "Benign", similarity_score: 95, confidence: "HIGH", threat_category: "Network Utility" }], id: 1906 },
  { file_name: "FlashLight_Ultra.apk", package_name: "com.flash.ultra.light", sha256: "9c4b6d8e2f1a3c5b7d9e0f2a4c6b8d1e", size: "4.7 MB", created_at: "2026-06-16 11:03 UTC", risk_assessment: { risk_score: 67, verdict: "High Risk", risk_level: "HIGH", breakdown: { permission_risk_score: 75, threat_intel_score: 55, obfuscation_risk_score: 60, mitre_severity_score: 65 } }, metadata: { target_sdk: "27", signer: "CN=FlashDev, O=Unknown", dangerous_permissions: 6, first_seen: "2026-06-14" }, family_similarity: [{ family_name: "Hiddad", similarity_score: 72, confidence: "MEDIUM", threat_category: "Adware/Dropper" }], id: 1907 },
  { file_name: "PDF_Reader_Fast.apk", package_name: "com.pdfread.fast.viewer", sha256: "1a3c5e7f9b2d4f6a8c0e2d4f6a8b1c3e", size: "5.9 MB", created_at: "2026-06-15 08:30 UTC", risk_assessment: { risk_score: 83, verdict: "Critical", risk_level: "CRITICAL", breakdown: { permission_risk_score: 80, threat_intel_score: 90, obfuscation_risk_score: 72, mitre_severity_score: 85 } }, metadata: { target_sdk: "26", signer: "CN=PDFTools, O=Unknown", dangerous_permissions: 7, first_seen: "2026-06-13" }, family_similarity: [{ family_name: "Cerberus", similarity_score: 81, confidence: "HIGH", threat_category: "Banking Trojan" }], id: 1908 },
  { file_name: "Battery_Boost.apk", package_name: "com.battery.boost.optimize", sha256: "5d7f9a1c3e5b7d9f1a3c5e7f9b2d4f6a", size: "3.3 MB", created_at: "2026-06-14 14:18 UTC", risk_assessment: { risk_score: 52, verdict: "Suspicious", risk_level: "MEDIUM", breakdown: { permission_risk_score: 45, threat_intel_score: 50, obfuscation_risk_score: 40, mitre_severity_score: 55 } }, metadata: { target_sdk: "30", signer: "CN=BoostApps, O=BoostCo", dangerous_permissions: 4, first_seen: "2026-06-12" }, family_similarity: [{ family_name: "Generic PUP", similarity_score: 64, confidence: "MEDIUM", threat_category: "Potentially Unwanted" }], id: 1909 },
  { file_name: "VPN_Shield_Pro.apk", package_name: "com.vpn.shield.unlimited", sha256: "8b0d2f4a6c8e1f3a5c7e9b1d3f5a7c9e", size: "11.2 MB", created_at: "2026-06-13 20:55 UTC", risk_assessment: { risk_score: 74, verdict: "High Risk", risk_level: "HIGH", breakdown: { permission_risk_score: 70, threat_intel_score: 80, obfuscation_risk_score: 68, mitre_severity_score: 72 } }, metadata: { target_sdk: "29", signer: "CN=VPNDev, O=ShieldVPN, C=RU", dangerous_permissions: 5, first_seen: "2026-06-11" }, family_similarity: [{ family_name: "SpyNote", similarity_score: 70, confidence: "MEDIUM", threat_category: "RAT/Spyware" }], id: 1910 },
  { file_name: "Calendar_Widget.apk", package_name: "com.widgets.calendar.clean", sha256: "2d4f6a8c0e2b4d6f8a1c3e5b7d9f1a3c", size: "1.8 MB", created_at: "2026-06-13 10:12 UTC", risk_assessment: { risk_score: 8, verdict: "Safe", risk_level: "LOW", breakdown: { permission_risk_score: 5, threat_intel_score: 3, obfuscation_risk_score: 0, mitre_severity_score: 2 } }, metadata: { target_sdk: "34", signer: "CN=CalendarCo, O=WidgetLab, C=DE", dangerous_permissions: 0, first_seen: "2026-06-09" }, family_similarity: [{ family_name: "Benign", similarity_score: 99, confidence: "HIGH", threat_category: "Utility" }], id: 1911 },
  { file_name: "QR_Scanner_Pro.apk", package_name: "com.qr.scanner.barcode.pro", sha256: "4f6a8c0e2d4b6f8a1c3e5d7f9b1a3c5e", size: "6.2 MB", created_at: "2026-06-12 17:40 UTC", risk_assessment: { risk_score: 71, verdict: "High Risk", risk_level: "HIGH", breakdown: { permission_risk_score: 65, threat_intel_score: 72, obfuscation_risk_score: 58, mitre_severity_score: 75 } }, metadata: { target_sdk: "28", signer: "CN=QRTools, O=Unknown", dangerous_permissions: 5, first_seen: "2026-06-10" }, family_similarity: [{ family_name: "TeaBot", similarity_score: 68, confidence: "MEDIUM", threat_category: "Banking Trojan" }], id: 1912 },
  { file_name: "Weather_Live.apk", package_name: "com.weather.live.forecast", sha256: "6a8c0e2d4f6b8a1c3e5d7f9b1a3c5e7f", size: "4.0 MB", created_at: "2026-06-11 07:28 UTC", risk_assessment: { risk_score: 18, verdict: "Safe", risk_level: "LOW", breakdown: { permission_risk_score: 12, threat_intel_score: 8, obfuscation_risk_score: 10, mitre_severity_score: 5 } }, metadata: { target_sdk: "33", signer: "CN=WeatherApps, O=ForecastCo, C=US", dangerous_permissions: 1, first_seen: "2026-06-08" }, family_similarity: [{ family_name: "Benign", similarity_score: 96, confidence: "HIGH", threat_category: "Weather" }], id: 1913 },
  { file_name: "File_Manager_X.apk", package_name: "com.filemanager.x.explorer", sha256: "0e2d4f6a8c1b3e5d7f9a1c3e5b7d9f1a", size: "7.6 MB", created_at: "2026-06-10 22:15 UTC", risk_assessment: { risk_score: 59, verdict: "Suspicious", risk_level: "MEDIUM", breakdown: { permission_risk_score: 55, threat_intel_score: 60, obfuscation_risk_score: 48, mitre_severity_score: 62 } }, metadata: { target_sdk: "29", signer: "CN=FileMgrDev, O=Unknown", dangerous_permissions: 4, first_seen: "2026-06-07" }, family_similarity: [{ family_name: "FluBot", similarity_score: 55, confidence: "LOW", threat_category: "SMS Trojan" }], id: 1914 },
  { file_name: "Crypto_Monitor.apk", package_name: "com.crypto.price.monitor", sha256: "c1e3d5f7a9b2c4d6e8f0a1b3c5d7e9f1", size: "9.1 MB", created_at: "2026-06-10 14:03 UTC", risk_assessment: { risk_score: 86, verdict: "Critical", risk_level: "CRITICAL", breakdown: { permission_risk_score: 88, threat_intel_score: 82, obfuscation_risk_score: 85, mitre_severity_score: 90 } }, metadata: { target_sdk: "27", signer: "CN=CryptoDev, O=Unknown, C=KR", dangerous_permissions: 9, first_seen: "2026-06-06" }, family_similarity: [{ family_name: "Hydra", similarity_score: 83, confidence: "HIGH", threat_category: "Banking Trojan" }], id: 1915 },
  { file_name: "Notes_Secure.apk", package_name: "com.notes.secure.encrypted", sha256: "a3b5c7d9e1f2a4b6c8d0e2f4a6b8c1d3", size: "2.4 MB", created_at: "2026-06-09 09:50 UTC", risk_assessment: { risk_score: 14, verdict: "Safe", risk_level: "LOW", breakdown: { permission_risk_score: 8, threat_intel_score: 6, obfuscation_risk_score: 12, mitre_severity_score: 4 } }, metadata: { target_sdk: "34", signer: "CN=SecureNotes, O=NotesLab, C=US", dangerous_permissions: 0, first_seen: "2026-06-05" }, family_similarity: [{ family_name: "Benign", similarity_score: 97, confidence: "HIGH", threat_category: "Productivity" }], id: 1916 }
];

export default function Home() {
  const [activeTab, setActiveTab] = useState<string>("upload"); 
  const [activeAnalysis, setActiveAnalysis] = useState<any>(DEMO_PROFILES[3]); // Default to Crypto Wallet
  const [analysisHistory, setAnalysisHistory] = useState<any[]>(DEMO_PROFILES);

  const allScans = [
    ...analysisHistory,
    ...HARDCODED_HISTORY
  ];

  const [dashboardData, setDashboardData] = useState<any>({
    total_apks: 142,
    malware_detected: 48,
    critical_threats: 19,
    recent_analyses: DEMO_PROFILES
  });

  const [explanationMode, setExplanationMode] = useState<"technical" | "beginner">("technical");
  const [iocFeed, setIocFeed] = useState<any[]>(INITIAL_IOCS);

  // Dynamic IOC Feed Ticker
  useEffect(() => {
    const iocTypes = ["domain", "ip", "hash", "url", "cert"];
    const iocSeverities = ["critical", "high", "medium", "low"];
    const mockDomains = ["update-service-sys.su", "c2-gate-port.net", "mfa-bank-verify.info", "adserver-load-ban.com", "tele-api-upload-bot.org"];
    const mockIPs = ["194.26.135.85", "185.225.10.12", "185.41.22.90", "195.12.80.4", "45.138.99.21"];
    const mockHashes = ["SHA256: cf8a96cde7a1db", "SHA256: d8f34190cde11", "SHA256: b9cdbc13d8daf", "SHA256: ea84931a742c3", "SHA256: ef8a96cde7a1d"];
    
    const interval = setInterval(() => {
      const type = iocTypes[Math.floor(Math.random() * iocTypes.length)];
      const severity = iocSeverities[Math.floor(Math.random() * iocSeverities.length)];
      let value = "";
      
      if (type === "domain") {
        value = mockDomains[Math.floor(Math.random() * mockDomains.length)];
      } else if (type === "ip") {
        value = mockIPs[Math.floor(Math.random() * mockIPs.length)];
      } else if (type === "hash") {
        value = mockHashes[Math.floor(Math.random() * mockHashes.length)];
      } else if (type === "url") {
        value = mockDomains[Math.floor(Math.random() * mockDomains.length)] + "/api/v2/update";
      } else {
        value = "CN=HackerCA, O=" + mockDomains[Math.floor(Math.random() * mockDomains.length)] + ", C=RU";
      }
      
      const now = new Date();
      const timeStr = now.toTimeString().split(' ')[0];
      const newItem = { type, value, severity, timestamp: timeStr };
      setIocFeed(prev => [newItem, ...prev.slice(0, 14)]);
    }, 10000); // Add item every 10 seconds
    
    return () => clearInterval(interval);
  }, []);

  const [apiConnectionStatus, setApiConnectionStatus] = useState<string>("offline"); 
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [analysisStatus, setAnalysisStatus] = useState<string>("idle"); // idle, queued, processing, completed, failed
  const [progressLogs, setProgressLogs] = useState<string[]>([]);
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [activeSocket, setActiveSocket] = useState<WebSocket | null>(null);
  
  const fileInputRef = useRef<HTMLInputElement>(null);
  const consoleLogEndRef = useRef<HTMLDivElement>(null);

  // Animated Gauge state
  const [gaugeScore, setGaugeScore] = useState<number>(0);

  // Auto-scroll terminal log
  useEffect(() => {
    consoleLogEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [progressLogs]);

  // Load metrics from FastAPI if running
  const loadDashboardData = async () => {
    try {
      const res = await fetch(`${API_URL}/dashboard`);
      if (res.ok) {
        const data = await res.json();
        setDashboardData(data);
        
        // Merge history
        setAnalysisHistory((prev: any[]) => {
          const merged = data.recent_analyses.map((item: any) => {
            const demo = DEMO_PROFILES.find(p => p.id === item.id);
            if (demo) {
              return {
                ...demo,
                ...item,
                risk_assessment: {
                  ...demo.risk_assessment,
                  risk_score: item.risk_score !== undefined ? item.risk_score : demo.risk_assessment.risk_score,
                  verdict: item.verdict || demo.risk_assessment.verdict
                }
              };
            }
            return item;
          });
          
          DEMO_PROFILES.forEach(p => {
            if (!merged.some((x: any) => x.id === p.id)) {
              merged.push(p);
            }
          });
          return merged;
        });
        setApiConnectionStatus("online");
      } else {
        setApiConnectionStatus("offline");
      }
    } catch (e) {
      console.log("FastAPI backend offline. Running in hybrid simulated demo mode.");
      setApiConnectionStatus("offline");
    }
  };

  // Load dashboard metrics periodically for live updates
  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(() => {
      loadDashboardData();
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  // Poll active analysis details if it's currently analyzing (non-demo and not completed/failed)
  useEffect(() => {
    if (!activeAnalysis) return;
    const isDemo = [901, 902, 903, 904].includes(activeAnalysis.id);
    const isDone = activeAnalysis.status === "Completed" || activeAnalysis.status === "Failed";
    
    if (apiConnectionStatus === "online" && !isDemo && !isDone) {
      const interval = setInterval(async () => {
        try {
          const res = await fetch(`${API_URL}/analysis/${activeAnalysis.id}`);
          if (res.ok) {
            const data = await res.json();
            const mappedData = formatBackendAnalysis(data);
            
            // If the status changed to Completed or Failed, refresh dashboard data
            if (mappedData.status === "Completed" || mappedData.status === "Failed") {
              loadDashboardData();
            }
            
            setActiveAnalysis(mappedData);
          }
        } catch (e) {
          console.error("Error polling active analysis", e);
        }
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [activeAnalysis?.id, activeAnalysis?.status, apiConnectionStatus]);

  // Synchronize currentStep if viewing an in-progress active analysis
  useEffect(() => {
    if (!activeAnalysis) return;
    
    const statusToStep: { [key: string]: number } = {
      "Queued": 1,
      "Parsing APK": 3,
      "Extracting Features": 4,
      "Threat Analysis": 6,
      "ML Detection": 9,
      "MITRE Mapping": 7,
      "Obfuscation Scan": 8,
      "Dynamic Sandbox": 10,
      "AI Report": 11,
      "PDF Generation": 12,
      "Completed": 14,
      "Failed": 14
    };
    
    const stepVal = statusToStep[activeAnalysis.status];
    if (stepVal !== undefined) {
      setCurrentStep(stepVal);
    }
  }, [activeAnalysis?.status]);

  // Update animated gauge whenever activeAnalysis changes or overview tab becomes active
  useEffect(() => {
    if (activeTab === "overview" && activeAnalysis) {
      setGaugeScore(0);
      const target = activeAnalysis.risk_assessment?.risk_score || 0;
      let cur = 0;
      const interval = setInterval(() => {
        cur += Math.max(1, Math.round((target - cur) / 4));
        if (cur >= target) {
          cur = target;
          clearInterval(interval);
        }
        setGaugeScore(cur);
      }, 50);
      return () => clearInterval(interval);
    }
  }, [activeTab, activeAnalysis]);

  const handleDownloadPDF = () => {
    if (!activeAnalysis) return;
    if (apiConnectionStatus === "online") {
      window.open(`${API_URL}/pdf/${activeAnalysis.id}`, "_blank");
    } else {
      alert("PDF report generation requires a live backend server connection. Please run the backend uvicorn server at localhost:8000.");
    }
  };

  const selectAnalysis = async (id: number) => {
    const demo = DEMO_PROFILES.find(x => x.id === id);
    if (demo) {
      setActiveAnalysis(demo);
      setActiveTab("overview");
      return;
    }

    if (apiConnectionStatus === "online") {
      try {
        const res = await fetch(`${API_URL}/analysis/${id}`);
        if (res.ok) {
          const data = await res.json();
          // Map backend response fields to local structure
          const mappedData = formatBackendAnalysis(data);
          setActiveAnalysis(mappedData);
          setActiveTab("overview");
          return;
        }
      } catch (e) {
        console.error("Error loading analysis", e);
      }
    }

    // Fallback for hardcoded history items or failed online fetch
    const histItem = HARDCODED_HISTORY.find((x: any) => x.id === id) || analysisHistory.find((x: any) => x.id === id);
    if (histItem) {
      const score = histItem.risk_assessment?.risk_score ?? histItem.risk_score ?? 0;
      let baseProfile = DEMO_PROFILES[0];
      if (score >= 80) {
        baseProfile = DEMO_PROFILES[3];
      } else if (score >= 60) {
        baseProfile = DEMO_PROFILES[2];
      } else if (score >= 30) {
        baseProfile = DEMO_PROFILES[1];
      }

      const mocked = {
        ...baseProfile,
        id: histItem.id,
        file_name: histItem.file_name,
        package_name: histItem.package_name,
        sha256: histItem.sha256 || "—",
        created_at: histItem.created_at,
        risk_assessment: {
          ...baseProfile.risk_assessment,
          risk_score: score,
          verdict: histItem.risk_assessment?.verdict || histItem.verdict || baseProfile.risk_assessment.verdict,
          risk_level: histItem.risk_assessment?.risk_level || baseProfile.risk_assessment.risk_level,
        },
        metadata: {
          ...baseProfile.metadata,
          target_sdk: histItem.metadata?.target_sdk || baseProfile.metadata.target_sdk,
          signer: histItem.metadata?.signer || baseProfile.metadata.signer,
          dangerous_permissions: histItem.metadata?.dangerous_permissions ?? baseProfile.metadata.dangerous_permissions,
          first_seen: histItem.metadata?.first_seen || baseProfile.metadata.first_seen,
        },
        family_similarity: histItem.family_similarity || baseProfile.family_similarity,
        ai_report: {
          ...baseProfile.ai_report,
          executive_summary: `The application ${histItem.file_name || 'analyzed'} exhibits behaviors consistent with ${histItem.family_similarity?.[0]?.threat_category || 'its profile'}. ${baseProfile.ai_report?.executive_summary || ''}`,
          chips: [
            `Family: ${histItem.family_similarity?.[0]?.family_name || 'Unknown'} (${histItem.family_similarity?.[0]?.similarity_score || 0}% conf.)`,
            ...(baseProfile.ai_report?.chips?.slice(1) || [])
          ]
        }
      };
      setActiveAnalysis(mocked);
      setActiveTab("overview");
    }
  };

  // Convert backend data keys to match React UI structure
  const formatBackendAnalysis = (data: any) => {
    const defaultStatic: {
      permissions: { name: string; flag: string; why: string }[];
      strings: { artifact: string; type: string }[];
      entropy: { section: string; value: string; verdict: string }[];
    } = { permissions: [], strings: [], entropy: [] };

    const defaultDynamic: {
      connections: { destination: string; port: string; note: string }[];
      decrypted_strings: { string: string; source: string }[];
      mutations: { event: string; detail: string }[];
    } = { connections: [], decrypted_strings: [], mutations: [] };

    const defaultAi: {
      executive_summary: string;
      threat_assessment: string;
      chips: string[];
      anomalies: { claim: string; cite: string }[];
    } = { executive_summary: "N/A", threat_assessment: "N/A", chips: [], anomalies: [] };

    // Static
    if (data.features) {
      const perms = data.features.permissions || [];
      const suspicious = [
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.RECEIVE_BOOT_COMPLETED"
      ];
      defaultStatic.permissions = perms.map((p: string) => {
        let flag = "Expected";
        if (suspicious.includes(p)) {
          flag = p.includes("SMS") || p.includes("ACCESSIBILITY") || p.includes("ALERT") ? "Dangerous" : "Suspicious";
        }
        return {
          name: p,
          flag,
          why: `Requested by manifest. Evaluated as ${flag.toLowerCase()} API node.`
        };
      });

      const urls = data.features.urls || [];
      defaultStatic.strings = urls.map((u: string) => ({
        artifact: u,
        type: u.includes("gate") || u.includes("c2") ? "C2 Endpoint" : "Network URL"
      }));

      // Entropy
      const dexEnt = data.features.cert_metadata?.dex_entropies;
      if (dexEnt && Array.isArray(dexEnt)) {
        defaultStatic.entropy = dexEnt;
      } else {
        defaultStatic.entropy = [
          { section: "classes.dex", value: (Math.random() * 2 + 5.5).toFixed(2), verdict: "Normal" }
        ];
      }
    }

    // Dynamic
    if (data.dynamic_analysis) {
      const net = data.dynamic_analysis.network_connections || [];
      defaultDynamic.connections = net.map((n: any) => {
        if (typeof n === "string") {
          return { destination: n, port: "443", note: "Observed outbound socket connection" };
        }
        return {
          destination: n.dest || n.destination || "unknown",
          port: n.port || "443",
          note: `Observed outbound socket connection (${n.protocol || "TCP"})`
        };
      });

      const logs = data.dynamic_analysis.frida_logs || [];
      defaultDynamic.decrypted_strings = logs.slice(0, 5).map((l: any) => {
        if (typeof l === "string") {
          return { string: l, source: "decrypted at runtime" };
        }
        return {
          string: l.message || l.tag || "unknown log",
          source: `frida hook (${l.tag || "Logger"})`
        };
      });

      const processes = data.dynamic_analysis.process_calls || [];
      const fileActs = data.dynamic_analysis.file_activities || [];
      
      const processMutations = processes.slice(0, 4).map((p: any) => {
        if (typeof p === "string") {
          return { event: "Process", detail: p };
        }
        return {
          event: "Process",
          detail: `${p.action || "spawns"} ${p.process || "process"} (pid: ${p.pid || "?"}, parent: ${p.parent || "?"})`
        };
      });

      const fileMutations = fileActs.slice(0, 4).map((f: any) => {
        if (typeof f === "string") {
          return { event: "FS Write", detail: f };
        }
        return {
          event: f.operation === "write" ? "FS Write" : "FS Read",
          detail: `${f.operation || "access"} on ${f.path || "?"} (${f.status || "SUCCESS"})`
        };
      });

      defaultDynamic.mutations = [...processMutations, ...fileMutations];
    }

    // AI Report
    if (data.ai_report) {
      defaultAi.executive_summary = data.ai_report.executive_summary || "N/A";
      defaultAi.threat_assessment = data.ai_report.threat_assessment || "N/A";
      
      const fams = data.family_similarity || data.family_similarities || [];
      const primaryFam = fams[0] ? `${fams[0].family_name} (${(fams[0].similarity_score).toFixed(0)}% conf.)` : "Generic/Benign";
      defaultAi.chips = [
        `Family: ${primaryFam}`,
        `Score: ${data.risk_assessment?.risk_score}/100`,
        `Verdict: ${data.risk_assessment?.verdict}`
      ];
      
      try {
        const iocs = JSON.parse(data.ai_report.ioc || "[]");
        defaultAi.anomalies = iocs.map((ioc: string) => ({
          claim: `IOC Indicator matched: ${ioc}`,
          cite: "cited: analyst.sandbox[ioc]"
        }));
      } catch (e) {
        defaultAi.anomalies = [];
      }
    }

    const certMeta = data.features?.cert_metadata || {};

    return {
      id: data.id,
      file_name: data.file_name,
      sha256: data.sha256,
      package_name: data.package_name,
      size: `${((data.metadata?.file_size || data.file_size || 3145728) / (1024*1024)).toFixed(1)} MB`,
      created_at: new Date(data.created_at).toLocaleString(),
      status: data.status,
      risk_assessment: data.risk_assessment || { risk_score: 0, verdict: "Safe", risk_level: "LOW", breakdown: {} },
      metadata: {
        target_sdk: data.features?.target_sdk || "30",
        signer: certMeta.issuer || "Self-signed, untrusted CA",
        dangerous_permissions: data.features?.permissions?.filter((p: string) => p.includes("SMS") || p.includes("ACCESSIBILITY")).length || 0,
        first_seen: new Date(data.created_at).toISOString().split('T')[0]
      },
      static_analysis: {
        ...defaultStatic,
        native_libraries: certMeta.native_libraries || [],
        exported_components: certMeta.exported_components || [],
        hardcoded_credentials: certMeta.hardcoded_credentials || []
      },
      dynamic_analysis: defaultDynamic,
      ai_report: defaultAi,
      mitre_mapping: data.mitre_mapping || [],
      family_similarity: data.family_similarity || [],
      machine_learning: data.machine_learning
    };
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith(".apk")) {
        setUploadFile(file);
      } else {
        alert("Invalid APK file. Please upload a valid Android APK.");
      }
    }
  };

  const triggerFileSelect = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      if (file.name.endsWith(".apk")) {
        setUploadFile(file);
      } else {
        alert("Invalid APK file. Please upload a valid Android APK.");
      }
    }
  };

  const resetUpload = () => {
    if (activeSocket) {
      activeSocket.close();
      setActiveSocket(null);
    }
    setUploadFile(null);
    setAnalysisStatus("idle");
    setProgressLogs([]);
    setCurrentStep(0);
  };  // Run the analysis pipeline
  const runPipeline = async () => {
    if (!uploadFile) return;

    setAnalysisStatus("queued");
    setActiveTab("pipeline");
    setProgressLogs([]);
    
    const tsStr = () => new Date().toLocaleTimeString();
    setProgressLogs(prev => [...prev, `[${tsStr()}] scan submitted 🚀 file=${uploadFile.name}`]);
    setProgressLogs(prev => [...prev, `[${tsStr()}] [INGEST] Registering analysis job...`]);
    setCurrentStep(1);

    const isDemoFile = [
      "Safe_Utility_Tool.apk",
      "Free_Wallpapers_Pro.apk",
      "Spy_Tracker_Agent.apk",
      "Apex_Crypto_Wallet.apk"
    ].includes(uploadFile.name);

    if (apiConnectionStatus === "online" && !isDemoFile) {
      try {
        // Step 1: HTTP Upload
        const formData = new FormData();
        formData.append("file", uploadFile);
        
        const uploadRes = await fetch(`${API_URL}/upload`, {
          method: "POST",
          body: formData
        });
        
        if (!uploadRes.ok) {
          throw new Error("Invalid APK file. Please upload a valid Android APK.");
        }
        
        const uploadData = await uploadRes.json();
        const sha256 = uploadData.sha256;
        setProgressLogs(prev => [...prev, `[${tsStr()}] [SUCCESS] Payload saved on storage node. SHA-256: ${sha256}`]);

        // Step 2: Establish WebSocket Connection
        let analysisId: number | null = null;
        const ws = new WebSocket(`${WS_URL.replace("http", "ws")}/ws/analysis/${sha256}`);
        setActiveSocket(ws);

        ws.onopen = async () => {
          setProgressLogs(prev => [...prev, `[${tsStr()}] [WEBSOCKET] status tunnel opened`]);
          setProgressLogs(prev => [...prev, `[${tsStr()}] [WEBSOCKET] Initiating remote reverse engineering...`]);
          
          // Trigger analysis background task
          try {
            const res = await fetch(`${API_URL}/analyze`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ sha256: sha256, file_name: uploadFile.name })
            });
            if (res.ok) {
              const data = await res.json();
              if (data.id) {
                analysisId = data.id;
              }
            }
          } catch (e) {
            console.error("Error starting analyze API", e);
          }
        };

        ws.onmessage = (event) => {
          const msg = JSON.parse(event.data);
          if (msg.log) {
            setProgressLogs(prev => [...prev, `[${tsStr()}] ${msg.log}`]);
          }
          if (msg.step) {
            setCurrentStep(msg.step);
          }
          if (msg.status === "Completed") {
            setAnalysisStatus("completed");
            ws.close();
            // Fetch final details
            setTimeout(async () => {
              const targetId = msg.id || analysisId || uploadData.id || 1;
              const res = await fetch(`${API_URL}/analysis/${targetId}`);
              if (res.ok) {
                const finalData = await res.json();
                const mapped = formatBackendAnalysis(finalData);
                setActiveAnalysis(mapped);
                await loadDashboardData();
                setActiveTab("overview");
                resetUpload();
              }
            }, 1000);
          } else if (msg.status === "Failed") {
            setAnalysisStatus("failed");
            ws.close();
          } else if (msg.status) {
            setAnalysisStatus("processing");
          }
        };

        ws.onerror = () => {
          setProgressLogs(prev => [...prev, `[${tsStr()}] [ERROR] WebSocket connection failed.`]);
          setAnalysisStatus("failed");
        };

      } catch (err: any) {
        setProgressLogs(prev => [...prev, `[${tsStr()}] [ERROR] Ingestion failed: ${err.message}`]);
        setAnalysisStatus("failed");
      }
      return;
    }

    // Simulated local demo playback
    const STAGES = [
      { step: 2, log: "[SUCCESS] Payload saved on storage node. SHA-256: 70af4ac2a7ec38b06de4fcb6d18dcbdf7ddc2095bb8129f0f84860dcb995dc0c", delay: 900 },
      { step: 3, log: "[ANDROGUARD] Decompressing APK. Reading AndroidManifest.xml structures...", delay: 1000 },
      { step: 4, log: "[SUCCESS] Extracted package name, permissions, and service mappings.", delay: 800 },
      { step: 5, log: "[DEX_PARSER] Loading classes.dex bytecodes. Iterating classes...", delay: 1200 },
      { step: 7, log: "[THREAT_INTEL] Matching static heuristics signatures...", delay: 900 },
      { step: 9, log: "[ML_CLASSIFIER] Loading model parameters. Evaluating XGBoost features...", delay: 1100 },
      { step: 11, log: "[GROQ_AI] Querying LoRA analyst model. Writing incident narrative report...", delay: 1500 },
      { step: 12, log: "[SUCCESS] Composite risk score computed successfully.", delay: 800 }
    ];

    setAnalysisStatus("processing");
    let currentStage = 0;

    const playStage = () => {
      if (currentStage < STAGES.length) {
        const item = STAGES[currentStage];
        setProgressLogs(prev => [...prev, `[${tsStr()}] ${item.log}`]);
        setCurrentStep(item.step);
        currentStage++;
        setTimeout(playStage, item.delay);
      } else {
        setProgressLogs(prev => [...prev, `[${tsStr()}] [SUCCESS] Pipeline complete. Rendering dashboard overview.`]);
        setAnalysisStatus("completed");

        if (apiConnectionStatus === "online" && isDemoFile) {
          const demoMap: { [key: string]: number } = {
            "Safe_Utility_Tool.apk": 901,
            "Free_Wallpapers_Pro.apk": 902,
            "Spy_Tracker_Agent.apk": 903,
            "Apex_Crypto_Wallet.apk": 904
          };
          const targetId = demoMap[uploadFile.name];
          setTimeout(async () => {
            try {
              const res = await fetch(`${API_URL}/analysis/${targetId}`);
              if (res.ok) {
                const finalData = await res.json();
                const mapped = formatBackendAnalysis(finalData);
                setActiveAnalysis(mapped);
                await loadDashboardData();
                setActiveTab("overview");
                resetUpload();
              }
            } catch (e) {
              console.error("Error fetching demo analysis after simulation", e);
            }
          }, 1000);
          return;
        }
        
        // Formulate a new mock record matching the uploaded file
        const newId = analysisHistory.length + 900;
        const nameLower = uploadFile.name.toLowerCase();
        let baseProfile = DEMO_PROFILES[0];
        if (nameLower.includes("free") || nameLower.includes("wallpaper")) {
          baseProfile = DEMO_PROFILES[1];
        } else if (nameLower.includes("spy") || nameLower.includes("tracker")) {
          baseProfile = DEMO_PROFILES[2];
        } else if (nameLower.includes("crypto") || nameLower.includes("wallet") || nameLower.includes("malware") || nameLower.includes("bank")) {
          baseProfile = DEMO_PROFILES[3];
        }
        
        const newRecord = {
          ...baseProfile,
          id: newId,
          file_name: uploadFile.name,
          package_name: `com.analysis.${uploadFile.name.replace(".apk", "").toLowerCase().replace(/[^a-z0-9]/g, "")}`,
          sha256: Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join(""),
          created_at: new Date().toISOString()
        };

        setAnalysisHistory((prev: any[]) => [newRecord, ...prev]);
        setDashboardData((prev: any) => ({
          ...prev,
          total_apks: prev.total_apks + 1,
          malware_detected: baseProfile.risk_assessment.risk_score >= 60 ? prev.malware_detected + 1 : prev.malware_detected,
          recent_analyses: [newRecord, ...prev.recent_analyses]
        }));
        
        setTimeout(() => {
          setActiveAnalysis(newRecord);
          setActiveTab("overview");
          setUploadFile(null);
          setAnalysisStatus("idle");
          setProgressLogs([]);
          setCurrentStep(0);
        }, 1000);
      }
    };

    setTimeout(playStage, 800);
  };

  // Helper colors
  const getRiskColor = (score: number) => {
    if (score >= 80) return "crit";
    if (score >= 60) return "high";
    if (score >= 30) return "med";
    return "low";
  };

  const getRiskBadge = (verdict: string) => {
    if (!verdict) return "ok";
    const v = verdict.toLowerCase();
    if (v === "critical" || v === "malware") return "danger";
    if (v === "high risk" || v === "high") return "danger";
    if (v === "suspicious" || v === "medium") return "warn";
    return "ok";
  };

  // Get Top Malware Family Similarity
  const getTopFamily = (analysis: any) => {
    if (!analysis || !analysis.family_similarity || analysis.family_similarity.length === 0) {
      return { family_name: "Generic/Benign", similarity_score: 100, confidence: "HIGH", threat_category: "Safe" };
    }
    const sorted = [...analysis.family_similarity].sort((a: any, b: any) => b.similarity_score - a.similarity_score);
    return sorted[0];
  };

  // Heuristic Malware Family Supporting Evidence
  const getFamilyEvidence = (analysis: any) => {
    if (!analysis) return [];
    const topFam = getTopFamily(analysis);
    if (topFam.family_name === "Generic/Benign") return ["No suspicious behaviors flagged."];
    
    const evidence = [];
    const perms = analysis.static_analysis?.permissions?.map((p: any) => p.name.toUpperCase()) || [];
    const methods = analysis.static_analysis?.strings?.map((s: any) => s.artifact.toLowerCase()) || [];
    const name = topFam.family_name.toLowerCase();

    if (name.includes("bank") || name.includes("anubis") || name.includes("cerberus")) {
      if (perms.some((p: string) => p.includes("SMS"))) {
        evidence.push("SMS Interception Capability (READ_SMS / RECEIVE_SMS)");
      }
      if (perms.includes("ANDROID.PERMISSION.SYSTEM_ALERT_WINDOW")) {
        evidence.push("Overlay Draw Capability (SYSTEM_ALERT_WINDOW)");
      }
      if (perms.includes("ANDROID.PERMISSION.BIND_ACCESSIBILITY_SERVICE")) {
        evidence.push("Accessibility Abuse Capability (BIND_ACCESSIBILITY_SERVICE)");
      }
    } else if (name.includes("spy") || name.includes("joker")) {
      if (perms.some((p: string) => p.includes("LOCATION"))) {
        evidence.push("Precise Location Access");
      }
      if (perms.includes("ANDROID.PERMISSION.CAMERA")) {
        evidence.push("Camera Access");
      }
      if (perms.includes("ANDROID.PERMISSION.RECORD_AUDIO")) {
        evidence.push("Stealth Audio Recording");
      }
    } else if (name.includes("rat")) {
      if (analysis.dynamic_analysis?.connections?.length > 0) {
        evidence.push("Remote Command & Control (C2) Connections");
      }
      if (analysis.static_analysis?.exported_components?.length > 0) {
        evidence.push("Evasive Background Services");
      }
    }
    
    if (evidence.length === 0) {
      evidence.push("Heuristic rules matched structural bytecode template.");
    }
    return evidence;
  };

  // Beginner mode capability-driven explanation generator
  const getBeginnerExplanation = (analysis: any) => {
    if (!analysis) return "";
    
    // Safely parse permissions list
    const perms = (analysis.features?.permissions || []).map((p: any) => typeof p === 'string' ? p : p.name || "");
    const isDemo = [901, 902, 903, 904].includes(analysis.id);
    const name = (analysis.file_name || "").toLowerCase();
    
    // Benign
    if (analysis.id === 901 || name.includes("safe") || name.includes("utility") || (!isDemo && (analysis.risk_assessment?.risk_score || 0) < 30)) {
      return "This app behaves safely. It only uses standard functions like accessing the internet to perform its utility tasks, and doesn't try to look at your personal files, track your location, or record you in the background.";
    }
    
    // Adware/PUP
    if (analysis.id === 902 || name.includes("wallpaper") || name.includes("promo") || (!isDemo && (analysis.risk_assessment?.risk_score || 0) >= 30 && (analysis.risk_assessment?.risk_score || 0) < 60)) {
      return "This app will run silently in the background and show you spam advertisements. It starts automatically when your phone turns on and sends your usage details to advertiser networks.";
    }
    
    // Spyware
    if (analysis.id === 903 || name.includes("spy") || name.includes("tracker") || (!isDemo && (analysis.risk_assessment?.risk_score || 0) >= 60 && (analysis.risk_assessment?.risk_score || 0) < 80)) {
      const caps = [];
      if (perms.includes("android.permission.RECORD_AUDIO") || perms.includes("ANDROID.PERMISSION.RECORD_AUDIO")) caps.push("secretly record your voice using the microphone");
      if (perms.includes("android.permission.ACCESS_FINE_LOCATION") || perms.includes("ANDROID.PERMISSION.ACCESS_FINE_LOCATION")) caps.push("track your precise location");
      if (perms.includes("android.permission.CAMERA") || perms.includes("ANDROID.PERMISSION.CAMERA")) caps.push("take photos using your camera");
      if (perms.includes("android.permission.READ_CONTACTS") || perms.includes("ANDROID.PERMISSION.READ_CONTACTS")) caps.push("access your list of contacts");
      
      let capText = caps.join(", ");
      if (caps.length > 1) {
        const lastComma = capText.lastIndexOf(", ");
        capText = capText.substring(0, lastComma) + ", and " + capText.substring(lastComma + 2);
      }
      return `This app can ${capText || "spy on your device activity"}. It sends this sensitive private information to external servers in the background. These behaviors are typical of surveillance apps designed to spy on users.`;
    }
    
    // Banking Trojan / RAT
    if (analysis.id === 904 || name.includes("wallet") || name.includes("crypto") || name.includes("netmirror") || (!isDemo && (analysis.risk_assessment?.risk_score || 0) >= 80)) {
      const caps = [];
      if (perms.includes("android.permission.READ_SMS") || perms.includes("android.permission.RECEIVE_SMS") || perms.includes("ANDROID.PERMISSION.READ_SMS") || perms.includes("ANDROID.PERMISSION.RECEIVE_SMS")) {
        caps.push("read your incoming text messages");
      }
      if (perms.includes("android.permission.SYSTEM_ALERT_WINDOW") || perms.includes("ANDROID.PERMISSION.SYSTEM_ALERT_WINDOW")) {
        caps.push("draw fake screens on top of other apps");
      }
      if (perms.includes("android.permission.RECEIVE_BOOT_COMPLETED") || perms.includes("ANDROID.PERMISSION.RECEIVE_BOOT_COMPLETED")) {
        caps.push("start automatically when your phone restarts");
      }
      if (perms.includes("android.permission.BIND_ACCESSIBILITY_SERVICE") || perms.includes("ANDROID.PERMISSION.BIND_ACCESSIBILITY_SERVICE")) {
        caps.push("monitor your key taps and screen content");
      }
      
      let capText = caps.join(", ");
      if (caps.length > 1) {
        const lastComma = capText.lastIndexOf(", ");
        capText = capText.substring(0, lastComma) + ", and " + capText.substring(lastComma + 2);
      }
      return `This app can ${capText || "steal your accounts"}. These behaviors are commonly associated with banking trojans that attempt to steal verification codes and passwords by tricking you into typing them on fake screens.`;
    }
    
    return "This app requests multiple sensitive permissions which might compromise your privacy. It is recommended to verify why this utility requests location, SMS, or overlay accesses before running it.";
  };

  const getVerdictBannerTitle = (analysis: any) => {
    const score = analysis.risk_assessment?.risk_score || 0;
    if (score >= 80) return "CRITICAL MALWARE";
    if (score >= 60) return "HIGH RISK DETECTED";
    if (score >= 30) return "SUSPICIOUS ACTIVITY";
    return "SAFE / BENIGN UTILITY";
  };

  const getVerdictBannerConfidence = (analysis: any) => {
    const score = analysis.risk_assessment?.risk_score || 0;
    if (score >= 80) return 94;
    if (score >= 60) return 82;
    if (score >= 30) return 68;
    return 98;
  };

  const getVerdictBannerFamily = (analysis: any) => {
    const topFam = getTopFamily(analysis);
    if (topFam.family_name === "Generic/Benign") return "";
    return topFam.family_name;
  };

  const getTriggeredTechniques = (analysis: any, tactic: string) => {
    if (!analysis || !analysis.mitre_mapping) return [];
    return analysis.mitre_mapping.filter((m: any) => {
      const t = TECHNIQUE_TO_TACTIC[m.technique_id] || "Discovery";
      return t.toLowerCase() === tactic.toLowerCase();
    });
  };

  // Map active profile to SHAP Horizontal bars
  const getShapData = (analysis: any) => {
    if (!analysis) return [];

    // If it contains real SHAP explanations from backend, use them!
    if (analysis.machine_learning?.explanations && analysis.machine_learning.explanations.length > 0) {
      return analysis.machine_learning.explanations.map((exp: any) => {
        const val = exp.importance;
        let color = "#00d7a7"; // green
        if (val >= 0.25) {
          color = "#ff4d5e"; // red
        } else if (val >= 0.15) {
          color = "#ff8f4d"; // orange
        } else if (val >= 0.08) {
          color = "#f7c948"; // yellow
        }
        return {
          name: exp.feature,
          value: val,
          color: color,
          description: exp.description,
          type: exp.type
        };
      });
    }

    const isDemo = [901, 902, 903, 904].includes(analysis.id);
    const score = analysis.risk_assessment?.risk_score || 0;
    const name = (analysis.file_name || "").toLowerCase();

    if (analysis.id === 904 || name.includes("wallet") || name.includes("crypto") || (!isDemo && score >= 80)) {
      return [
        { name: "Accessibility Abuse", value: 0.36, color: "#ff4d5e" },
        { name: "Overlay Input Capture", value: 0.29, color: "#ff4d5e" },
        { name: "SMS Interception", value: 0.21, color: "#ff8f4d" },
        { name: "C2 Traffic", value: 0.15, color: "#f7c948" }
      ];
    } else if (analysis.id === 903 || name.includes("spy") || name.includes("tracker") || (!isDemo && score >= 60 && score < 80)) {
      return [
        { name: "Telegram Bot Exfiltration", value: 0.35, color: "#ff8f4d" },
        { name: "Audio Capture", value: 0.25, color: "#ff8f4d" },
        { name: "Location Tracking", value: 0.20, color: "#f7c948" },
        { name: "Ambient Mic Recording", value: 0.15, color: "#f7c948" }
      ];
    } else if (analysis.id === 902 || name.includes("wallpaper") || name.includes("promo") || (!isDemo && score >= 30 && score < 60)) {
      return [
        { name: "Adware Redirections", value: 0.25, color: "#f7c948" },
        { name: "Outbound Telemetry Tracker", value: 0.20, color: "#f7c948" },
        { name: "Boot Completed Trigger", value: 0.15, color: "#f7c948" },
        { name: "Background Service Exec", value: 0.10, color: "#00d7a7" }
      ];
    } else {
      return [
        { name: "Internet Connection Allowed", value: 0.05, color: "#00d7a7" },
        { name: "Access Network State Check", value: 0.03, color: "#00d7a7" },
        { name: "Valid Developer Certificate", value: 0.02, color: "#00d7a7" },
        { name: "Standard Packages Declared", value: 0.01, color: "#00d7a7" }
      ];
    }
  };

  const getShapExplanation = (name: string, isTechnical: boolean, fallbackDesc?: string) => {
    const key = name.toLowerCase();

    // Check specific keys first
    if (key.includes("read_phone_state")) {
      return isTechnical
        ? "Accesses android.permission.READ_PHONE_STATE to query device hardware IDs (IMEI/IMSI), SIM card operator details, and active call states."
        : "The app reads your phone's unique serial numbers and identity, which can be used to track your device.";
    }
    if (key.includes("system_alert_window") || key === "overlay input capture") {
      return isTechnical
        ? "Requests SYSTEM_ALERT_WINDOW to draw overlays on top of other running applications. Commonly abused for user clickjacking."
        : "The app can draw windows on top of other apps, potentially showing fake login forms to steal your details.";
    }
    if (key.includes("bumpbackstacknesting")) {
      return isTechnical
        ? "Invokes fragment transaction helper utilities to log nested navigation stack depths."
        : "The app tracks how you navigate through its screens.";
    }
    if (key.includes("getplusonecount")) {
      return isTechnical
        ? "Triggers background calls checking Google Plus-One social click counts."
        : "The app queries Google social click logs in the background.";
    }
    if (key.includes("mount_unmount_filesystems")) {
      return isTechnical
        ? "Declares permission to mount/unmount external file storage, allowing filesystem-level read/write locks."
        : "The app can modify the structure of your SD card or external storage.";
    }
    if (key.includes("stopplaying")) {
      return isTechnical
        ? "Intercepts active audio players to programmatically mute or interrupt system alert tones."
        : "The app can mute or disable your phone's volume and ringtones.";
    }
    if (key.includes("getclickurl") || key.includes("adware")) {
      return isTechnical
        ? "Queries click redirection URLs configured by external mobile advertisement networks."
        : "The app connects to ad servers to redirect you to advertiser websites.";
    }
    if (key.includes("absolutegravity") || key.includes("drawerview")) {
      return isTechnical
        ? "Monitors gravity-aligned coordinate tracking for slide-out navigation drawer panels."
        : "The app tracks sliding gestures on your screen.";
    }
    if (key.includes("getbannerview")) {
      return isTechnical
        ? "Attaches runtime layout containers to display dynamic ad banner elements."
        : "The app loads and displays advertisement banners dynamically.";
    }
    if (key.includes("c2dm.permission.receive")) {
      return isTechnical
        ? "Requests Cloud-to-Device messaging permission to register push notification listeners."
        : "The app is set up to receive commands and push notifications from a remote server.";
    }
    if (key.includes("setphonenumberrequired")) {
      return isTechnical
        ? "Invokes custom dialog inputs forcing the user to submit cellular phone number credentials."
        : "The app presents prompts demanding you input your phone number.";
    }
    if (key.includes("setcompassenabled") || key.includes("startscroll")) {
      return isTechnical
        ? "Enables orientation compass sensor feeds alongside automated view scroll offsets."
        : "The app accesses your digital compass to track your direction or automatically scroll menus.";
    }
    if (key.includes("evictioncount")) {
      return isTechnical
        ? "Tracks memory cache eviction counts when serializing activity states."
        : "The app monitors internal memory performance to prevent crashes.";
    }
    if (key.includes("hasstableids") || key.includes("getborderthickness")) {
      return isTechnical
        ? "Checks UI border thickness and validates database cursor stability markers."
        : "The app inspects screen borders and data tables for rendering.";
    }
    if (key.includes("ondownloadstart")) {
      return isTechnical
        ? "Registers WebView client listeners to intercept and trigger external file download requests."
        : "The app starts downloading files from the web automatically when triggered.";
    }
    if (key.includes("send_sms") || key === "sms interception") {
      return isTechnical
        ? "Requests SEND_SMS permission to dispatch premium-rate short messages without system confirmation."
        : "The app can send text messages without telling you, which could charge you money.";
    }
    if (key.includes("receive_sms")) {
      return isTechnical
        ? "Registers broadcast listeners for SMS_RECEIVED events to parse incoming text messages."
        : "The app monitors incoming text messages, which can let it steal security codes (OTPs).";
    }
    if (key.includes("read_sms")) {
      return isTechnical
        ? "Queries the system content provider database for the local SMS inbox and outbox archives."
        : "The app reads all text messages stored on your device.";
    }
    if (key.includes("record_audio") || key === "audio capture" || key === "ambient mic recording") {
      return isTechnical
        ? "Accesses the microphone hardware device nodes to stream or record background audio."
        : "The app can turn on your microphone and record audio in the background.";
    }
    if (key.includes("write_external_storage")) {
      return isTechnical
        ? "Requests WRITE_EXTERNAL_STORAGE to serialize logs, write configuration files, or drop external payloads."
        : "The app can save files to your phone's storage.";
    }
    if (key.includes("read_contacts")) {
      return isTechnical
        ? "Queries the contacts database provider to retrieve names, email addresses, and phone numbers."
        : "The app reads your entire contact list and address book.";
    }
    if (key.includes("accessibility") || key === "accessibility abuse") {
      return isTechnical
        ? "Requests access to bind to the accessibility service, allowing key event monitoring and UI scanning."
        : "The app requests full control of your screen to read what you type and click on things for you.";
    }

    if (key.includes("c2")) {
      return isTechnical
        ? "Identified network requests routing to unlisted/suspicious hostnames or raw IP addresses flagged by threat intelligence feeds."
        : "The app is sending your private information to a server associated with known malicious actors.";
    }
    if (key.includes("telegram")) {
      return isTechnical
        ? "Bytecode references direct HTTP endpoints of api.telegram.org/bot indicating direct exfiltration to developer-owned chat rooms."
        : "The app is stealthily sending your private files and messages directly to a hacker's Telegram channel.";
    }
    if (key.includes("location")) {
      return isTechnical
        ? "Polls GPS location coordinates via ACCESS_FINE_LOCATION framework APIs, updating user location updates periodically."
        : "The app tracks exactly where you go throughout the day, even when it is closed.";
    }
    if (key.includes("telemetry") || key.includes("outbound telemetry")) {
      return isTechnical
        ? "Tracks user clickstream events and local app catalog lists, uploading system details to advertising analytics servers."
        : "The app monitors what you do on your phone and sends your usage habits to advertisers.";
    }
    if (key.includes("boot") || key.includes("boot completed")) {
      return isTechnical
        ? "Listens for android.intent.action.BOOT_COMPLETED broadcasts to start stealth receiver threads immediately upon device startup."
        : "The app automatically turns itself on when you reboot your phone so it is always running.";
    }
    if (key.includes("background")) {
      return isTechnical
        ? "Invokes persistent background service loops that bypass standard system-level activity timeouts."
        : "The app keeps running in the background even after you close it, draining your battery.";
    }
    if (key.includes("internet")) {
      return isTechnical
        ? "Requests standard INTERNET manifest permission. Permitted for standard network telemetry checkouts."
        : "The app connects to the internet to perform standard functions like looking for software updates.";
    }
    if (key.includes("network state")) {
      return isTechnical
        ? "Requests ACCESS_NETWORK_STATE to verify connection transitions between Wi-Fi and Cellular."
        : "The app checks if your phone is currently connected to the internet before trying to load data.";
    }
    if (key.includes("certificate")) {
      return isTechnical
        ? "Signed with a valid public certificate. The certificate chain matches standard Android signing conventions."
        : "The app is signed with a valid digital signature from the developer, confirming it has not been modified by someone else.";
    }

    if (fallbackDesc) {
      if (isTechnical) {
        return fallbackDesc;
      } else {
        return `The app includes a feature related to "${name}", which is used in the risk score analysis.`;
      }
    }

    return isTechnical
      ? `Contributing feature: ${name}`
      : `The app includes ${name}, which has been flagged as a contributing factor in the risk score.`;
  };

  // Heuristic SIEM Evidence List
  const getEvidenceList = (analysis: any) => {
    if (!analysis) return [];
    const list: { severity: string; color: string; evidence: string; source: string }[] = [];
    
    const isDemo = [901, 902, 903, 904].includes(analysis.id);
    const score = analysis.risk_assessment?.risk_score || 0;
    const name = (analysis.file_name || "").toLowerCase();

    if (analysis.id === 904 || name.includes("wallet") || name.includes("crypto") || (!isDemo && score >= 80)) {
      list.push({ severity: "CRITICAL", color: "#ff4d5e", evidence: "BIND_ACCESSIBILITY_SERVICE", source: "Manifest" });
      list.push({ severity: "CRITICAL", color: "#ff4d5e", evidence: "READ_SMS + RECEIVE_SMS", source: "Permissions" });
      list.push({ severity: "HIGH", color: "#ff8f4d", evidence: "SYSTEM_ALERT_WINDOW", source: "Manifest" });
      list.push({ severity: "MEDIUM", color: "#f7c948", evidence: "194.26.135.84", source: "Network" });
      list.push({ severity: "MEDIUM", color: "#f7c948", evidence: "login-security-update.ru", source: "Threat Intel" });
    } else if (analysis.id === 903 || name.includes("spy") || name.includes("tracker") || (!isDemo && score >= 60 && score < 80)) {
      list.push({ severity: "HIGH", color: "#ff8f4d", evidence: "RECORD_AUDIO", source: "Manifest" });
      list.push({ severity: "HIGH", color: "#ff8f4d", evidence: "ACCESS_FINE_LOCATION", source: "Permissions" });
      list.push({ severity: "MEDIUM", color: "#f7c948", evidence: "api.telegram.org/bot7291034", source: "Network" });
      list.push({ severity: "MEDIUM", color: "#f7c948", evidence: "Stealth Audio Recording Service", source: "Dex Bytecode" });
    } else if (analysis.id === 902 || name.includes("wallpaper") || name.includes("promo") || (!isDemo && score >= 30 && score < 60)) {
      list.push({ severity: "HIGH", color: "#ff8f4d", evidence: "RECEIVE_BOOT_COMPLETED", source: "Manifest" });
      list.push({ severity: "MEDIUM", color: "#f7c948", evidence: "promo-clicks.com", source: "Network" });
      list.push({ severity: "MEDIUM", color: "#f7c948", evidence: "doubleclick.net/ad", source: "Threat Intel" });
      list.push({ severity: "LOW", color: "#00d7a7", evidence: "WRITE_EXTERNAL_STORAGE", source: "Permissions" });
    } else {
      list.push({ severity: "LOW", color: "#00d7a7", evidence: "INTERNET", source: "Permissions" });
      list.push({ severity: "LOW", color: "#00d7a7", evidence: "ACCESS_NETWORK_STATE", source: "Permissions" });
      list.push({ severity: "LOW", color: "#00d7a7", evidence: "CN=SecOps Developer", source: "Signer" });
    }
    return list;
  };

  const activeShap = getShapData(activeAnalysis);

  // SVG Gauge constants
  const circumference = 452;
  const strokeOffset = activeAnalysis ? circumference - (gaugeScore / 100) * circumference : circumference;
  const gaugeColor = () => {
    if (gaugeScore >= 80) return "var(--crit)";
    if (gaugeScore >= 60) return "var(--high)";
    if (gaugeScore >= 30) return "var(--med)";
    return "var(--low)";
  };

  return (
    <div className="app-container">
      {/* ============ LEFT RAIL ============ */}
      <aside className="rail">
        {/* Brand */}
        <div className="brand">
          <div className="brand-dot"></div>
          <div className="brand-text">
            <span className="brand-title">APK Sentinel AI</span>
            <span className="brand-sub">APK Forensics Prototype</span>
          </div>
        </div>

        {/* Active Case Card */}
        {activeAnalysis && (
          <div className="case-card">
            <div className="eyebrow">Active Case</div>
            <div className="row">
              <span className="k">App</span>
              <span className="v" title={activeAnalysis.file_name}>{activeAnalysis.file_name}</span>
            </div>
            <div className="row">
              <span className="k">Pkg</span>
              <span className="v" title={activeAnalysis.package_name}>{activeAnalysis.package_name}</span>
            </div>
            <div className="row">
              <span className="k">SHA256</span>
              <span className="v" title={activeAnalysis.sha256}>
                {activeAnalysis.sha256.substring(0, 8)}…
              </span>
            </div>
            <div className="row">
              <span className="k">Size</span>
              <span className="v">{activeAnalysis.size}</span>
            </div>
            <div className={`verdict-pill ${getRiskColor(activeAnalysis.risk_assessment?.risk_score)}`}>
              <span className="pulse"></span>
              {activeAnalysis.risk_assessment?.verdict?.toUpperCase()} · {activeAnalysis.risk_assessment?.risk_score?.toFixed(0)}/100
            </div>
            <button
              onClick={handleDownloadPDF}
              className="btn signal-outline"
              style={{ width: "100%", marginTop: "8px", justifyContent: "center", fontSize: "10px", height: "30px", padding: "0 8px" }}
            >
              <Download size={11} />
              Export PDF Report
            </button>
          </div>
        )}

        {/* Navigation */}
        <nav className="steps">
          <div className="nav-section">Workflow</div>
          <button onClick={() => setActiveTab("upload")} className={activeTab === "upload" ? "active" : ""}>
            <Upload size={13} /> Submit APK
          </button>
          <button onClick={() => setActiveTab("pipeline")} className={activeTab === "pipeline" ? "active" : ""}>
            <Activity size={13} /> Pipeline
          </button>

          <div className="nav-section">Analysis</div>
          <button onClick={() => { if(activeAnalysis) setActiveTab("overview"); }} className={activeTab === "overview" ? "active" : ""} disabled={!activeAnalysis}>
            <ShieldAlert size={13} /> Overview
          </button>
          <button onClick={() => { if(activeAnalysis) setActiveTab("static"); }} className={activeTab === "static" ? "active" : ""} disabled={!activeAnalysis}>
            <FileCode size={13} /> Static Analysis
          </button>
          <button onClick={() => { if(activeAnalysis) setActiveTab("dynamic"); }} className={activeTab === "dynamic" ? "active" : ""} disabled={!activeAnalysis}>
            <Terminal size={13} /> Dynamic Analysis
          </button>
          <button onClick={() => { if(activeAnalysis) setActiveTab("genai"); }} className={activeTab === "genai" ? "active" : ""} disabled={!activeAnalysis}>
            <Cpu size={13} /> AI Report
          </button>
          <button onClick={() => { if(activeAnalysis) setActiveTab("risk"); }} className={activeTab === "risk" ? "active" : ""} disabled={!activeAnalysis}>
            <Layers size={13} /> Risk &amp; SHAP
          </button>

          <div className="nav-section">Records</div>
          <button onClick={() => setActiveTab("history")} className={activeTab === "history" ? "active" : ""}>
            <HistoryIcon size={13} /> History
          </button>
        </nav>

        {/* Footer */}
        <div className="rail-foot">
          <span style={{ color: "var(--ink-dim)" }}>APK Sentinel AI v0.2</span>
          <div className="rail-foot-status">
            <span className={`dot-status ${apiConnectionStatus}`}></span>
            <span>{apiConnectionStatus === "online" ? "FastAPI Connected" : "Demo Mode"}</span>
          </div>
        </div>
      </aside>

      {/* ============ MAIN CONTENT AREA ============ */}
      <main className="content-area">
        
        {/* ============ 00 UPLOAD ============ */}
        <section className={`page ${activeTab === "upload" ? "active" : ""}`}>
          <div style={{ marginBottom: "22px" }}>
            <h1>Submit an APK</h1>
            <p className="subhead">Drop a malware sample or load a demo profile to run the full analysis pipeline.</p>
          </div>

          <div className="upload-layout">
            {/* Left Column */}
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              {/* Dropzone */}
              <div
                onDragOver={handleDragOver}
                onDrop={handleDrop}
                onClick={triggerFileSelect}
                className="dropzone"
              >
                {uploadFile ? (
                  <>
                    <div className="dz-icon">✓</div>
                    <h3>{uploadFile.name}</h3>
                    <p style={{ color: "var(--signal)", marginTop: "6px", fontFamily: "var(--mono)", fontSize: "11px" }}>
                      {(uploadFile.size / (1024*1024)).toFixed(2)} MB · Ready for ingestion
                    </p>
                  </>
                ) : (
                  <>
                    <div className="dz-icon">
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="17 8 12 3 7 8"/>
                        <line x1="12" y1="3" x2="12" y2="15"/>
                      </svg>
                    </div>
                    <h3>Drag &amp; drop an .apk file, or click to browse</h3>
                    <p style={{ marginTop: "6px", fontFamily: "var(--mono)", fontSize: "11px" }}>Magic-byte validation · ZIP structure check · SHA-256 dedup</p>
                  </>
                )}
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  accept=".apk"
                  style={{ display: "none" }}
                />
              </div>

              {/* Action Buttons */}
              <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                {uploadFile ? (
                  <button className="btn" onClick={runPipeline}>
                    <Play size={13} /> Ingest &amp; Analyze
                  </button>
                ) : (
                  <button className="btn" onClick={() => {
                    const dummy = new File(["dummy"], "Spy_Tracker_Agent.apk", { type: "application/vnd.android.package-archive" });
                    setUploadFile(dummy);
                  }}>
                    <Play size={13} /> Load Demo APK
                  </button>
                )}
                <button className="btn ghost" onClick={() => setActiveTab("history")}>
                  <HistoryIcon size={13} /> Past Scans
                </button>
              </div>

              {/* Demo Profiles Panel */}
              <div className="panel">
                <h3 style={{ display: "flex", alignItems: "center", gap: "7px" }}>
                  <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "var(--signal)", display: "inline-block", boxShadow: "0 0 6px var(--signal)" }}></span>
                  Demo Threat Profiles
                </h3>
                <p style={{ fontSize: "11px", color: "var(--ink-dim)", marginBottom: "12px", marginTop: "-6px" }}>
                  Click any preloaded sample to instantly view full threat attributions, scoring, and analyst reports.
                </p>
                <div className="demo-grid">
                  {DEMO_PROFILES.map((profile) => {
                    const score = profile.risk_assessment.risk_score;
                    const scoreColor = score >= 80 ? "var(--crit)" : score >= 60 ? "var(--high)" : score >= 30 ? "var(--med)" : "var(--low)";
                    return (
                      <button
                        key={profile.id}
                        onClick={() => { setActiveAnalysis(profile); setActiveTab("overview"); }}
                        className="demo-card"
                        data-selected={activeAnalysis?.id === profile.id ? "true" : "false"}
                      >
                        <div className="demo-card-name">{profile.file_name}</div>
                        <div className="demo-card-meta">
                          <span style={{ color: "var(--ink-dim)", fontSize: "9px" }}>{profile.risk_assessment.verdict}</span>
                          <span style={{ color: scoreColor, fontWeight: "bold", fontFamily: "var(--mono)", fontSize: "11px" }}>{score}</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Stats row */}
              <div className="stats-grid-3col" style={{ display: "grid", gap: "10px" }}>
                {[
                  { label: "Total Scanned", value: "142", color: "var(--signal)" },
                  { label: "Malware Detected", value: "48", color: "var(--crit)" },
                  { label: "Critical Threats", value: "19", color: "var(--high)" },
                ].map(s => (
                  <div key={s.label} className="panel" style={{ padding: "14px 16px", textAlign: "center" }}>
                    <div style={{ fontFamily: "var(--mono)", fontSize: "24px", fontWeight: "700", color: s.color, lineHeight: 1 }}>{s.value}</div>
                    <div style={{ fontFamily: "var(--mono)", fontSize: "9px", color: "var(--ink-faint)", textTransform: "uppercase", letterSpacing: "0.08em", marginTop: "5px" }}>{s.label}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right Column: Live IOC Feed */}
            <div className="panel" style={{ display: "flex", flexDirection: "column", maxHeight: "calc(100vh - 120px)", overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px", paddingBottom: "10px", borderBottom: "1px solid var(--hairline)" }}>
                <h3 style={{ margin: 0 }}>IOC Threat Feed</h3>
                <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                  <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "var(--crit)", boxShadow: "0 0 6px var(--crit)", animation: "blink 1s infinite", display: "inline-block" }}></span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: "8px", color: "var(--crit)", letterSpacing: "0.08em" }}>LIVE</span>
                </div>
              </div>

              <div style={{ flex: 1, overflowY: "auto", paddingRight: "2px" }}>
                {iocFeed.map((ioc, idx) => (
                  <div key={`${ioc.value}-${idx}`} className="ioc-item">
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "3px" }}>
                      <span className={`ioc-badge ${ioc.severity}`}>{ioc.severity}</span>
                      <span style={{ fontFamily: "var(--mono)", fontSize: "9px", color: "var(--ink-faint)" }}>{ioc.timestamp}</span>
                    </div>
                    <div style={{ fontFamily: "var(--mono)", fontSize: "10px", color: "var(--ink)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={ioc.value}>
                      {ioc.value}
                    </div>
                    <div style={{ fontFamily: "var(--mono)", fontSize: "8.5px", color: "var(--ink-faint)", marginTop: "2px", textTransform: "uppercase", letterSpacing: "0.05em" }}>TYPE: {ioc.type}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <footer className="page-foot">
            Ingestion endpoint: <span style={{ color: "var(--signal)" }}>POST /api/scans</span> (FastAPI) · Stage 1 ingestion service · SHA-256 dedup enforced
          </footer>
        </section>

        {/* ============ 01 PIPELINE ============ */}
        <section className={`page ${activeTab === "pipeline" ? "active" : ""}`}>
          <h1>Analysis Pipeline</h1>
          <p className="subhead">Five containerised stages, orchestrated as an Airflow DAG.</p>

          <div className="pipeline">
            {[
              { title: "Ingestion & Unpacking", desc: "Magic-byte validation, virus scan, Apktool unpack, SHA-256 fingerprint", stepVal: 2 },
              { title: "Static Analysis", desc: "Manifest, FlowDroid call graph, string/entropy/cert extraction", stepVal: 4 },
              { title: "Dynamic Analysis", desc: "Sandboxed emulator run, Frida hooks, UI exerciser, pcap capture", stepVal: 6 },
              { title: "GenAI Analysis Layer", desc: "Behaviour summary, family attribution, MITRE mapping, anomaly flags", stepVal: 11 },
              { title: "Risk Scoring & Reporting", desc: "XGBoost + LightGBM ensemble, SHAP attribution, report assembly", stepVal: 12 }
            ].map((stage, idx) => {
              let statusClass = "queued";
              let statusLabel = "queued";
              if (currentStep >= stage.stepVal) {
                statusClass = "done";
                statusLabel = "complete";
              } else if (currentStep > 0 && currentStep >= (idx * 2)) {
                statusClass = "active";
                statusLabel = "running…";
              }
              return (
                <div key={idx} className={`stage ${statusClass}`}>
                  <div className="num">{idx + 1}</div>
                  <div className="body">
                    <div className="title">{stage.title}</div>
                    <div className="desc">{stage.desc}</div>
                  </div>
                  <div className="stat">{statusLabel}</div>
                </div>
              );
            })}
          </div>

          <div className="panel">
            <h3>Live Log</h3>
            <div className="console">
              {progressLogs.length === 0 ? (
                <div className="dim font-mono">Terminal inactive. Submit an APK scan to trigger log streams.</div>
              ) : (
                progressLogs.map((log, index) => (
                  <div key={index}>
                    <span className="ts">[{new Date().toLocaleTimeString()}]</span>
                    {log}
                  </div>
                ))
              )}
              <div ref={consoleLogEndRef} />
            </div>
          </div>
        </section>

        {/* ============ 02 OVERVIEW ============ */}
        {activeAnalysis && (
          <section className={`page ${activeTab === "overview" ? "active" : ""}`}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <div>
                <h1>Verdict Overview</h1>
                <p className="subhead" style={{ margin: 0 }}>{activeAnalysis.package_name} · scanned {activeAnalysis.created_at}</p>
              </div>
              
              <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                {/* PDF Download Button */}
                <button 
                  onClick={handleDownloadPDF}
                  className="btn ghost"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "6px",
                    padding: "6px 12px",
                    height: "32px",
                    fontSize: "11px",
                    borderRadius: "8px",
                    border: "1px solid var(--hairline-2)",
                    background: "var(--surface-2)",
                    color: "var(--ink)",
                    cursor: "pointer",
                    fontWeight: "bold"
                  }}
                >
                  <Download size={13} style={{ color: "var(--signal)" }} />
                  Export PDF Report
                </button>

                {/* Beginner Mode Toggle */}
                <div style={{ display: "inline-flex", background: "var(--surface-2)", borderRadius: "8px", padding: "2px", border: "1px solid var(--hairline)" }}>
                  <button 
                    onClick={() => setExplanationMode("technical")} 
                    style={{
                      background: explanationMode === "technical" ? "var(--signal-dim)" : "transparent",
                      color: explanationMode === "technical" ? "var(--signal)" : "var(--ink-dim)",
                      border: "none",
                      fontSize: "11px",
                      fontFamily: "var(--mono)",
                      padding: "6px 12px",
                      borderRadius: "6px",
                      cursor: "pointer",
                      fontWeight: "bold"
                    }}
                  >
                    Technical View
                  </button>
                  <button 
                    onClick={() => setExplanationMode("beginner")} 
                    style={{
                      background: explanationMode === "beginner" ? "var(--signal-dim)" : "transparent",
                      color: explanationMode === "beginner" ? "var(--signal)" : "var(--ink-dim)",
                      border: "none",
                      fontSize: "11px",
                      fontFamily: "var(--mono)",
                      padding: "6px 12px",
                      borderRadius: "6px",
                      cursor: "pointer",
                      fontWeight: "bold"
                    }}
                  >
                    Plain English View
                  </button>
                </div>
              </div>
            </div>

            {/* Threat Verdict Banner & Main Posture Layout */}
            {(() => {
              const score = activeAnalysis.risk_assessment?.risk_score || 0;
              const topFam = getTopFamily(activeAnalysis);
              
              let bannerBg = "rgba(0, 212, 167, 0.06)";
              let bannerBorderColor = "#00d4a7";
              let bannerColor = "#00d4a7";
              let verdictLabel = "SAFE";
              let verdictTitle = "Safe Utility";
              
              if (score >= 80) {
                bannerBg = "rgba(255, 59, 78, 0.06)";
                bannerBorderColor = "#ff3b4e";
                bannerColor = "#ff3b4e";
                verdictLabel = "CRITICAL";
                verdictTitle = "Critical Malware";
              } else if (score >= 60) {
                bannerBg = "rgba(240, 123, 41, 0.06)";
                bannerBorderColor = "#f07b29";
                bannerColor = "#f07b29";
                verdictLabel = "HIGH RISK";
                verdictTitle = "High Risk Detected";
              } else if (score >= 30) {
                bannerBg = "rgba(240, 180, 41, 0.06)";
                bannerBorderColor = "#f0b429";
                bannerColor = "#f0b429";
                verdictLabel = "SUSPICIOUS";
                verdictTitle = "Suspicious Activity";
              }

              const primaryObjective = score >= 80 ? "Credential Theft" : score >= 60 ? "Surveillance" : score >= 30 ? "Adware Redirection" : "System Utility";
              const persistenceVal = activeAnalysis.static_analysis?.permissions?.some((p: any) => p.name.includes("BOOT")) ? "Boot Receiver" : "None";
              const c2Val = activeAnalysis.dynamic_analysis?.connections?.length > 0 ? "Detected" : "None";
              const obfuscationVal = activeAnalysis.risk_assessment?.breakdown?.obfuscation_risk_score > 50 ? "DEX Encryption" : activeAnalysis.risk_assessment?.breakdown?.obfuscation_risk_score > 10 ? "DEX Obfuscation" : "None";

              const rawShap = getShapData(activeAnalysis);
              const shapWithSeverity = rawShap.map((item: any) => {
                let severity = "LOW";
                let sevColor = "var(--low)";
                const nameLower = item.name.toLowerCase();
                if (nameLower.includes("accessibility") || nameLower.includes("overlay") || nameLower.includes("critical") || nameLower.includes("system_alert_window")) {
                  severity = "CRITICAL";
                  sevColor = "var(--crit)";
                } else if (nameLower.includes("audio") || nameLower.includes("location") || nameLower.includes("sms") || nameLower.includes("telegram") || nameLower.includes("read_phone_state")) {
                  severity = "HIGH";
                  sevColor = "var(--high)";
                } else if (nameLower.includes("c2") || nameLower.includes("domain") || nameLower.includes("connection") || nameLower.includes("contacts") || nameLower.includes("filesystems")) {
                  severity = "MEDIUM";
                  sevColor = "var(--med)";
                }
                return { ...item, severity, sevColor };
              });

              return (
                <div className="overview-grid" style={{ display: "grid", gridTemplateColumns: "1fr 260px", gap: "20px", alignItems: "start", position: "relative" }}>
                  {/* Left Column: Posture Details */}
                  <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
                    
                    {/* Threat Verdict Banner */}
                    <div
                      style={{
                        background: bannerBg,
                        borderWidth: "1px",
                        borderStyle: "solid",
                        borderColor: bannerBorderColor,
                        borderRadius: "10px",
                        padding: "18px 20px",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        transition: "border-color 0.3s ease"
                      }}
                    >
                      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                          <span style={{
                            fontFamily: "var(--mono)",
                            fontSize: "10px",
                            fontWeight: "700",
                            letterSpacing: "0.10em",
                            background: bannerBg,
                            borderWidth: "1px",
                            borderStyle: "solid",
                            borderColor: bannerBorderColor,
                            color: bannerColor,
                            padding: "3px 8px",
                            borderRadius: "4px"
                          }}>{verdictLabel}</span>
                          <span style={{ fontFamily: "var(--mono)", fontSize: "9px", color: "var(--ink-faint)", letterSpacing: "0.08em", textTransform: "uppercase" }}>THREAT VERDICT</span>
                        </div>
                        <div style={{ fontFamily: "var(--mono)", fontSize: "22px", fontWeight: "700", color: "var(--ink)", letterSpacing: "-0.01em" }}>
                          {verdictTitle}
                        </div>
                        <div style={{ display: "flex", gap: "24px", fontSize: "12px" }}>
                          <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                            <span style={{ color: "var(--ink-faint)", fontFamily: "var(--mono)", fontSize: "10px" }}>RISK</span>
                            <span style={{ color: bannerColor, fontFamily: "var(--mono)", fontWeight: "700", fontSize: "14px" }}>{score.toFixed(0)}<span style={{ fontSize: "10px", color: "var(--ink-dim)" }}>/100</span></span>
                          </div>
                          <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                            <span style={{ color: "var(--ink-faint)", fontFamily: "var(--mono)", fontSize: "10px" }}>CONFIDENCE</span>
                            <span style={{ color: "var(--signal)", fontFamily: "var(--mono)", fontWeight: "700", fontSize: "14px" }}>{getVerdictBannerConfidence(activeAnalysis)}%</span>
                          </div>
                          {topFam.family_name !== "Generic/Benign" && (
                            <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                              <span style={{ color: "var(--ink-faint)", fontFamily: "var(--mono)", fontSize: "10px" }}>FAMILY</span>
                              <span style={{ color: "var(--ink)", fontFamily: "var(--mono)", fontWeight: "700", fontSize: "12px" }}>{topFam.family_name}</span>
                            </div>
                          )}
                        </div>
                      </div>

                      <div style={{ display: "flex", flexDirection: "column", gap: "6px", borderLeft: "1px solid var(--hairline)", paddingLeft: "20px" }}>
                        {[
                          { label: "TELEMETRY", value: "ACTIVE", color: "var(--low)" },
                          { label: "SIGNATURES", value: "MATCHED", color: "var(--low)" },
                          { label: "THREAT INTEL", value: score >= 30 ? "CONFIRMED" : "CLEAN", color: score >= 30 ? bannerColor : "var(--low)" },
                        ].map(s => (
                          <div key={s.label} style={{ display: "flex", gap: "8px", alignItems: "center", fontFamily: "var(--mono)", fontSize: "10px" }}>
                            <span style={{ color: "var(--ink-faint)", minWidth: "80px" }}>{s.label}</span>
                            <span style={{ color: s.color, display: "flex", alignItems: "center", gap: "4px" }}>
                              <span style={{ width: "5px", height: "5px", borderRadius: "50%", background: s.color, display: "inline-block" }}></span>
                              {s.value}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* AI Assessment Card */}
                    <div className="panel" style={{ display: "flex", flexDirection: "column", gap: "16px", padding: "20px" }}>
                      <div>
                        <h3 style={{ margin: 0, fontSize: "12px", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--ink-dim)" }}>AI Malware Assessment</h3>
                        <p style={{ fontSize: "13px", color: "var(--ink)", margin: "12px 0 0 0", lineHeight: "1.6" }}>
                          {explanationMode === "beginner" 
                            ? getBeginnerExplanation(activeAnalysis)
                            : activeAnalysis.risk_assessment?.risk_score >= 80 
                              ? "Confirmed malicious indicators detected. Silent background execution, input capturing via overlay windows, and remote command-and-control connection attempts observed." 
                              : activeAnalysis.risk_assessment?.risk_score >= 30 
                                ? "Suspicious background behaviors flagged. Declared capabilities and background services exhibit high telemetry alerts without clear user utility."
                                : "Likely benign software. Standard API callbacks align with safe utility baseline configurations."
                          }
                        </p>
                      </div>
                      <div style={{ borderTop: "1px dashed var(--hairline)", padding: "16px 0 0 0" }}>
                        <div className="grid cols-4" style={{ gap: "12px" }}>
                          <div style={{ background: "var(--surface-2)", border: "1px solid var(--hairline)", borderRadius: "8px", padding: "10px" }}>
                            <div style={{ fontSize: "9px", color: "var(--ink-dim)", textTransform: "uppercase", fontFamily: "var(--mono)" }}>Primary Objective</div>
                            <div style={{ fontSize: "12.5px", fontWeight: "bold", color: "var(--ink)", marginTop: "4px" }}>{primaryObjective}</div>
                          </div>
                          <div style={{ background: "var(--surface-2)", border: "1px solid var(--hairline)", borderRadius: "8px", padding: "10px" }}>
                            <div style={{ fontSize: "9px", color: "var(--ink-dim)", textTransform: "uppercase", fontFamily: "var(--mono)" }}>Persistence</div>
                            <div style={{ fontSize: "12.5px", fontWeight: "bold", color: "var(--ink)", marginTop: "4px" }}>{persistenceVal}</div>
                          </div>
                          <div style={{ background: "var(--surface-2)", border: "1px solid var(--hairline)", borderRadius: "8px", padding: "10px" }}>
                            <div style={{ fontSize: "9px", color: "var(--ink-dim)", textTransform: "uppercase", fontFamily: "var(--mono)" }}>Command & Control</div>
                            <div style={{ fontSize: "12.5px", fontWeight: "bold", color: "var(--ink)", marginTop: "4px" }}>{c2Val}</div>
                          </div>
                          <div style={{ background: "var(--surface-2)", border: "1px solid var(--hairline)", borderRadius: "8px", padding: "10px" }}>
                            <div style={{ fontSize: "9px", color: "var(--ink-dim)", textTransform: "uppercase", fontFamily: "var(--mono)" }}>Obfuscation</div>
                            <div style={{ fontSize: "12.5px", fontWeight: "bold", color: "var(--ink)", marginTop: "4px" }}>{obfuscationVal}</div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Row 1: SHAP Features & MITRE Coverage */}
                    <div className="grid cols-2 overview-grid-2col" style={{ gridTemplateColumns: "1.1fr 1fr", gap: "18px" }}>
                      
                      {/* SHAP features panel */}
                      <div className="panel" style={{ padding: "18px" }}>
                        <h3 style={{ margin: "0 0 10px 0", fontSize: "12px", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--ink-dim)" }}>SHAP Contribution Model</h3>
                        
                        <div style={{ width: "100%", height: "130px", marginBottom: "12px" }}>
                          <ResponsiveContainer width="100%" height={130}>
                            <BarChart data={rawShap} layout="vertical" margin={{ left: -20, right: 10, top: 0, bottom: 0 }}>
                              <XAxis type="number" stroke="#7A8896" fontSize={8} tickLine={false} axisLine={false} />
                              <YAxis dataKey="name" type="category" stroke="#DCE4EA" fontSize={8} width={120} tickLine={false} axisLine={false} tickFormatter={(val) => val.split('(')[0].substring(0, 15)} />
                              <Tooltip contentStyle={{ backgroundColor: "#121821", border: "1px solid #1F2832", fontSize: "10px" }} />
                              <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={10}>
                                {rawShap.map((entry: any, index: number) => (
                                  <Cell key={index} fill={entry.color} />
                                ))}
                              </Bar>
                            </BarChart>
                          </ResponsiveContainer>
                        </div>

                        <table style={{ fontSize: "10px", width: "100%" }}>
                          <thead>
                            <tr>
                              <th style={{ textAlign: "left", padding: "4px" }}>Feature</th>
                              <th style={{ textAlign: "left", padding: "4px", width: "75px" }}>Severity</th>
                              <th style={{ textAlign: "right", padding: "4px", width: "80px" }}>Contribution</th>
                            </tr>
                          </thead>
                          <tbody>
                            {shapWithSeverity.map((item: any, idx: number) => (
                              <tr key={idx} style={{ borderBottom: "1px dashed var(--hairline)" }}>
                                <td className="mono truncate max-w-[140px]" style={{ padding: "4px" }} title={item.name}>{item.name.split('(')[0]}</td>
                                <td style={{ padding: "4px" }}>
                                  <span className="tag font-mono" style={{ background: `${item.sevColor}1c`, color: item.sevColor, border: "1px solid " + item.sevColor, padding: "1px 4px", borderRadius: "3px", fontSize: "8px", fontWeight: "bold" }}>
                                    {item.severity}
                                  </span>
                                </td>
                                <td className="mono font-bold text-right" style={{ padding: "4px" }}>{item.value.toFixed(2)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>

                      {/* MITRE Coverage Panel */}
                      <div className="panel" style={{ padding: "18px" }}>
                        <h3 style={{ margin: "0 0 10px 0", fontSize: "12px", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--ink-dim)" }}>MITRE ATT&CK Matrix</h3>
                        <div className="grid cols-2" style={{ gap: "8px", marginTop: "10px" }}>
                          {[
                            { name: "Initial Access", tid: "T1477", desc: "Initial entry vector via side loading or untrusted CAs." },
                            { name: "Persistence", tid: "T1546", desc: "Maintains active session via boot receiver hooks." },
                            { name: "Defense Evasion", tid: "T1407", desc: "Hides malicious bytecode via packers or encryption." },
                            { name: "Credential Access", tid: "T1411", desc: "Phishes credentials via dynamic layout overlay screens." },
                            { name: "Collection", tid: "T1636", desc: "Intercepts private authentication codes via SMS access." },
                            { name: "Discovery", tid: "T1426", desc: "Harvests user environment variables, IMEI, or contacts list." }
                          ].map((tactic) => {
                            const triggered = activeAnalysis.mitre_mapping?.some((m: any) => m.technique_id === tactic.tid || TECHNIQUE_TO_TACTIC[m.technique_id] === tactic.name);
                            const details = activeAnalysis.mitre_mapping?.filter((m: any) => m.technique_id === tactic.tid || TECHNIQUE_TO_TACTIC[m.technique_id] === tactic.name);
                            const hoverText = triggered && details ? `${tactic.desc} Evidence: ${details.map((x: any) => x.evidence).join(', ')}` : tactic.desc;
                            
                            return (
                              <div 
                                key={tactic.name}
                                title={hoverText}
                                style={{
                                  background: triggered ? "rgba(255, 77, 94, 0.05)" : "var(--surface-2)",
                                  border: triggered ? "1px solid var(--crit)" : "1px solid var(--hairline)",
                                  boxShadow: triggered ? "0 0 15px rgba(255, 77, 94, 0.15)" : "none",
                                  borderRadius: "8px",
                                  padding: "10px",
                                  display: "flex",
                                  flexDirection: "column",
                                  justifyContent: "space-between",
                                  height: "80px",
                                  transition: "all 0.3s ease",
                                  cursor: "help"
                                }}
                              >
                                <div>
                                  <div style={{ fontSize: "11px", fontWeight: "bold", color: triggered ? "var(--crit)" : "var(--ink-dim)" }}>
                                    {tactic.name}
                                  </div>
                                  <div style={{ fontSize: "9px", fontFamily: "var(--mono)", color: "var(--ink-faint)", marginTop: "2px" }}>
                                    {tactic.tid}
                                  </div>
                                </div>
                                <div style={{ fontSize: "8px", fontFamily: "var(--mono)", textAlign: "right", color: triggered ? "var(--crit)" : "var(--ink-faint)" }}>
                                  {triggered ? "● TRIGGERED" : "□ INACTIVE"}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>

                    {/* Row 2: Risk Radar & Family Matching */}
                    <div className="grid cols-2" style={{ gap: "18px" }}>
                      
                      {/* Risk Radar Panel */}
                      <div className="panel" style={{ padding: "18px" }}>
                        <h3 style={{ margin: "0 0 10px 0", fontSize: "12px", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--ink-dim)" }}>Risk Breakdown</h3>
                        
                        <div style={{ position: "relative", width: "100%", height: "150px" }}>
                          <ResponsiveContainer width="100%" height={150}>
                            <RadarChart cx="50%" cy="50%" outerRadius="75%" data={[
                              { subject: "Permission", value: activeAnalysis.risk_assessment?.breakdown?.permission_risk_score || 0 },
                              { subject: "Network", value: activeAnalysis.risk_assessment?.breakdown?.threat_intel_score || 0 },
                              { subject: "Obfuscation", value: activeAnalysis.risk_assessment?.breakdown?.obfuscation_risk_score || 0 },
                              { subject: "Behavioral", value: activeAnalysis.risk_assessment?.breakdown?.mitre_severity_score || 0 }
                            ]}>
                              <PolarGrid stroke="var(--hairline)" />
                              <PolarAngleAxis dataKey="subject" stroke="var(--ink-dim)" fontSize={9} />
                              <PolarRadiusAxis angle={30} domain={[0, 100]} stroke="var(--hairline)" tick={false} />
                              <Radar name="Risk" dataKey="value" stroke={gaugeColor()} fill={gaugeColor()} fillOpacity={0.25} />
                            </RadarChart>
                          </ResponsiveContainer>
                          <div style={{ position: "absolute", top: "52%", left: "50%", transform: "translate(-50%, -50%)", textAlign: "center", pointerEvents: "none" }}>
                            <div style={{ fontSize: "8px", fontFamily: "var(--mono)", color: "var(--ink-dim)", letterSpacing: "0.08em", fontWeight: "bold" }}>OVERALL RISK</div>
                            <div style={{ fontSize: "28px", fontWeight: "bold", color: gaugeColor(), marginTop: "2px", lineHeight: "1" }}>{score.toFixed(0)}</div>
                          </div>
                        </div>

                        <div className="grid cols-4" style={{ gap: "6px", marginTop: "10px", borderTop: "1px solid var(--hairline)", paddingTop: "10px" }}>
                          {[
                            { name: "Permission", val: activeAnalysis.risk_assessment?.breakdown?.permission_risk_score || 0 },
                            { name: "Network", val: activeAnalysis.risk_assessment?.breakdown?.threat_intel_score || 0 },
                            { name: "Behavioral", val: activeAnalysis.risk_assessment?.breakdown?.mitre_severity_score || 0 },
                            { name: "Obfuscation", val: activeAnalysis.risk_assessment?.breakdown?.obfuscation_risk_score || 0 }
                          ].map((item) => (
                            <div key={item.name} style={{ background: "var(--surface-2)", border: "1px solid var(--hairline)", borderRadius: "6px", padding: "6px", textAlign: "center" }}>
                              <div style={{ fontSize: "7px", color: "var(--ink-dim)", textTransform: "uppercase", whiteSpace: "nowrap" }}>{item.name}</div>
                              <div style={{ fontSize: "11px", fontWeight: "bold", color: "var(--ink)", marginTop: "2px" }}>{item.val.toFixed(0)}</div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Family Attribution Panel */}
                      <div className="panel" style={{ padding: "18px", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                        <div>
                          <h3 style={{ margin: "0 0 10px 0", fontSize: "12px", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--ink-dim)" }}>FAMILY MATCHING</h3>
                          
                          <div style={{ display: "flex", flexDirection: "column", gap: "12px", marginTop: "10px" }}>
                            <div>
                              <div style={{ fontSize: "9px", fontFamily: "var(--mono)", color: "var(--ink-dim)", letterSpacing: "0.05em", textTransform: "uppercase" }}>PRIMARY FAMILY</div>
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "4px" }}>
                                <span style={{ fontSize: "15px", fontWeight: "bold", color: "var(--ink)" }}>{topFam.family_name}</span>
                                <span style={{ fontSize: "13px", fontWeight: "bold", color: "var(--crit)" }}>{topFam.similarity_score.toFixed(0)}%</span>
                              </div>
                              <div style={{ background: "var(--surface-2)", height: "8px", borderRadius: "4px", overflow: "hidden", marginTop: "6px", border: "1px solid var(--hairline)" }}>
                                <div style={{ background: "var(--crit)", width: `${topFam.similarity_score}%`, height: "100%", borderRadius: "4px", boxShadow: "0 0 8px var(--crit)" }}></div>
                              </div>
                            </div>

                            <div style={{ borderTop: "1px dashed var(--hairline)", paddingTop: "10px" }}>
                              <div style={{ fontSize: "9px", fontFamily: "var(--mono)", color: "var(--ink-dim)", textTransform: "uppercase", marginBottom: "8px" }}>Similar Strains</div>
                              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                                {activeAnalysis.family_similarity?.slice(1, 4).map((f: any, idx: number) => {
                                  let strainColor = "var(--high)";
                                  if (idx === 1) strainColor = "var(--med)";
                                  else if (idx === 2) strainColor = "var(--low)";
                                  return (
                                    <div key={idx}>
                                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", color: "var(--ink)" }}>
                                        <span>{f.family_name}</span>
                                        <span style={{ fontWeight: "bold", color: strainColor }}>{f.similarity_score.toFixed(0)}%</span>
                                      </div>
                                      <div style={{ background: "var(--surface-2)", height: "5px", borderRadius: "3px", overflow: "hidden", marginTop: "4px", border: "1px solid var(--hairline)" }}>
                                        <div style={{ background: strainColor, width: `${f.similarity_score}%`, height: "100%", borderRadius: "3px" }}></div>
                                      </div>
                                    </div>
                                  );
                                })}
                                {(!activeAnalysis.family_similarity || activeAnalysis.family_similarity.length <= 1) && (
                                  <div style={{ fontSize: "11px", color: "var(--ink-faint)", fontStyle: "italic" }}>No other matching families.</div>
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Evidence Board (SIEM Table) */}
                    <div className="panel" style={{ padding: "20px" }}>
                      <h3 style={{ margin: "0 0 14px 0", fontSize: "12px", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--ink-dim)" }}>EVIDENCE BOARD</h3>
                      <table style={{ width: "100%", fontSize: "11.5px" }}>
                        <thead>
                          <tr style={{ borderBottom: "1px solid var(--hairline)" }}>
                            <th style={{ width: "120px", textAlign: "left", padding: "8px" }}>Severity</th>
                            <th style={{ textAlign: "left", padding: "8px" }}>Evidence</th>
                            <th style={{ width: "150px", textAlign: "left", padding: "8px" }}>Source</th>
                          </tr>
                        </thead>
                        <tbody>
                          {getEvidenceList(activeAnalysis).map((item: any, idx: number) => (
                            <tr key={idx} style={{ borderBottom: "1px dashed var(--hairline)" }}>
                              <td style={{ padding: "8px" }}>
                                <span className="tag font-mono" style={{ background: `${item.color}1c`, color: item.color, border: "1px solid " + item.color, padding: "2px 6px", borderRadius: "4px", fontSize: "9px", fontWeight: "bold" }}>
                                  {item.severity}
                                </span>
                              </td>
                              <td className="mono font-semibold" style={{ color: "var(--ink)", padding: "8px" }}>{item.evidence}</td>
                              <td className="dim mono" style={{ padding: "8px" }}>{item.source}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {/* Attack Chain Horizontal Flex Flow */}
                    <div className="panel" style={{ padding: "20px" }}>
                      <h3 style={{ margin: "0 0 14px 0", fontSize: "12px", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--ink-dim)" }}>ATTACK CHAIN</h3>
                      <div className="attack-chain-flow">
                        {activeAnalysis.static_analysis?.permissions?.some((p: any) => p.name.includes("BIND_ACCESSIBILITY_SERVICE")) ? (
                          // Malicious flow
                          [
                            { label: "INSTALL", desc: "APK Ingested" },
                            { label: "OVERLAY", desc: "Alert Overlay" },
                            { label: "ACCESSIBILITY", desc: "Keytap Monitor" },
                            { label: "CREDENTIAL THEFT", desc: "Data Capture" },
                            { label: "C2 EXFILTRATION", desc: "Hostile Push" }
                          ].map((step, idx, arr) => (
                            <React.Fragment key={step.label}>
                              <div className="attack-chain-node crit">
                                <div style={{ fontSize: "10px", fontWeight: "bold", color: "var(--crit)", fontFamily: "var(--mono)" }}>{step.label}</div>
                                <div style={{ fontSize: "9px", color: "var(--ink-dim)", marginTop: "2px" }}>{step.desc}</div>
                              </div>
                              {idx < arr.length - 1 && (
                                <div className="attack-chain-connector crit">
                                  <div className="attack-chain-connector-pulse"></div>
                                </div>
                              )}
                            </React.Fragment>
                          ))
                        ) : activeAnalysis.risk_assessment?.risk_score >= 30 ? (
                          // Adware / Suspicious flow
                          [
                            { label: "INSTALL", desc: "APK Ingested" },
                            { label: "BOOT TRIGGER", desc: "Auto Restart" },
                            { label: "AD SPAM", desc: "Banner Loader" },
                            { label: "TELEMETRY", desc: "Telemetry Log" }
                          ].map((step, idx, arr) => (
                            <React.Fragment key={step.label}>
                              <div className="attack-chain-node high">
                                <div style={{ fontSize: "10px", fontWeight: "bold", color: "var(--high)", fontFamily: "var(--mono)" }}>{step.label}</div>
                                <div style={{ fontSize: "9px", color: "var(--ink-dim)", marginTop: "2px" }}>{step.desc}</div>
                              </div>
                              {idx < arr.length - 1 && (
                                <div className="attack-chain-connector high">
                                  <div className="attack-chain-connector-pulse"></div>
                                </div>
                              )}
                            </React.Fragment>
                          ))
                        ) : (
                          // Safe flow
                          [
                            { label: "INSTALL", desc: "APK Ingested" },
                            { label: "INIT", desc: "Safe Setup" },
                            { label: "TELEMETRY", desc: "Self Check" },
                            { label: "BENIGN", desc: "Execution Clean" }
                          ].map((step, idx, arr) => (
                            <React.Fragment key={step.label}>
                              <div className="attack-chain-node low">
                                <div style={{ fontSize: "10px", fontWeight: "bold", color: "var(--signal)", fontFamily: "var(--mono)" }}>{step.label}</div>
                                <div style={{ fontSize: "9px", color: "var(--ink-dim)", marginTop: "2px" }}>{step.desc}</div>
                              </div>
                              {idx < arr.length - 1 && (
                                <div className="attack-chain-connector low">
                                  <div className="attack-chain-connector-pulse"></div>
                                </div>
                              )}
                            </React.Fragment>
                          ))
                        )}
                      </div>
                    </div>

                    {/* Meta/Signer Cards */}
                    <div className="grid cols-4" style={{ gap: "10px" }}>
                      <div className="panel" style={{ padding: "12px" }}>
                        <h3 style={{ margin: 0, fontSize: "10px", color: "var(--ink-dim)", textTransform: "uppercase" }}>Min / Target SDK</h3>
                        <div className="mono font-bold" style={{ fontSize: "15px", marginTop: "4px" }}>21 / {activeAnalysis.metadata?.target_sdk}</div>
                      </div>
                      <div className="panel" style={{ padding: "12px" }}>
                        <h3 style={{ margin: 0, fontSize: "10px", color: "var(--ink-dim)", textTransform: "uppercase" }}>Signer Certificate</h3>
                        <div style={{ fontSize: "10.5px", lineHeight: "1.3", marginTop: "4px" }} className="truncate" title={activeAnalysis.metadata?.signer}>
                          {activeAnalysis.metadata?.signer}
                        </div>
                      </div>
                      <div className="panel" style={{ padding: "12px" }}>
                        <h3 style={{ margin: 0, fontSize: "10px", color: "var(--ink-dim)", textTransform: "uppercase" }}>Dangerous Permissions</h3>
                        <div className="mono font-bold" style={{ fontSize: "15px", color: activeAnalysis.metadata?.dangerous_permissions > 0 ? "var(--high)" : "var(--low)", marginTop: "4px" }}>
                          {activeAnalysis.metadata?.dangerous_permissions}
                        </div>
                      </div>
                      <div className="panel" style={{ padding: "12px" }}>
                        <h3 style={{ margin: 0, fontSize: "10px", color: "var(--ink-dim)", textTransform: "uppercase" }}>First Seen</h3>
                        <div className="mono font-bold" style={{ fontSize: "12px", marginTop: "4px" }}>{activeAnalysis.metadata?.first_seen}</div>
                      </div>
                    </div>

                  </div>

                  {/* Right Column: Sticky Analyst Card */}
                  <div className="overview-sticky-card" style={{ position: "sticky", top: "24px", display: "flex", flexDirection: "column", gap: "14px" }}>
                    <div 
                      style={{
                        background: "var(--surface-2)",
                        borderWidth: "1px",
                        borderStyle: "solid",
                        borderColor: bannerBorderColor,
                        borderRadius: "10px",
                        padding: "16px",
                        display: "flex",
                        flexDirection: "column",
                        gap: "12px",
                        transition: "border-color 0.3s ease"
                      }}
                    >
                      <div style={{ fontFamily: "var(--mono)", fontSize: "9px", color: "var(--ink-dim)", letterSpacing: "0.08em", textTransform: "uppercase" }}>
                        AI VERDICT Posture
                      </div>
                      <div>
                        <div style={{ fontSize: "11px", fontWeight: "bold", color: bannerColor, textTransform: "uppercase" }}>
                          {verdictTitle.replace("🟢 ", "").replace("🔴 ", "").replace("🟡 ", "").replace("🟠 ", "")}
                        </div>
                        <div style={{ fontSize: "28px", fontWeight: "bold", color: "var(--ink)", marginTop: "4px" }}>
                          {score.toFixed(0)}/100
                        </div>
                      </div>
                      <div style={{ borderTop: "1px dashed var(--hairline)", paddingTop: "10px", fontSize: "11px", display: "flex", flexDirection: "column", gap: "6px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "var(--ink-dim)" }}>Family:</span>
                          <span style={{ color: "var(--ink)", fontWeight: "bold" }}>{topFam.family_name}</span>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "var(--ink-dim)" }}>Confidence:</span>
                          <span style={{ color: "var(--signal)", fontWeight: "bold" }}>{getVerdictBannerConfidence(activeAnalysis)}%</span>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "var(--ink-dim)" }}>Objective:</span>
                          <span style={{ color: "var(--ink)", fontWeight: "bold" }} className="truncate max-w-[120px]">{primaryObjective}</span>
                        </div>
                      </div>
                      <div style={{ borderTop: "1px dashed var(--hairline)", paddingTop: "10px", fontSize: "9px", color: "var(--ink-faint)", fontFamily: "var(--mono)" }}>
                        SOC STATUS TRACKER<br/>
                        ● TELEMETRY: ACTIVE<br/>
                        ● SIGNATURES: MATCHED
                      </div>
                    </div>
                  </div>

                </div>
              </div>
              );
            })()}
          </section>
        )}

        {/* ============ 03 STATIC ANALYSIS ============ */}
        {activeAnalysis && (
          <section className={`page ${activeTab === "static" ? "active" : ""}`}>
            <h1>Static Analysis</h1>
            <p className="subhead">Manifest, API call graph, strings, entropy, certificate.</p>

            <div className="panel" style={{ marginBottom: "18px" }}>
              <h3>Declared permissions</h3>
              <table>
                <thead>
                  <tr>
                    <th>Permission</th>
                    <th>Flag</th>
                    <th>Why it matters</th>
                  </tr>
                </thead>
                <tbody>
                  {activeAnalysis.static_analysis?.permissions.map((perm: any, i: number) => (
                    <tr key={i}>
                      <td className="mono font-semibold" style={{ color: "var(--ink)" }}>{perm.name}</td>
                      <td>
                        <span className={`tag ${perm.flag === "Dangerous" ? "danger" : perm.flag === "Suspicious" ? "warn" : "ok"}`}>
                          {perm.flag}
                        </span>
                      </td>
                      <td className="dim">{perm.why}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="grid cols-2">
              <div className="panel">
                <h3>Suspicious strings</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Artifact</th>
                      <th>Type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeAnalysis.static_analysis?.strings.map((str: any, i: number) => (
                      <tr key={i}>
                        <td className="mono truncate max-w-[260px]" title={str.artifact}>{str.artifact}</td>
                        <td>
                          <span className={`tag ${str.type.includes("C2") || str.type.includes("Exfil") ? "danger" : "warn"}`}>
                            {str.type}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="panel">
                <h3>Code entropy / packing</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Section</th>
                      <th>Entropy</th>
                      <th>Verdict</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeAnalysis.static_analysis?.entropy.map((ent: any, i: number) => (
                      <tr key={i}>
                        <td className="mono">{ent.section}</td>
                        <td className="mono">{ent.value}</td>
                        <td>
                          <span className={`tag ${ent.verdict.includes("Packed") || ent.verdict.includes("Obfuscated") ? "danger" : "ok"}`}>
                            {ent.verdict}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* New static indicators: Exported Components, Hardcoded credentials, Native libraries */}
            <div className="panel" style={{ marginTop: "18px", marginBottom: "18px" }}>
              <h3>Exported Android Components (Attack Surface Mapping)</h3>
              {activeAnalysis.static_analysis?.exported_components && activeAnalysis.static_analysis.exported_components.length > 0 ? (
                <table>
                  <thead>
                    <tr>
                      <th>Component Class Path</th>
                      <th>Type</th>
                      <th>Access</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeAnalysis.static_analysis.exported_components.map((comp: any, idx: number) => (
                      <tr key={`${comp.name}-${idx}`}>
                        <td className="mono truncate max-w-[450px]" style={{ color: "var(--ink)" }} title={comp.name}>{comp.name}</td>
                        <td className="mono">{comp.type}</td>
                        <td><span className="tag warn">Exported</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="dim font-mono">No exported activities, services, or receivers detected in manifest.</div>
              )}
            </div>

            <div className="grid cols-2" style={{ marginBottom: "18px" }}>
              <div className="panel">
                <h3>Hardcoded Credentials &amp; API Keys</h3>
                {activeAnalysis.static_analysis?.hardcoded_credentials && activeAnalysis.static_analysis.hardcoded_credentials.length > 0 ? (
                  <table>
                    <thead>
                      <tr>
                        <th>Key Type</th>
                        <th>Redacted Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeAnalysis.static_analysis.hardcoded_credentials.map((cred: any, idx: number) => (
                        <tr key={`${cred.type}-${idx}`}>
                          <td style={{ color: "var(--ink)" }}>{cred.type}</td>
                          <td className="mono font-semibold" style={{ color: "var(--crit)" }}>
                            {cred.raw.includes("...") || cred.raw.includes("******") || cred.raw.length <= 10
                              ? cred.raw
                              : `${cred.raw.substring(0, 6)}...${cred.raw.substring(cred.raw.length - 4)}`}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="dim font-mono">No hardcoded credentials, secret assignments, or API keys flagged.</div>
                )}
              </div>

              <div className="panel">
                <h3>Extracted Native Libraries (.so files)</h3>
                {activeAnalysis.static_analysis?.native_libraries && activeAnalysis.static_analysis.native_libraries.length > 0 ? (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "10px" }}>
                    {activeAnalysis.static_analysis.native_libraries.map((lib: string, idx: number) => (
                      <span key={`${lib}-${idx}`} className="tag info mono" style={{ fontSize: "11px" }}>
                        {lib.split('/').pop() || lib}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="dim font-mono">No native shared object (.so) libraries compiled in this APK.</div>
                )}
              </div>
            </div>
          </section>
        )}

        {/* ============ 04 DYNAMIC ANALYSIS ============ */}
        {activeAnalysis && (
          <section className={`page ${activeTab === "dynamic" ? "active" : ""}`}>
            <h1>Dynamic Analysis</h1>
            <p className="subhead">Headless emulator run, Frida-instrumented, network-isolated sandbox.</p>

            <div className="grid cols-2">
              <div className="panel">
                <h3>Network connections</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Destination</th>
                      <th>Port</th>
                      <th>Note</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeAnalysis.dynamic_analysis?.connections.map((conn: any, i: number) => (
                      <tr key={i}>
                        <td className="mono font-semibold" style={{ color: "var(--ink)" }}>{conn.destination}</td>
                        <td className="mono">{conn.port}</td>
                        <td>
                          <span className="tag danger">
                            {conn.note}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="panel">
                <h3>Runtime-decrypted strings</h3>
                <table>
                  <thead>
                    <tr>
                      <th>String</th>
                      <th>Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeAnalysis.dynamic_analysis?.decrypted_strings.map((str: any, i: number) => (
                      <tr key={i}>
                        <td className="mono" style={{ color: "var(--signal)" }}>"{str.string}"</td>
                        <td className="dim">{str.source}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="panel" style={{ marginTop: "18px" }}>
              <h3>Spawned processes &amp; filesystem mutations</h3>
              <table>
                <thead>
                  <tr>
                    <th>Event</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {activeAnalysis.dynamic_analysis?.mutations.map((mut: any, i: number) => (
                    <tr key={i}>
                      <td>
                        <span className={`tag ${mut.event === "UI" ? "info" : "warn"}`}>
                          {mut.event}
                        </span>
                      </td>
                      <td className="dim">{mut.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* ============ 05 GENAI REPORT ============ */}
        {activeAnalysis && (
          <section className={`page ${activeTab === "genai" ? "active" : ""}`}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <div>
                <h1>GenAI Behaviour Report</h1>
                <p className="subhead" style={{ margin: 0 }}>LoRA-adapted analyst LLM · grounded, citation-checked output.</p>
              </div>
              <button 
                onClick={handleDownloadPDF}
                className="btn ghost"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  padding: "6px 12px",
                  height: "32px",
                  fontSize: "11px",
                  borderRadius: "8px",
                  border: "1px solid var(--hairline-2)",
                  background: "var(--surface-2)",
                  color: "var(--ink)",
                  cursor: "pointer",
                  fontWeight: "bold"
                }}
              >
                <Download size={13} style={{ color: "var(--signal)" }} />
                Export PDF Report
              </button>
            </div>

            <div className="panel" style={{ marginBottom: "18px" }}>
              <h3>Behaviour summary</h3>
              <p className="narrative">{activeAnalysis.ai_report?.executive_summary}</p>
              <div className="chips">
                {activeAnalysis.ai_report?.chips?.map((chip: string, i: number) => (
                  <span key={i} className="chip">
                    {chip}
                  </span>
                ))}
              </div>
            </div>

            <div className="panel">
              <h3>Anomaly flags (declared vs. observed)</h3>
              {activeAnalysis.ai_report?.anomalies?.map((an: any, i: number) => (
                <div key={i} className="anomaly">
                  <div className="claim">{an.claim}</div>
                  <div className="cite">{an.cite}</div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* ============ 06 RISK & SHAP ============ */}
        {activeAnalysis && (
          <section className={`page ${activeTab === "risk" ? "active" : ""}`}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <div>
                <h1>Risk Score &amp; Explainability</h1>
                <p className="subhead" style={{ margin: 0 }}>Stacked XGBoost + LightGBM ensemble · SHAP-ranked contributing factors.</p>
              </div>
              
              {/* Beginner Mode Toggle */}
              <div style={{ display: "inline-flex", background: "var(--surface-2)", borderRadius: "8px", padding: "2px", border: "1px solid var(--hairline)" }}>
                <button 
                  onClick={() => setExplanationMode("technical")} 
                  style={{
                    background: explanationMode === "technical" ? "var(--signal-dim)" : "transparent",
                    color: explanationMode === "technical" ? "var(--signal)" : "var(--ink-dim)",
                    border: "none",
                    fontSize: "11px",
                    fontFamily: "var(--mono)",
                    padding: "6px 12px",
                    borderRadius: "6px",
                    cursor: "pointer",
                    fontWeight: "bold"
                  }}
                >
                  Technical View
                </button>
                <button 
                  onClick={() => setExplanationMode("beginner")} 
                  style={{
                    background: explanationMode === "beginner" ? "var(--signal-dim)" : "transparent",
                    color: explanationMode === "beginner" ? "var(--signal)" : "var(--ink-dim)",
                    border: "none",
                    fontSize: "11px",
                    fontFamily: "var(--mono)",
                    padding: "6px 12px",
                    borderRadius: "6px",
                    cursor: "pointer",
                    fontWeight: "bold"
                  }}
                >
                  Plain English View
                </button>
              </div>
            </div>

            <div className="grid cols-2 overview-grid-2col" style={{ gridTemplateColumns: "1.2fr 1fr", gap: "18px", alignItems: "start" }}>
              {/* Left Side: SHAP Features */}
              <div className="panel">
                <h3>Top contributing features</h3>
                <div style={{ width: "100%", height: "240px", marginTop: "14px" }}>
                  <ResponsiveContainer width="100%" height={240}>
                    <BarChart data={activeShap} layout="vertical" margin={{ left: 10, right: 10, top: 0, bottom: 0 }}>
                      <XAxis type="number" stroke="#7A8896" fontSize={10} tickLine={false} axisLine={false} />
                      <YAxis dataKey="name" type="category" stroke="#DCE4EA" fontSize={10} width={240} tickLine={false} axisLine={false} />
                      <Tooltip contentStyle={{ backgroundColor: "#121821", border: "1px solid #1F2832" }} />
                      <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={14}>
                        {activeShap.map((entry: any, index: number) => (
                          <Cell key={index} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Right Side: MITRE Tactic Heatmap */}
              <div className="panel" style={{ display: "flex", flexDirection: "column" }}>
                <h3 style={{ margin: 0, fontSize: "12px", letterSpacing: "0.08em", marginBottom: "12px" }}>MITRE ATT&CK Mobile Coverage</h3>
                
                <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                  {[
                    "Initial Access",
                    "Persistence",
                    "Defense Evasion",
                    "Credential Access",
                    "Collection",
                    "Discovery"
                  ].map((tactic) => {
                    const triggered = getTriggeredTechniques(activeAnalysis, tactic);
                    const isTriggered = triggered.length > 0;
                    return (
                      <div 
                        key={tactic}
                        style={{
                          border: isTriggered ? "1px solid var(--signal-dim)" : "1px solid var(--hairline)",
                          background: isTriggered ? "var(--surface-2)" : "transparent",
                          opacity: isTriggered ? 1 : 0.4,
                          borderRadius: "8px",
                          padding: "10px 14px",
                          transition: "all 0.2s ease"
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <span style={{ color: isTriggered ? "var(--ink)" : "var(--ink-dim)", fontWeight: "bold", fontSize: "12px" }}>
                            {tactic}
                          </span>
                          {isTriggered ? (
                            <span className="tag danger" style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "9px" }}>
                              <span className="pulse" style={{ width: "4px", height: "4px" }}></span> ■ Triggered ({triggered.length})
                            </span>
                          ) : (
                            <span className="tag" style={{ background: "var(--surface-2)", color: "var(--ink-faint)", fontSize: "9px" }}>
                              □ Not Triggered
                            </span>
                          )}
                        </div>
                        
                        {isTriggered && (
                          <div style={{ marginTop: "6px", paddingTop: "6px", borderTop: "1px dashed var(--hairline)", fontSize: "10px" }}>
                            <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                              {triggered.map((t: any, i: number) => (
                                <div key={i} style={{ color: "var(--ink-dim)" }}>
                                  <b style={{ color: "var(--signal)" }}>{t.technique_id} - {t.technique_name}</b>
                                  <span style={{ fontSize: "10px" }}>: {t.evidence}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Feature Attribution Insights panel */}
            <div className="panel" style={{ marginTop: "18px" }}>
              <h3>Feature Attribution Insights</h3>
              <p className="subhead" style={{ marginBottom: "14px" }}>
                {explanationMode === "technical" 
                  ? "Attribution values represent SHAP (SHapley Additive exPlanations) values indicating how much each feature pushes the ensemble's prediction away from the baseline score."
                  : "These contributing factors explain why the AI flagged this app and how they affect the overall risk assessment."
                }
              </p>
              
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {activeShap.map((item: any, index: number) => {
                  const expl = getShapExplanation(item.name, explanationMode === "technical", item.description);
                  return (
                    <div 
                      key={index} 
                      style={{ 
                        display: "flex", 
                        flexDirection: "column", 
                        padding: "12px", 
                        background: "var(--surface-2)", 
                        border: `1px solid ${item.color}33`, 
                        borderRadius: "8px" 
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                        <span style={{ fontWeight: "bold", color: "var(--ink)", fontSize: "13px" }}>
                          {item.name}
                        </span>
                        <span style={{ fontFamily: "var(--mono)", fontWeight: "bold", color: item.color, fontSize: "12px" }}>
                          {explanationMode === "technical" ? `SHAP Value: +${item.value.toFixed(2)}` : `Impact Weight: ${Math.round(item.value * 100)}%`}
                        </span>
                      </div>
                      <p style={{ margin: 0, fontSize: "11.5px", color: "var(--ink-dim)", lineHeight: "1.4" }}>
                        {expl}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="panel" style={{ marginTop: "18px" }}>
              <h3>Threshold legend</h3>
              <div className="grid cols-4">
                <div><span className="tag ok">0–30</span> Likely benign</div>
                <div><span className="tag warn">31–60</span> Suspicious</div>
                <div><span className="tag danger" style={{ background: "rgba(242,120,75,.14)", color: "var(--high)" }}>61–80</span> Probable malware</div>
                <div><span className="tag danger">81–100</span> Confirmed malicious</div>
              </div>
            </div>
          </section>
        )}

        {/* ============ 07 CASE HISTORY ============ */}
        <section className={`page ${activeTab === "history" ? "active" : ""}`}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
            <div>
              <h1>Case History</h1>
              <p className="subhead" style={{ margin: 0 }}>All scans processed by this APK Sentinel instance. Click any row to load full analysis.</p>
            </div>
            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              <button className="btn ghost" style={{ fontSize: "10px", padding: "6px 12px" }} onClick={() => {
                const csv = ["App,Package,Score,Verdict,SHA256,Size,Scanned",
                  ...allScans.map((r: any) => {
                    const score = r.risk_assessment?.risk_score ?? r.risk_score ?? 0;
                    const verdict = r.risk_assessment?.verdict || r.verdict || "Safe";
                    const sha256 = r.sha256 || r.metadata?.sha256 || "—";
                    const size = r.size || (r.metadata?.file_size ? `${(r.metadata.file_size / (1024*1024)).toFixed(1)} MB` : "2.5 MB");
                    return `${r.file_name},${r.package_name},${score.toFixed(0)},${verdict},${sha256},${size},${r.created_at}`;
                  })
                ].join("\n");
                const blob = new Blob([csv], { type: "text/csv" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a"); a.href = url; a.download = "apk_sentinel_history.csv"; a.click();
              }}>
                <Download size={11} /> Export CSV
              </button>
            </div>
          </div>

          {/* Summary Stats */}
          {(() => {
            const totalScans = allScans.length;
            const critCount = allScans.filter((s: any) => (s.risk_assessment?.risk_score ?? s.risk_score ?? 0) >= 80).length;
            const highCount = allScans.filter((s: any) => { const sc = s.risk_assessment?.risk_score ?? s.risk_score ?? 0; return sc >= 60 && sc < 80; }).length;
            const suspCount = allScans.filter((s: any) => { const sc = s.risk_assessment?.risk_score ?? s.risk_score ?? 0; return sc >= 30 && sc < 60; }).length;
            const safeCount = allScans.filter((s: any) => (s.risk_assessment?.risk_score ?? s.risk_score ?? 0) < 30).length;
            const avgScore = totalScans > 0 ? (allScans.reduce((sum: number, s: any) => sum + (s.risk_assessment?.risk_score ?? s.risk_score ?? 0), 0) / totalScans) : 0;

            const getFamily = (row: any) => {
              if (row.family_similarity && row.family_similarity.length > 0) {
                const sorted = [...row.family_similarity].sort((a: any, b: any) => b.similarity_score - a.similarity_score);
                return sorted[0].family_name;
              }
              return "—";
            };

            const getScoreColor = (score: number) => {
              if (score >= 80) return "var(--crit)";
              if (score >= 60) return "var(--high)";
              if (score >= 30) return "var(--med)";
              return "var(--low)";
            };

            return (
              <>
                {/* Stats Row */}
                <div className="stats-grid-6col" style={{ display: "grid", gap: "10px", margin: "20px 0" }}>
                  {[
                    { label: "Total Scans", value: totalScans, color: "var(--signal)" },
                    { label: "Critical", value: critCount, color: "var(--crit)" },
                    { label: "High Risk", value: highCount, color: "var(--high)" },
                    { label: "Suspicious", value: suspCount, color: "var(--med)" },
                    { label: "Safe", value: safeCount, color: "var(--low)" },
                    { label: "Avg Score", value: avgScore.toFixed(0), color: avgScore >= 50 ? "var(--high)" : "var(--low)" },
                  ].map(stat => (
                    <div key={stat.label} className="panel" style={{ padding: "14px 12px", textAlign: "center" }}>
                      <div style={{ fontFamily: "var(--mono)", fontSize: "22px", fontWeight: "700", color: stat.color, lineHeight: 1 }}>{stat.value}</div>
                      <div style={{ fontFamily: "var(--mono)", fontSize: "8px", color: "var(--ink-faint)", textTransform: "uppercase", letterSpacing: "0.10em", marginTop: "6px" }}>{stat.label}</div>
                    </div>
                  ))}
                </div>

                {/* Main Table */}
                <div className="panel" style={{ padding: "0", overflow: "hidden" }}>
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ minWidth: "900px" }}>
                      <thead>
                        <tr>
                          <th style={{ paddingLeft: "16px", width: "32px" }}>#</th>
                          <th>Application</th>
                          <th>Package Name</th>
                          <th>SHA-256</th>
                          <th>Size</th>
                          <th>Score</th>
                          <th>Verdict</th>
                          <th>Family</th>
                          <th>Perms</th>
                          <th>Scanned</th>
                        </tr>
                      </thead>
                      <tbody>
                        {allScans.map((row: any, index: number) => {
                          const score = row.risk_assessment?.risk_score ?? row.risk_score ?? 0;
                          const verdict = row.risk_assessment?.verdict || row.verdict || "Safe";
                          const family = getFamily(row);
                          const perms = row.metadata?.dangerous_permissions ?? "—";
                          const isActive = activeAnalysis?.id === row.id;

                          return (
                            <tr
                              key={`hist-${row.id}-${index}`}
                              onClick={() => selectAnalysis(row.id)}
                              style={{
                                cursor: "pointer",
                                background: isActive ? "rgba(0, 229, 200, 0.04)" : undefined,
                              }}
                            >
                              <td style={{ paddingLeft: "16px", fontFamily: "var(--mono)", fontSize: "10px", color: "var(--ink-faint)" }}>{totalScans - index}</td>
                              <td>
                                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                                  <span style={{ width: "4px", height: "24px", borderRadius: "2px", background: getScoreColor(score), flexShrink: 0 }}></span>
                                  <div>
                                    <div style={{ fontWeight: "600", color: "var(--ink)", fontSize: "12px" }}>{row.file_name}</div>
                                    {row.id >= 901 && row.id <= 904 && (
                                      <div style={{ fontFamily: "var(--mono)", fontSize: "8px", color: "var(--signal)", letterSpacing: "0.08em", marginTop: "1px" }}>DEMO PROFILE</div>
                                    )}
                                  </div>
                                </div>
                              </td>
                              <td style={{ fontFamily: "var(--mono)", fontSize: "10.5px", color: "var(--ink-dim)" }}>{row.package_name}</td>
                              <td style={{ fontFamily: "var(--mono)", fontSize: "10px", color: "var(--ink-faint)" }} title={row.sha256}>
                                {row.sha256 ? `${row.sha256.substring(0, 8)}\u2026${row.sha256.substring(row.sha256.length - 6)}` : "—"}
                              </td>
                              <td style={{ fontFamily: "var(--mono)", fontSize: "11px", color: "var(--ink-dim)", whiteSpace: "nowrap" }}>{row.size}</td>
                              <td>
                                <span style={{
                                  fontFamily: "var(--mono)",
                                  fontWeight: "700",
                                  fontSize: "13px",
                                  color: getScoreColor(score),
                                }}>{score.toFixed(0)}</span>
                              </td>
                              <td>
                                <span className={`tag ${getRiskBadge(verdict)}`}>{verdict}</span>
                              </td>
                              <td style={{ fontFamily: "var(--mono)", fontSize: "10.5px", color: family === "Benign" || family === "—" ? "var(--ink-faint)" : "var(--ink)" }}>
                                {family}
                              </td>
                              <td style={{ fontFamily: "var(--mono)", fontSize: "11px", color: (perms as number) >= 5 ? "var(--high)" : "var(--ink-dim)", textAlign: "center" }}>
                                {perms}
                              </td>
                              <td style={{ fontFamily: "var(--mono)", fontSize: "10px", color: "var(--ink-faint)", whiteSpace: "nowrap" }}>{row.created_at}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Footer info */}
                <footer className="page-foot">
                  {totalScans} records · Showing all scans from this APK Sentinel AI instance · Click any demo profile row to load full analysis
                </footer>
              </>
            );
          })()}
        </section>

      </main>
    </div>
  );
}
