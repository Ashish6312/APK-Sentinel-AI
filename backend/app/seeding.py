import json
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.database import APKAnalysis, ExtractedFeatures, ThreatIntelligence, MITREMapping, FamilySimilarity, AIReport, DynamicAnalysis, TrainingSample

def seed_db_if_empty(db: Session):
    if db.query(APKAnalysis).count() > 0:
        print("Database already seeded. Skipping initial data population.")
        return

    print("Seeding database with 4 hackathon demo profiles...")
    
    # Base timestamp
    base_time = datetime.utcnow()

    # ----------------------------------------------------
    # Profile 1: Safe Utility Tool
    # ----------------------------------------------------
    apk1 = APKAnalysis(
        id=901,
        file_name="Safe_Utility_Tool.apk",
        sha256="ea84931a742c38d9cd316a8d7cb12c9bf39cd5bc13d8d9ff3d8b39cd5bc13d8d",
        package_name="com.secops.safe.utility",
        risk_score=12.0,
        malware_probability=0.024,
        obfuscation_score=0.0,
        verdict="Safe",
        status="Completed",
        created_at=base_time - timedelta(hours=6)
    )
    db.add(apk1)
    db.flush()

    feat1 = ExtractedFeatures(
        apk_id=apk1.id,
        permissions=json.dumps(["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"]),
        activities=json.dumps(["com.secops.safe.utility.MainActivity", "com.secops.safe.utility.SettingsActivity"]),
        services=json.dumps([]),
        receivers=json.dumps([]),
        urls=json.dumps(["https://api.github.com/repos/check"]),
        domains=json.dumps(["api.github.com"]),
        ips=json.dumps([]),
        methods=json.dumps(["getSystemService", "initView", "onStart"]),
        intent_filters=json.dumps(["android.intent.action.MAIN"]),
        cert_metadata=json.dumps({
            "issuer": "CN=SecOps Developer, O=SecOps, C=US",
            "subject": "CN=SecOps Developer, O=SecOps, C=US",
            "serial_number": "99827364510",
            "sig_algo": "sha256WithRSAEncryption",
            "target_sdk": "31",
            "version_name": "1.2.0",
            "version_code": "12"
        }),
        obfuscation_findings=json.dumps([])
    )
    db.add(feat1)

    ti1 = ThreatIntelligence(
        apk_id=apk1.id,
        threat_score=5.0,
        severity="LOW",
        indicators=json.dumps([])
    )
    db.add(ti1)

    fam1_1 = FamilySimilarity(apk_id=apk1.id, family_name="Adware-like", similarity_score=8.0, confidence="LOW", threat_category="Adware / PUP")
    fam1_2 = FamilySimilarity(apk_id=apk1.id, family_name="Joker-like", similarity_score=5.0, confidence="LOW", threat_category="Spyware / SMS Fraud")
    db.add(fam1_1)
    db.add(fam1_2)

    dyn1 = DynamicAnalysis(
        apk_id=apk1.id,
        behavior_score=10.0,
        frida_logs=json.dumps([
            {"timestamp": "+0.10s", "tag": "DETECTION", "message": "Safe environment initialized. No root bindings found.", "level": "INFO"}
        ]),
        process_calls=json.dumps([
            {"timestamp": "+0.00s", "parent": "zygote64", "process": "com.secops.safe.utility", "pid": 5110, "action": "spawn"}
        ]),
        file_activities=json.dumps([
            {"timestamp": "+0.15s", "operation": "read", "path": "/data/user/0/com.secops.safe.utility/shared_prefs/settings.xml", "status": "SUCCESS"}
        ]),
        network_connections=json.dumps([
            {"timestamp": "+0.50s", "dest": "api.github.com:443", "protocol": "HTTPS", "status": "SUCCESS", "bytes_sent": 256, "bytes_rcvd": 1024}
        ]),
        runtime_permissions=json.dumps([
            {"permission": "INTERNET", "state": "ALLOWED_BY_MANIFEST", "usage": "Checking updates"}
        ])
    )
    db.add(dyn1)

    ai1 = AIReport(
        apk_id=apk1.id,
        executive_summary="The application exhibits typical behaviors of a benign system utility. Minimal security indicators were matched.",
        threat_assessment="Standard permissions are requested. Bytecode scanning did not trigger any suspicious network connections or overlay indicators.",
        ioc=json.dumps(["ea84931a742c38d9cd316a8d7cb12c9bf39cd5bc13d8d9ff3d8b39cd5bc13d8d", "com.secops.safe.utility"]),
        recommendations="Whitelisted for installation.",
        soc_commentary="Benign application structure. Signature certificate is valid."
    )
    db.add(ai1)

    # ----------------------------------------------------
    # Profile 2: Free Wallpapers Pro (Adware)
    # ----------------------------------------------------
    apk2 = APKAnalysis(
        id=902,
        file_name="Free_Wallpapers_Pro.apk",
        sha256="b9cdbc13d8daf829038d128d9c12b9bf39cd5bc13d8d9ffd38b39cd5bc13d8dea",
        package_name="com.adpromo.wallpapers.pro",
        risk_score=45.0,
        malware_probability=0.421,
        obfuscation_score=25.0,
        verdict="Suspicious",
        status="Completed",
        created_at=base_time - timedelta(hours=5)
    )
    db.add(apk2)
    db.flush()

    feat2 = ExtractedFeatures(
        apk_id=apk2.id,
        permissions=json.dumps(["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.RECEIVE_BOOT_COMPLETED"]),
        activities=json.dumps(["com.adpromo.wallpapers.MainActivity", "com.adpromo.wallpapers.AdActivity"]),
        services=json.dumps(["com.adpromo.wallpapers.AdBackgroundService"]),
        receivers=json.dumps([]),
        urls=json.dumps(["http://adserver.promo-clicks.com/load", "https://doubleclick.net/ad"]),
        domains=json.dumps(["promo-clicks.com", "doubleclick.net"]),
        ips=json.dumps([]),
        methods=json.dumps(["getBannerView", "getClickUrl", "loadAd", "invoke", "getMethod"]),
        intent_filters=json.dumps(["android.intent.action.BOOT_COMPLETED"]),
        cert_metadata=json.dumps({
            "issuer": "CN=AdPromo Dev, O=AdPromo, C=CN",
            "subject": "CN=AdPromo Dev, O=AdPromo, C=CN",
            "serial_number": "22839401928",
            "sig_algo": "sha256WithRSAEncryption",
            "target_sdk": "29",
            "version_name": "2.0.4",
            "version_code": "204"
        }),
        obfuscation_findings=json.dumps([
            {"category": "Reflection APIs", "evidence": "Identified reflection APIs: invoke, getMethod", "score": 15.0}
        ])
    )
    db.add(feat2)

    ti2 = ThreatIntelligence(
        apk_id=apk2.id,
        threat_score=35.0,
        severity="MEDIUM",
        indicators=json.dumps([
            { "indicator": "Adware redirection methods loadAd/getClickUrl detected", "type": "Adware PUP", "severity": "MEDIUM", "weight": 20.0 },
            { "indicator": "Hardcoded click-tracker domains: promo-clicks.com", "type": "Adware Connection", "severity": "MEDIUM", "weight": 15.0 }
        ])
    )
    db.add(ti2)

    mitre2 = MITREMapping(
        apk_id=apk2.id,
        technique_id="T1407",
        technique_name="Dynamic Code Execution",
        severity="MEDIUM",
        evidence="Loads external ad classes dynamically.",
        confidence="HIGH"
    )
    db.add(mitre2)

    fam2_1 = FamilySimilarity(apk_id=apk2.id, family_name="Adware-like", similarity_score=68.0, confidence="HIGH", threat_category="Adware / PUP")
    fam2_2 = FamilySimilarity(apk_id=apk2.id, family_name="Spyware-like", similarity_score=18.0, confidence="LOW", threat_category="Spyware / Surveillance")
    db.add(fam2_1)
    db.add(fam2_2)

    dyn2 = DynamicAnalysis(
        apk_id=apk2.id,
        behavior_score=40.0,
        frida_logs=json.dumps([
            {"timestamp": "+0.35s", "tag": "AD_MONITOR", "message": "Ad SDK initialized: Google Mobile Ads (or secondary networks)", "level": "INFO"},
            {"timestamp": "+1.90s", "tag": "OVERLAY", "message": "Intercepted full-screen advertisement intent spawn", "level": "MEDIUM"}
        ]),
        process_calls=json.dumps([
            {"timestamp": "+0.00s", "parent": "zygote64", "process": "com.adpromo.wallpapers.pro", "pid": 5012, "action": "spawn"}
        ]),
        file_activities=json.dumps([
            {"timestamp": "+0.40s", "operation": "write", "path": "/data/user/0/com.adpromo.wallpapers.pro/cache/ad_cache.png", "status": "SUCCESS"}
        ]),
        network_connections=json.dumps([
            {"timestamp": "+1.50s", "dest": "promo-clicks.com:80", "protocol": "HTTP", "status": "ESTABLISHED", "bytes_sent": 512, "bytes_rcvd": 102400}
        ]),
        runtime_permissions=json.dumps([
            {"permission": "WRITE_EXTERNAL_STORAGE", "state": "GRANTED_BY_USER", "usage": "Caching ad imagery asset packages"}
        ])
    )
    db.add(dyn2)

    ai2 = AIReport(
        apk_id=apk2.id,
        executive_summary="The application Wallpapers Pro displays adware characteristics, loading aggressive full-screen banner notifications.",
        threat_assessment="Standard permissions are mapped, but background services show high ad spams. Outbound telemetry hits ad servers.",
        ioc=json.dumps(["b9cdbc13d8daf829038d128d9c12b9bf39cd5bc13d8d9ffd38b39cd5bc13d8dea", "com.adpromo.wallpapers.pro", "promo-clicks.com"]),
        recommendations="Uninstall if unsolicited. Monitor outbound data volumes.",
        soc_commentary="Presents ad hijack modules."
    )
    db.add(ai2)

    # ----------------------------------------------------
    # Profile 3: Spy Tracker Agent (Spyware)
    # ----------------------------------------------------
    apk3 = APKAnalysis(
        id=903,
        file_name="Spy_Tracker_Agent.apk",
        sha256="cf8b9bc13d8daf829038d128d9c12b9bf39cd5bc13d8d9ffd38b39cd5bc13d8dea",
        package_name="com.spyware.tracker.agent",
        risk_score=76.0,
        malware_probability=0.812,
        obfuscation_score=55.0,
        verdict="High Risk",
        status="Completed",
        created_at=base_time - timedelta(hours=4)
    )
    db.add(apk3)
    db.flush()

    feat3 = ExtractedFeatures(
        apk_id=apk3.id,
        permissions=json.dumps(["android.permission.INTERNET", "android.permission.RECORD_AUDIO", "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_CONTACTS"]),
        activities=json.dumps(["com.spyware.tracker.MainActivity"]),
        services=json.dumps(["com.spyware.tracker.SpyService"]),
        receivers=json.dumps([]),
        urls=json.dumps(["https://api.telegram.org/bot7291034:sendMessage"]),
        domains=json.dumps(["api.telegram.org"]),
        ips=json.dumps([]),
        methods=json.dumps(["record", "startRecording", "takePicture", "getLastKnownLocation", "decrypt", "cipher", "invoke"]),
        intent_filters=json.dumps([]),
        cert_metadata=json.dumps({
            "issuer": "CN=SpyDev, O=SpyDev, C=RU",
            "subject": "CN=SpyDev, O=SpyDev, C=RU",
            "serial_number": "8873910283",
            "sig_algo": "sha256WithRSAEncryption",
            "target_sdk": "30",
            "version_name": "1.0",
            "version_code": "1"
        }),
        obfuscation_findings=json.dumps([
            {"category": "Reflection APIs", "evidence": "Identified reflection APIs: invoke", "score": 15.0},
            {"category": "Cryptographic Execution", "evidence": "Identified cryptographic operations: decrypt, cipher", "score": 15.0}
        ])
    )
    db.add(feat3)

    ti3 = ThreatIntelligence(
        apk_id=apk3.id,
        threat_score=75.0,
        severity="HIGH",
        indicators=json.dumps([
            { "indicator": "Telegram bot API exfiltration URL triggered", "type": "C2 Exfil", "severity": "HIGH", "weight": 35.0 },
            { "indicator": "Microphone recording methods (record/startRecording) detected", "type": "Surveillance", "severity": "HIGH", "weight": 20.0 },
            { "indicator": "Access to contacts and fine location details", "type": "Privacy Breach", "severity": "HIGH", "weight": 20.0 }
        ])
    )
    db.add(ti3)

    mitre3_1 = MITREMapping(apk_id=apk3.id, technique_id="T1429", technique_name="Audio Capture", severity="HIGH", evidence="Requests RECORD_AUDIO permission and triggers record() bytecode.", confidence="HIGH")
    mitre3_2 = MITREMapping(apk_id=apk3.id, technique_id="T1404", technique_name="Device Location Tracking", severity="MEDIUM", evidence="Requests precise location.", confidence="HIGH")
    mitre3_3 = MITREMapping(apk_id=apk3.id, technique_id="T1430", technique_name="Access Sensitive Data", severity="MEDIUM", evidence="Harvests user contacts catalog.", confidence="HIGH")
    db.add(mitre3_1)
    db.add(mitre3_2)
    db.add(mitre3_3)

    fam3_1 = FamilySimilarity(apk_id=apk3.id, family_name="Spyware-like", similarity_score=82.0, confidence="HIGH", threat_category="Spyware / Surveillance")
    fam3_2 = FamilySimilarity(apk_id=apk3.id, family_name="Joker-like", similarity_score=35.0, confidence="MEDIUM", threat_category="Spyware / SMS Fraud")
    db.add(fam3_1)
    db.add(fam3_2)

    dyn3 = DynamicAnalysis(
        apk_id=apk3.id,
        behavior_score=75.0,
        frida_logs=json.dumps([
            {"timestamp": "+0.20s", "tag": "FRIDA_HOOK", "message": "Hooked android.media.MediaRecorder.start() to capture voice payload", "level": "CRITICAL"},
            {"timestamp": "+1.80s", "tag": "FRIDA_HOOK", "message": "Hooked android.hardware.Camera.takePicture() backdrop trigger", "level": "WARNING"},
            {"timestamp": "+2.50s", "tag": "LOCATION", "message": "Intercepted LocationManager.getLastKnownLocation() call", "level": "MEDIUM"}
        ]),
        process_calls=json.dumps([
            {"timestamp": "+0.00s", "parent": "zygote64", "process": "com.spyware.tracker.agent", "pid": 4910, "action": "spawn"},
            {"timestamp": "+0.90s", "parent": "com.spyware.tracker.agent", "process": "/system/bin/screencap", "pid": 4922, "action": "exec"}
        ]),
        file_activities=json.dumps([
            {"timestamp": "+0.50s", "operation": "write", "path": "/sdcard/Documents/spy_recording.mp4", "status": "SUCCESS"},
            {"timestamp": "+2.10s", "operation": "read", "path": "/data/user/0/com.android.providers.contacts/databases/contacts2.db", "status": "SUCCESS"}
        ]),
        network_connections=json.dumps([
            {"timestamp": "+1.10s", "dest": "api.telegram.org:443", "protocol": "HTTPS", "status": "ESTABLISHED", "bytes_sent": 20480, "bytes_rcvd": 512}
        ]),
        runtime_permissions=json.dumps([
            {"permission": "RECORD_AUDIO", "state": "GRANTED_BY_USER", "usage": "Recording microphone buffer"},
            {"permission": "ACCESS_FINE_LOCATION", "state": "GRANTED_BY_USER", "usage": "Querying current GPS coordinates"}
        ])
    )
    db.add(dyn3)

    ai3 = AIReport(
        apk_id=apk3.id,
        executive_summary="The sample is an active Surveillance Spyware masquerading as a utility. It captures background microphone recordings.",
        threat_assessment="Abuses critical permissions (RECORD_AUDIO, CAMERA, LOCATION) without active UI triggers. Exfiltrates directly using HTTP requests to Telegram API endpoints.",
        ioc=json.dumps(["cf8b9bc13d8daf829038d128d9c12b9bf39cd5bc13d8d9ffd38b39cd5bc13d8dea", "com.spyware.tracker.agent", "api.telegram.org"]),
        recommendations="Immediate device isolation. Block Telegram API exfiltration endpoints.",
        soc_commentary="Malicious tracking payload."
    )
    db.add(ai3)

    # ----------------------------------------------------
    # Profile 4: Apex Crypto Wallet (Banking Trojan)
    # ----------------------------------------------------
    apk4 = APKAnalysis(
        id=904,
        file_name="Apex_Crypto_Wallet.apk",
        sha256="df8a96cde7a1db39ad8119c4d9bc272d1a3c6be4a0b2d3c948db7e2e34ff601c",
        package_name="com.apex.crypto.wallet",
        risk_score=91.0,
        malware_probability=0.954,
        obfuscation_score=85.0,
        verdict="Critical",
        status="Completed",
        created_at=base_time - timedelta(hours=3)
    )
    db.add(apk4)
    db.flush()

    feat4 = ExtractedFeatures(
        apk_id=apk4.id,
        permissions=json.dumps(["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_SMS"]),
        activities=json.dumps(["com.apex.crypto.wallet.MainActivity", "com.apex.crypto.wallet.OverlayActivity"]),
        services=json.dumps(["com.apex.crypto.wallet.HijackService"]),
        receivers=json.dumps([]),
        urls=json.dumps(["http://194.26.135.84/c2/receive"]),
        domains=json.dumps([]),
        ips=json.dumps(["194.26.135.84"]),
        methods=json.dumps(["sendTextMessage", "getSystemService", "loadClass", "invoke", "getMethod", "decrypt", "cipher", "DexClassLoader"]),
        intent_filters=json.dumps([]),
        cert_metadata=json.dumps({
            "issuer": "CN=CryptoDev, O=CryptoDev, C=RU",
            "subject": "CN=CryptoDev, O=CryptoDev, C=RU",
            "serial_number": "19384729103",
            "sig_algo": "sha256WithRSAEncryption",
            "target_sdk": "33",
            "version_name": "1.1",
            "version_code": "11"
        }),
        obfuscation_findings=json.dumps([
            {"category": "Reflection APIs", "evidence": "Identified reflection APIs: invoke, getMethod", "score": 15.0},
            {"category": "Dynamic Class Loading", "evidence": "Found dynamic loader methods: DexClassLoader, loadClass", "score": 25.0},
            {"category": "Cryptographic Execution", "evidence": "Identified cryptographic operations: decrypt, cipher", "score": 15.0},
            {"category": "Evasive Combinations", "evidence": "Combines dynamic class loading with auto-start permissions", "score": 10.0}
        ])
    )
    db.add(feat4)

    ti4 = ThreatIntelligence(
        apk_id=apk4.id,
        threat_score=90.0,
        severity="CRITICAL",
        indicators=json.dumps([
            { "indicator": "Accessibility Service bind request (keylogger trigger)", "type": "Accessibility Abuse", "severity": "CRITICAL", "weight": 35.0 },
            { "indicator": "Overlay drawing permission SYSTEM_ALERT_WINDOW requested", "type": "Overlay Phishing", "severity": "CRITICAL", "weight": 30.0 },
            { "indicator": "Outbound communication to raw malicious C2 IP: 194.26.135.84", "type": "C2 Connection", "severity": "HIGH", "weight": 25.0 }
        ])
    )
    db.add(ti4)

    mitre4_1 = MITREMapping(apk_id=apk4.id, technique_id="T1516", technique_name="Abuse Accessibility Service", severity="CRITICAL", evidence="Requests permission BIND_ACCESSIBILITY_SERVICE to keylog inputs.", confidence="HIGH")
    mitre4_2 = MITREMapping(apk_id=apk4.id, technique_id="T1411", technique_name="Input Capture via Overlay", severity="CRITICAL", evidence="Requests drawing alert overlays to phish inputs.", confidence="HIGH")
    mitre4_3 = MITREMapping(apk_id=apk4.id, technique_id="T1412", technique_name="Capture SMS Messages", severity="HIGH", evidence="Intercepts MFA codes via SMS permissions.", confidence="HIGH")
    db.add(mitre4_1)
    db.add(mitre4_2)
    db.add(mitre4_3)

    fam4_1 = FamilySimilarity(apk_id=apk4.id, family_name="BankBot-like", similarity_score=91.0, confidence="HIGH", threat_category="Banking Trojan")
    fam4_2 = FamilySimilarity(apk_id=apk4.id, family_name="Cerberus-like", similarity_score=82.0, confidence="HIGH", threat_category="Banking Trojan")
    fam4_3 = FamilySimilarity(apk_id=apk4.id, family_name="Joker-like", similarity_score=55.0, confidence="MEDIUM", threat_category="Spyware / SMS Fraud")
    db.add(fam4_1)
    db.add(fam4_2)
    db.add(fam4_3)

    dyn4 = DynamicAnalysis(
        apk_id=apk4.id,
        behavior_score=95.0,
        frida_logs=json.dumps([
            {"timestamp": "+0.42s", "tag": "FRIDA_HOOK", "message": "Intercepted JNI Call: RegisterNatives in libsecurity.so", "level": "WARNING"},
            {"timestamp": "+1.15s", "tag": "FRIDA_HOOK", "message": "Hooked android.view.View.onDraw() to monitor overlay layers", "level": "CRITICAL"},
            {"timestamp": "+2.84s", "tag": "ACCESSIBILITY", "message": "AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED read target input field: 'password'", "level": "CRITICAL"},
            {"timestamp": "+3.10s", "tag": "FRIDA_HOOK", "message": "Bypassed Certificate Pinning for OkHttpClient TrustManager", "level": "WARNING"}
        ]),
        process_calls=json.dumps([
            {"timestamp": "+0.00s", "parent": "zygote64", "process": "com.apex.crypto.wallet", "pid": 4820, "action": "spawn"},
            {"timestamp": "+1.50s", "parent": "com.apex.crypto.wallet", "process": "/system/bin/app_process", "pid": 4835, "action": "exec"},
            {"timestamp": "+4.20s", "parent": "com.apex.crypto.wallet", "process": "logcat", "pid": 4842, "action": "exec"}
        ]),
        file_activities=json.dumps([
            {"timestamp": "+0.80s", "operation": "read", "path": "/data/user/0/com.apex.crypto.wallet/databases/wallet.db", "status": "SUCCESS"},
            {"timestamp": "+1.20s", "operation": "write", "path": "/data/user/0/com.apex.crypto.wallet/shared_prefs/app_state.xml", "status": "SUCCESS"},
            {"timestamp": "+2.50s", "operation": "modify", "path": "/data/system/users/0/settings_secure.xml", "status": "DENIED (Sandbox Block)"}
        ]),
        network_connections=json.dumps([
            {"timestamp": "+0.90s", "dest": "194.26.135.84:8080", "protocol": "TCP", "status": "ESTABLISHED", "bytes_sent": 842, "bytes_rcvd": 240},
            {"timestamp": "+2.95s", "dest": "194.26.135.84:8080", "protocol": "TCP", "status": "TRANSMITTING", "bytes_sent": 4096, "bytes_rcvd": 1024}
        ]),
        runtime_permissions=json.dumps([
            {"permission": "SYSTEM_ALERT_WINDOW", "state": "GRANTED_BY_USER", "usage": "Draw overlay over system launcher"},
            {"permission": "BIND_ACCESSIBILITY_SERVICE", "state": "GRANTED_BY_USER", "usage": "Monitor input keystrokes dynamically"}
        ])
    )
    db.add(dyn4)

    ai4 = AIReport(
        apk_id=apk4.id,
        executive_summary="The application poses a critical threat, operating as a Banking Trojan targeting cryptocurrency wallets.",
        threat_assessment="Requests accessibility binds to log keyboard sequences and draws overlay windows to capture PIN inputs. Communicates with a known hostile C2 IP.",
        ioc=json.dumps(["df8a96cde7a1db39ad8119c4d9bc272d1a3c6be4a0b2d3c948db7e2e34ff601c", "com.apex.crypto.wallet", "194.26.135.84"]),
        recommendations="Isolate immediate host nodes. Block C2 IP 194.26.135.84.",
        soc_commentary="Critical credential harvester payload."
    )
    db.add(ai4)

    # Seed Training Samples for Online Learning model
    ts1 = TrainingSample(
        apk_id=apk1.id,
        feature_text="android.permission.INTERNET android.permission.ACCESS_NETWORK_STATE com.secops.safe.utility.MainActivity com.secops.safe.utility.SettingsActivity getSystemService initView onStart",
        label=0,
        risk_score=12.0,
        malware_probability=0.024,
        verdict="Safe",
        model_version=1
    )
    ts2 = TrainingSample(
        apk_id=apk2.id,
        feature_text="android.permission.INTERNET android.permission.ACCESS_NETWORK_STATE android.permission.WRITE_EXTERNAL_STORAGE android.permission.RECEIVE_BOOT_COMPLETED com.adpromo.wallpapers.MainActivity com.adpromo.wallpapers.AdActivity com.adpromo.wallpapers.AdBackgroundService getBannerView getClickUrl loadAd invoke getMethod",
        label=0,
        risk_score=45.0,
        malware_probability=0.421,
        verdict="Suspicious",
        model_version=2
    )
    ts3 = TrainingSample(
        apk_id=apk3.id,
        feature_text="android.permission.INTERNET android.permission.RECORD_AUDIO android.permission.CAMERA android.permission.ACCESS_FINE_LOCATION android.permission.READ_CONTACTS com.spyware.tracker.MainActivity com.spyware.tracker.SpyService record startRecording takePicture getLastKnownLocation decrypt cipher invoke",
        label=1,
        risk_score=76.0,
        malware_probability=0.812,
        verdict="High Risk",
        model_version=3
    )
    ts4 = TrainingSample(
        apk_id=apk4.id,
        feature_text="android.permission.INTERNET android.permission.SYSTEM_ALERT_WINDOW android.permission.BIND_ACCESSIBILITY_SERVICE android.permission.SEND_SMS android.permission.RECEIVE_SMS android.permission.READ_SMS com.apex.crypto.wallet.MainActivity com.apex.crypto.wallet.OverlayActivity com.apex.crypto.wallet.HijackService sendTextMessage getSystemService loadClass invoke getMethod decrypt cipher DexClassLoader",
        label=1,
        risk_score=91.0,
        malware_probability=0.954,
        verdict="Critical",
        model_version=4
    )
    db.add(ts1)
    db.add(ts2)
    db.add(ts3)
    db.add(ts4)

    db.commit()
    print("Database seeding completed successfully.")

    # Initialize Online Learner pkl assets with the seeded samples
    try:
        from app.online_learner import OnlineLearner
        learner = OnlineLearner()
        # Train sequentially
        learner.learn(ts1.feature_text, ts1.label)
        learner.learn(ts2.feature_text, ts2.label)
        learner.learn(ts3.feature_text, ts3.label)
        learner.learn(ts4.feature_text, ts4.label)
        learner.force_save()
        print("Online learner initialized with seeded samples.")
    except Exception as e:
        print(f"Warning during online learner initialization: {e}")

