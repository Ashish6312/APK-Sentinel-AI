import re

class DynamicSandbox:
    def __init__(self):
        pass

    def simulate(self, package_name: str, permissions: list[str], urls: list[str], ips: list[str]) -> dict:
        """
        Generates realistic dynamic analysis telemetry (Frida hooks, processes, file/net activities)
        tailored to the APK's package, permissions, and network indicators.
        Returns a dictionary structure.
        """
        # Determine malware markers
        perm_set = {p.upper() for p in permissions}
        has_accessibility = "ANDROID.PERMISSION.BIND_ACCESSIBILITY_SERVICE" in perm_set
        has_overlay = "ANDROID.PERMISSION.SYSTEM_ALERT_WINDOW" in perm_set
        has_sms = any(p in perm_set for p in ["ANDROID.PERMISSION.SEND_SMS", "ANDROID.PERMISSION.RECEIVE_SMS", "ANDROID.PERMISSION.READ_SMS"])
        has_surveillance = any(p in perm_set for p in ["ANDROID.PERMISSION.RECORD_AUDIO", "ANDROID.PERMISSION.CAMERA", "ANDROID.PERMISSION.ACCESS_FINE_LOCATION"])
        
        is_banking = "crypto" in package_name.lower() or "wallet" in package_name.lower() or (has_accessibility and has_overlay)
        is_spyware = "tracker" in package_name.lower() or "spy" in package_name.lower() or (has_surveillance and not is_banking)
        is_adware = "ad" in package_name.lower() or "promo" in package_name.lower() or "wallpaper" in package_name.lower()
        
        # 1. Frida Instrumentation Logs
        frida_logs = []
        # 2. Process Spawns
        process_calls = []
        # 3. File System Operations
        file_activities = []
        # 4. Network Connections
        network_connections = []
        # 5. Runtime Permissions
        runtime_permissions = []
        
        behavior_score = 0.0

        if is_banking:
            behavior_score = 95.0
            frida_logs = [
                {"timestamp": "+0.42s", "tag": "FRIDA_HOOK", "message": "Intercepted JNI Call: RegisterNatives in libsecurity.so", "level": "WARNING"},
                {"timestamp": "+1.15s", "tag": "FRIDA_HOOK", "message": "Hooked android.view.View.onDraw() to monitor overlay layers", "level": "CRITICAL"},
                {"timestamp": "+2.84s", "tag": "ACCESSIBILITY", "message": "AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED read target input field: 'password'", "level": "CRITICAL"},
                {"timestamp": "+3.10s", "tag": "FRIDA_HOOK", "message": "Bypassed Certificate Pinning for OkHttpClient TrustManager", "level": "WARNING"}
            ]
            process_calls = [
                {"timestamp": "+0.00s", "parent": "zygote64", "process": package_name, "pid": 4820, "action": "spawn"},
                {"timestamp": "+1.50s", "parent": package_name, "process": "/system/bin/app_process", "pid": 4835, "action": "exec"},
                {"timestamp": "+4.20s", "parent": package_name, "process": "logcat", "pid": 4842, "action": "exec"}
            ]
            file_activities = [
                {"timestamp": "+0.80s", "operation": "read", "path": f"/data/user/0/{package_name}/databases/wallet.db", "status": "SUCCESS"},
                {"timestamp": "+1.20s", "operation": "write", "path": f"/data/user/0/{package_name}/shared_prefs/app_state.xml", "status": "SUCCESS"},
                {"timestamp": "+2.50s", "operation": "modify", "path": "/data/system/users/0/settings_secure.xml", "status": "DENIED (Sandbox Block)"}
            ]
            # Use IPs or Fallback
            c2_ip = ips[0] if ips else "194.26.135.84"
            network_connections = [
                {"timestamp": "+0.90s", "dest": f"{c2_ip}:8080", "protocol": "TCP", "status": "ESTABLISHED", "bytes_sent": 842, "bytes_rcvd": 240},
                {"timestamp": "+2.95s", "dest": f"{c2_ip}:8080", "protocol": "TCP", "status": "TRANSMITTING", "bytes_sent": 4096, "bytes_rcvd": 1024}
            ]
            runtime_permissions = [
                {"permission": "SYSTEM_ALERT_WINDOW", "state": "GRANTED_BY_USER", "usage": "Draw overlay over system launcher"},
                {"permission": "BIND_ACCESSIBILITY_SERVICE", "state": "GRANTED_BY_USER", "usage": "Monitor input keystrokes dynamically"}
            ]

        elif is_spyware:
            behavior_score = 75.0
            frida_logs = [
                {"timestamp": "+0.20s", "tag": "FRIDA_HOOK", "message": "Hooked android.media.MediaRecorder.start() to capture voice payload", "level": "CRITICAL"},
                {"timestamp": "+1.80s", "tag": "FRIDA_HOOK", "message": "Hooked android.hardware.Camera.takePicture() backdrop trigger", "level": "WARNING"},
                {"timestamp": "+2.50s", "tag": "LOCATION", "message": "Intercepted LocationManager.getLastKnownLocation() call", "level": "MEDIUM"}
            ]
            process_calls = [
                {"timestamp": "+0.00s", "parent": "zygote64", "process": package_name, "pid": 4910, "action": "spawn"},
                {"timestamp": "+0.90s", "parent": package_name, "process": "/system/bin/screencap", "pid": 4922, "action": "exec"}
            ]
            file_activities = [
                {"timestamp": "+0.50s", "operation": "write", "path": "/sdcard/Documents/spy_recording.mp4", "status": "SUCCESS"},
                {"timestamp": "+2.10s", "operation": "read", "path": "/data/user/0/com.android.providers.contacts/databases/contacts2.db", "status": "SUCCESS"}
            ]
            net_url = urls[0] if urls else "api.telegram.org"
            network_connections = [
                {"timestamp": "+1.10s", "dest": f"{net_url}:443", "protocol": "HTTPS", "status": "ESTABLISHED", "bytes_sent": 20480, "bytes_rcvd": 512}
            ]
            runtime_permissions = [
                {"permission": "RECORD_AUDIO", "state": "GRANTED_BY_USER", "usage": "Recording microphone buffer"},
                {"permission": "ACCESS_FINE_LOCATION", "state": "GRANTED_BY_USER", "usage": "Querying current GPS coordinates"}
            ]

        elif is_adware:
            behavior_score = 40.0
            frida_logs = [
                {"timestamp": "+0.35s", "tag": "AD_MONITOR", "message": "Ad SDK initialized: Google Mobile Ads (or secondary networks)", "level": "INFO"},
                {"timestamp": "+1.90s", "tag": "OVERLAY", "message": "Intercepted full-screen advertisement intent spawn", "level": "MEDIUM"}
            ]
            process_calls = [
                {"timestamp": "+0.00s", "parent": "zygote64", "process": package_name, "pid": 5012, "action": "spawn"}
            ]
            file_activities = [
                {"timestamp": "+0.40s", "operation": "write", "path": f"/data/user/0/{package_name}/cache/ad_cache.png", "status": "SUCCESS"}
            ]
            net_url = urls[0] if urls else "promo-clicks.com"
            network_connections = [
                {"timestamp": "+1.50s", "dest": f"{net_url}:80", "protocol": "HTTP", "status": "ESTABLISHED", "bytes_sent": 512, "bytes_rcvd": 102400}
            ]
            runtime_permissions = [
                {"permission": "WRITE_EXTERNAL_STORAGE", "state": "GRANTED_BY_USER", "usage": "Caching ad imagery asset packages"}
            ]

        else: # Safe Utility
            behavior_score = 10.0
            frida_logs = [
                {"timestamp": "+0.10s", "tag": "DETECTION", "message": "Safe environment initialized. No root bindings found.", "level": "INFO"}
            ]
            process_calls = [
                {"timestamp": "+0.00s", "parent": "zygote64", "process": package_name, "pid": 5110, "action": "spawn"}
            ]
            file_activities = [
                {"timestamp": "+0.15s", "operation": "read", "path": f"/data/user/0/{package_name}/shared_prefs/settings.xml", "status": "SUCCESS"}
            ]
            net_url = urls[0] if urls else "api.github.com"
            network_connections = [
                {"timestamp": "+0.50s", "dest": f"{net_url}:443", "protocol": "HTTPS", "status": "SUCCESS", "bytes_sent": 256, "bytes_rcvd": 1024}
            ]
            runtime_permissions = [
                {"permission": "INTERNET", "state": "ALLOWED_BY_MANIFEST", "usage": "Checking updates"}
            ]

        return {
            "behavior_score": behavior_score,
            "frida_logs": frida_logs,
            "process_calls": process_calls,
            "file_activities": file_activities,
            "network_connections": network_connections,
            "runtime_permissions": runtime_permissions
        }
