class MITREMapper:
    def __init__(self):
        # Mapping rules based on permissions
        self.permission_mappings = {
            "android.permission.SEND_SMS": {
                "technique_id": "T1636",
                "technique_name": "Capture SMS Messages",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence": "Requests permission to send SMS messages (SEND_SMS)."
            },
            "android.permission.READ_SMS": {
                "technique_id": "T1636",
                "technique_name": "Capture SMS Messages",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence": "Requests permission to read SMS messages stored on the device (READ_SMS)."
            },
            "android.permission.RECEIVE_SMS": {
                "technique_id": "T1636",
                "technique_name": "Capture SMS Messages",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence": "Requests permission to intercept incoming SMS messages (RECEIVE_SMS)."
            },
            "android.permission.RECORD_AUDIO": {
                "technique_id": "T1429",
                "technique_name": "Audio Capture",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence": "Requests permission to record audio via the device microphone (RECORD_AUDIO)."
            },
            "android.permission.CAMERA": {
                "technique_id": "T1512",
                "technique_name": "Video Capture",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "evidence": "Requests permission to access the device camera (CAMERA)."
            },
            "android.permission.READ_CONTACTS": {
                "technique_id": "T1430",
                "technique_name": "Access Sensitive Data",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "evidence": "Requests permission to read the user's address book contacts (READ_CONTACTS)."
            },
            "android.permission.READ_CALL_LOG": {
                "technique_id": "T1430",
                "technique_name": "Access Sensitive Data",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence": "Requests permission to view call history logs (READ_CALL_LOG)."
            },
            "android.permission.ACCESS_FINE_LOCATION": {
                "technique_id": "T1404",
                "technique_name": "Device Location Tracking",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "evidence": "Requests precise GPS location coordinates (ACCESS_FINE_LOCATION)."
            },
            "android.permission.ACCESS_COARSE_LOCATION": {
                "technique_id": "T1404",
                "technique_name": "Device Location Tracking",
                "severity": "LOW",
                "confidence": "HIGH",
                "evidence": "Requests network-based coarse location data (ACCESS_COARSE_LOCATION)."
            },
            "android.permission.RECEIVE_BOOT_COMPLETED": {
                "technique_id": "T1624",
                "technique_name": "Boot or Logon Initialization",
                "severity": "LOW",
                "confidence": "HIGH",
                "evidence": "Registers receiver to run automatically on device boot (RECEIVE_BOOT_COMPLETED)."
            },
            "android.permission.REQUEST_INSTALL_PACKAGES": {
                "technique_id": "T1477",
                "technique_name": "Install Other Applications",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence": "Requests permission to install other APK packages without user interface intervention (REQUEST_INSTALL_PACKAGES)."
            },
            "android.permission.SYSTEM_ALERT_WINDOW": {
                "technique_id": "T1546",
                "technique_name": "Input Capture via Overlay",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "evidence": "Requests drawing screen overlays to hijack user inputs or hide activities (SYSTEM_ALERT_WINDOW)."
            },
            "android.permission.READ_PHONE_STATE": {
                "technique_id": "T1426",
                "technique_name": "System Information Discovery",
                "severity": "LOW",
                "confidence": "HIGH",
                "evidence": "Requests access to telephony details including IMEI, IMSI, and carrier (READ_PHONE_STATE)."
            },
            "android.permission.BIND_ACCESSIBILITY_SERVICE": {
                "technique_id": "T1516",
                "technique_name": "Abuse Accessibility Service",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "evidence": "Requests binding to Android Accessibility Services to read screen content or simulate clicks."
            }
        }

        # Mapping rules based on API methods/heuristics
        self.method_mappings = {
            "getDeviceId": {
                "technique_id": "T1426",
                "technique_name": "System Information Discovery",
                "severity": "LOW",
                "confidence": "MEDIUM",
                "evidence": "Queries unique hardware identifier (IMEI/getDeviceId)."
            },
            "getSubscriberId": {
                "technique_id": "T1426",
                "technique_name": "System Information Discovery",
                "severity": "LOW",
                "confidence": "MEDIUM",
                "evidence": "Queries cellular network IMSI (getSubscriberId)."
            },
            "sendTextMessage": {
                "technique_id": "T1636",
                "technique_name": "Capture SMS / Send Premium SMS",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence": "Uses API to send raw SMS text messages background (sendTextMessage)."
            },
            "DexClassLoader": {
                "technique_id": "T1407",
                "technique_name": "Dynamic Code Execution",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence": "Invokes custom class loader to execute external .dex files dynamically."
            },
            "Runtime.exec": {
                "technique_id": "T1409",
                "technique_name": "Command Execution",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "evidence": "Executes shell commands directly on the underlying Linux OS."
            }
        }

    def map_to_attack(self, permissions: list[str], methods: list[str]) -> list[dict]:
        mapped = []
        seen_ids = set()

        # Check permissions
        for perm in permissions:
            if perm in self.permission_mappings:
                rule = self.permission_mappings[perm]
                tech_id = rule["technique_id"]
                if tech_id not in seen_ids:
                    mapped.append(rule)
                    seen_ids.add(tech_id)

        # Check methods
        for method in methods:
            for key, rule in self.method_mappings.items():
                if key in method:
                    tech_id = rule["technique_id"]
                    if tech_id not in seen_ids:
                        mapped.append(rule)
                        seen_ids.add(tech_id)

        return mapped
