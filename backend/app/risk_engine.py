class RiskEngine:
    def __init__(self):
        # Weighted dangerous permissions
        self.dangerous_perms_weights = {
            "android.permission.BIND_ACCESSIBILITY_SERVICE": 45.0,
            "android.permission.SYSTEM_ALERT_WINDOW": 40.0,
            "android.permission.SEND_SMS": 30.0,
            "android.permission.RECEIVE_SMS": 30.0,
            "android.permission.READ_SMS": 25.0,
            "android.permission.REQUEST_INSTALL_PACKAGES": 25.0,
            "android.permission.RECORD_AUDIO": 20.0,
            "android.permission.CAMERA": 20.0,
            "android.permission.READ_CALL_LOG": 20.0,
            "android.permission.READ_CONTACTS": 15.0,
            "android.permission.ACCESS_FINE_LOCATION": 15.0,
            "android.permission.ACCESS_COARSE_LOCATION": 10.0,
            "android.permission.READ_PHONE_STATE": 15.0,
            "android.permission.WRITE_EXTERNAL_STORAGE": 10.0,
            "android.permission.READ_EXTERNAL_STORAGE": 10.0,
            "android.permission.GET_ACCOUNTS": 10.0
        }
        
        # Severity weights for MITRE techniques
        self.severity_mapping = {
            "CRITICAL": 100.0,
            "HIGH": 75.0,
            "MEDIUM": 45.0,
            "LOW": 15.0
        }

    def calculate_permission_risk(self, permissions: list[str]) -> float:
        score = 0.0
        for perm in permissions:
            if perm in self.dangerous_perms_weights:
                score += self.dangerous_perms_weights[perm]
        return min(score, 100.0)

    def calculate_mitre_score(self, mitre_techniques: list[dict]) -> float:
        if not mitre_techniques:
            return 0.0
        max_score = 0.0
        for tech in mitre_techniques:
            sev = tech.get("severity", "LOW")
            score = self.severity_mapping.get(sev, 15.0)
            if score > max_score:
                max_score = score
        return max_score

    def calculate_risk(
        self, 
        permissions: list[str], 
        threat_intel_score: float, 
        obfuscation_score: float, 
        mitre_techniques: list[dict],
        dynamic_behavior_score: float = 0.0
    ) -> dict:
        """
        Calculates the 4-factor risk metric:
        Final Risk = (0.25 * Permission Risk) + (0.25 * Network Risk) + (0.25 * Obfuscation Risk) + (0.25 * Behavior Risk)
        Categorize risk levels: Low (0-30), Suspicious (31-60), High (61-80), and Critical (81-100).
        """
        # 1. Permission Risk contribution (25%)
        perm_risk = self.calculate_permission_risk(permissions)
        
        # 2. Network Risk contribution (25%)
        network_risk = threat_intel_score
        
        # 3. Obfuscation Risk contribution (25%)
        obfuscation_risk = obfuscation_score
        
        # 4. Behavior Risk contribution (25%)
        # Combine static MITRE rules severity and runtime dynamic behavior logs
        mitre_score = self.calculate_mitre_score(mitre_techniques)
        behavior_risk = max(mitre_score, dynamic_behavior_score)
        
        # Final weighted score
        final_score = (
            (0.25 * perm_risk) + 
            (0.25 * network_risk) + 
            (0.25 * obfuscation_risk) + 
            (0.25 * behavior_risk)
        )
        
        # Round final score
        risk_score = round(final_score, 1)
        
        # Determine Verdict and Risk Level
        if risk_score <= 30.0:
            risk_level = "LOW"
            verdict = "Safe"
        elif risk_score <= 60.0:
            risk_level = "MEDIUM"
            verdict = "Suspicious"
        elif risk_score <= 80.0:
            risk_level = "HIGH"
            verdict = "High Risk"
        else:
            risk_level = "CRITICAL"
            verdict = "Critical"
            
        return {
            "risk_score": risk_score,
            "verdict": verdict,
            "risk_level": risk_level,
            "breakdown": {
                "permission_risk_score": round(perm_risk, 1),
                "threat_intel_score": round(network_risk, 1),
                "obfuscation_risk_score": round(obfuscation_risk, 1),
                "mitre_severity_score": round(behavior_risk, 1)
            }
        }
