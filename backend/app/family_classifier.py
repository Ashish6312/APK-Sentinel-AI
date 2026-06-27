class FamilyClassifier:
    """
    Attributes analyzed APKs to major Android malware families (Joker, BankBot, Anubis, etc.)
    based on permissions, bytecode method signatures, and package metadata.
    """
    def __init__(self):
        # Threat categories mapping
        self.categories = {
            "Joker": "Spyware / SMS Fraud",
            "BankBot": "Banking Trojan",
            "Anubis": "Banking Trojan",
            "Cerberus": "Banking Trojan",
            "Banking Trojan": "Banking Trojan",
            "Spyware": "Spyware / Surveillance",
            "Adware": "Adware / PUP",
            "Ransomware": "Ransomware / Screen Locker",
            "RAT": "Remote Access Trojan"
        }

    def classify(self, permissions: list[str], methods: list[str], urls: list[str], package_name: str) -> list[dict]:
        results = []
        
        # Helper set conversions for fast lookup
        perm_set = {p.upper() for p in permissions}
        method_set = {m.lower() for m in methods}
        url_set = {u.lower() for u in urls}
        pkg_lower = package_name.lower()

        # ----------------------------------------------------
        # 1. Joker Attribution
        # ----------------------------------------------------
        joker_score = 0.0
        # SMS permissions (SEND, RECEIVE, READ)
        sms_perms = {"ANDROID.PERMISSION.SEND_SMS", "ANDROID.PERMISSION.RECEIVE_SMS", "ANDROID.PERMISSION.READ_SMS"}
        joker_score += len(perm_set.intersection(sms_perms)) * 10.0
        
        # Dynamic loading methods
        dyn_methods = {"loadclass", "dexclassloader", "loaddex"}
        joker_score += len(method_set.intersection(dyn_methods)) * 15.0
        
        if "ANDROID.PERMISSION.READ_PHONE_STATE" in perm_set:
            joker_score += 15.0
        if any(kw in pkg_lower for kw in ["agent", "premium", "update", "service"]):
            joker_score += 15.0
        if "ANDROID.PERMISSION.RECEIVE_BOOT_COMPLETED" in perm_set:
            joker_score += 10.0
        
        joker_score = min(joker_score, 95.0)

        # ----------------------------------------------------
        # 2. BankBot Attribution
        # ----------------------------------------------------
        bankbot_score = 0.0
        if "ANDROID.PERMISSION.BIND_ACCESSIBILITY_SERVICE" in perm_set:
            bankbot_score += 35.0
        if "ANDROID.PERMISSION.SYSTEM_ALERT_WINDOW" in perm_set:
            bankbot_score += 25.0
        if any(m in method_set for m in ["getrunningappprocesses", "getrunningservices"]):
            bankbot_score += 15.0
        if any(kw in pkg_lower or kw in "".join(url_set) for kw in ["bank", "wallet", "checkout", "stripe", "pay"]):
            bankbot_score += 15.0
        if "ANDROID.PERMISSION.RECEIVE_BOOT_COMPLETED" in perm_set:
            bankbot_score += 10.0
            
        bankbot_score = min(bankbot_score, 95.0)

        # ----------------------------------------------------
        # 3. Anubis Attribution
        # ----------------------------------------------------
        anubis_score = 0.0
        if "ANDROID.PERMISSION.BIND_ACCESSIBILITY_SERVICE" in perm_set:
            anubis_score += 30.0
        if "ANDROID.PERMISSION.SYSTEM_ALERT_WINDOW" in perm_set:
            anubis_score += 20.0
        if len(perm_set.intersection(sms_perms)) > 0:
            anubis_score += 15.0
        if "android.intent.action.boot_completed" in "".join(method_set):
            anubis_score += 15.0
        if any(m in method_set for m in ["record", "startrecording"]):
            anubis_score += 15.0
            
        anubis_score = min(anubis_score, 95.0)

        # ----------------------------------------------------
        # 4. Cerberus Attribution
        # ----------------------------------------------------
        cerberus_score = 0.0
        if "ANDROID.PERMISSION.BIND_ACCESSIBILITY_SERVICE" in perm_set:
            cerberus_score += 30.0
        if "ANDROID.PERMISSION.SYSTEM_ALERT_WINDOW" in perm_set:
            cerberus_score += 20.0
        if len(perm_set.intersection(sms_perms)) > 0:
            cerberus_score += 15.0
        if "ANDROID.PERMISSION.WRITE_EXTERNAL_STORAGE" in perm_set:
            cerberus_score += 10.0
        if "ANDROID.PERMISSION.READ_CONTACTS" in perm_set or "ANDROID.PERMISSION.READ_CALL_LOG" in perm_set:
            cerberus_score += 15.0
        if "device_admin" in "".join(method_set) or "deviceadmin" in "".join(method_set):
            cerberus_score += 10.0
            
        cerberus_score = min(cerberus_score, 95.0)

        # ----------------------------------------------------
        # 5. Spyware Attribution
        # ----------------------------------------------------
        spyware_score = 0.0
        if "ANDROID.PERMISSION.RECORD_AUDIO" in perm_set:
            spyware_score += 25.0
        if "ANDROID.PERMISSION.READ_CONTACTS" in perm_set or "ANDROID.PERMISSION.READ_CALL_LOG" in perm_set:
            spyware_score += 20.0
        if "ANDROID.PERMISSION.CAMERA" in perm_set:
            spyware_score += 15.0
        if "ANDROID.PERMISSION.ACCESS_FINE_LOCATION" in perm_set or "ANDROID.PERMISSION.ACCESS_COARSE_LOCATION" in perm_set:
            spyware_score += 15.0
        if any("telegram" in u or "pastebin" in u or "194." in u for u in url_set):
            spyware_score += 15.0
        if "ANDROID.PERMISSION.ACCESS_BACKGROUND_LOCATION" in perm_set:
            spyware_score += 10.0
            
        spyware_score = min(spyware_score, 95.0)

        # ----------------------------------------------------
        # 6. Adware Attribution
        # ----------------------------------------------------
        adware_score = 0.0
        if any(m in method_set for m in ["getbannerview", "getclickurl", "loadad"]):
            adware_score += 30.0
        if len(perm_set.intersection({"ANDROID.PERMISSION.INTERNET", "ANDROID.PERMISSION.ACCESS_NETWORK_STATE"})) == 2:
            adware_score += 20.0
        if any(kw in pkg_lower for kw in ["ad", "ads", "promo", "banner"]):
            adware_score += 15.0
        if any("googleads" in u or "doubleclick" in u or "admob" in u for u in url_set):
            adware_score += 20.0
        
        adware_score = min(adware_score, 95.0)

        # ----------------------------------------------------
        # 7. Ransomware Attribution
        # ----------------------------------------------------
        ransomware_score = 0.0
        if "ANDROID.PERMISSION.SYSTEM_ALERT_WINDOW" in perm_set:
            ransomware_score += 25.0
        if "ANDROID.PERMISSION.WRITE_EXTERNAL_STORAGE" in perm_set:
            ransomware_score += 20.0
        if any("encrypt" in m or "cipher" in m for m in method_set):
            ransomware_score += 25.0
        if "device_admin" in "".join(method_set) or "deviceadmin" in "".join(method_set):
            ransomware_score += 15.0
        if any("lock" in m or "disablekeyguard" in m for m in method_set):
            ransomware_score += 15.0
            
        ransomware_score = min(ransomware_score, 95.0)

        # ----------------------------------------------------
        # 8. RAT Attribution (Heuristic Signature)
        # ----------------------------------------------------
        rat_score = 0.0
        # Remote C2 signature: URL/IP indicators or specific socket connections
        if any(kw in "".join(url_set) or kw in pkg_lower for kw in ["c2", "194.", "telegram", "bot", "gate"]):
            rat_score += 50.0
        # Background Service: background worker or autostart triggers
        if "ANDROID.PERMISSION.RECEIVE_BOOT_COMPLETED" in perm_set or any("service" in m or "run" in m for m in method_set):
            rat_score += 45.0
        rat_score = min(rat_score, 95.0)

        # Compile and sort
        banking_trojan_score = max(bankbot_score, anubis_score, cerberus_score)
        
        family_scores = [
            ("Banking Trojan", banking_trojan_score),
            ("Spyware", spyware_score),
            ("RAT", rat_score),
            ("Joker", joker_score),
            ("Adware", adware_score),
            ("Ransomware", ransomware_score)
        ]

        # Determine confidence for each
        for family, score in family_scores:
            if score >= 75.0:
                confidence = "HIGH"
            elif score >= 40.0:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"
            
            # Baseline similarity for generic software
            if score < 10.0:
                score = 5.0 + (len(perm_set) % 5) # Generates a low variety baseline

            results.append({
                "family_name": family,
                "similarity_score": round(score, 1),
                "confidence": confidence,
                "threat_category": self.categories[family]
            })

        # Sort descending
        return sorted(results, key=lambda x: x["similarity_score"], reverse=True)
