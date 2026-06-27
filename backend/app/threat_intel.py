import re
import json

class ThreatIntelEngine:
    def __init__(self):
        # Compiled regexes for pattern matching
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.telegram_pattern = re.compile(r'api\.telegram\.org', re.IGNORECASE)
        self.pastebin_pattern = re.compile(r'pastebin\.com', re.IGNORECASE)
        
        # Suspicious dynamic DNS / C2 domain suffixes
        self.ddns_patterns = [
            r'\.ddns\.net', r'\.no-ip\.', r'\.duckdns\.org', r'\.ngrok\.',
            r'\.serveblog\.net', r'\.serveftp\.com', r'\.hopto\.org'
        ]
        
        # Suspicious keywords in package names, methods, or URLs
        self.c2_keywords = ['c2', 'command', 'control', 'botnet', 'shell', 'payload', 'exploit']
        self.banking_keywords = ['bank', 'wallet', 'crypto', 'pay', 'checkout', 'creditcard', 'stripe']
        self.credential_keywords = ['login', 'password', 'credential', 'auth', 'signin', 'token', 'session']

    def analyze(self, urls: list[str], domains: list[str], ips: list[str], methods: list[str], package_name: str) -> dict:
        indicators = []
        threat_score = 0.0

        # 1. Check for Telegram Bot API (commonly used for C2 exfiltration in Android spyware)
        for url in urls:
            if self.telegram_pattern.search(url):
                indicators.append({
                    "indicator": f"Telegram Bot API URL detected: {url}",
                    "type": "C2 Channel",
                    "severity": "CRITICAL",
                    "weight": 35.0
                })
            if self.pastebin_pattern.search(url):
                indicators.append({
                    "indicator": f"Pastebin URL detected: {url} (often used for hosted payloads/C2 configs)",
                    "type": "Payload Delivery / C2",
                    "severity": "HIGH",
                    "weight": 25.0
                })
            # Check for raw IP connections
            if self.ip_pattern.search(url):
                # Ensure it's not a local IP
                if not url.startswith(("http://127.0.0.1", "https://127.0.0.1", "http://10.", "http://192.168.")):
                    indicators.append({
                        "indicator": f"Raw public IP connection URL: {url}",
                        "type": "Suspicious Network Connection",
                        "severity": "HIGH",
                        "weight": 20.0
                    })

        # 2. Analyze domains
        for domain in domains:
            for pattern in self.ddns_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    indicators.append({
                        "indicator": f"Dynamic DNS / C2 domain detected: {domain}",
                        "type": "C2 Infrastructure",
                        "severity": "CRITICAL",
                        "weight": 30.0
                    })
            # Check for generic C2 keywords in domain names
            for word in self.c2_keywords:
                if word in domain.lower():
                    indicators.append({
                        "indicator": f"C2 keyword '{word}' found in domain: {domain}",
                        "type": "C2 Domain",
                        "severity": "HIGH",
                        "weight": 15.0
                    })

        # 3. Analyze IPs
        for ip in ips:
            # Skip local or private IPs
            if ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.31.")):
                continue
            indicators.append({
                "indicator": f"Hardcoded outbound IP connection: {ip}",
                "type": "Network Connection",
                "severity": "MEDIUM",
                "weight": 10.0
            })

        # 4. Analyze methods
        # Look for SMS fraud methods
        sms_methods = [m for m in methods if 'sms' in m.lower() or 'textmessage' in m.lower()]
        if sms_methods:
            indicators.append({
                "indicator": f"SMS-sending/receiving API methods found: {', '.join(sms_methods[:3])}",
                "type": "SMS Fraud / Spyware",
                "severity": "HIGH",
                "weight": 20.0
            })

        # Look for system overlays / banking trojan indicators
        overlay_methods = [m for m in methods if 'window' in m.lower() or 'overlay' in m.lower() or 'alert' in m.lower()]
        if overlay_methods:
            indicators.append({
                "indicator": f"Overlay/System alert window APIs found: {', '.join(overlay_methods[:3])}",
                "type": "Banking Trojan / Overlay Hijacking",
                "severity": "HIGH",
                "weight": 20.0
            })

        # Look for accessibility hijacking methods
        accessibility_methods = [m for m in methods if 'accessibility' in m.lower() or 'service' in m.lower() and 'event' in m.lower()]
        if accessibility_methods:
            indicators.append({
                "indicator": "Accessibility Service API abuse hooks detected",
                "type": "Credential Theft / Ransomware",
                "severity": "CRITICAL",
                "weight": 30.0
            })

        # Look for reflection/obfuscation methods
        reflection_methods = [m for m in methods if 'invoke' in m.lower() or 'getmethod' in m.lower() or 'getdeclaredfield' in m.lower()]
        if reflection_methods:
            indicators.append({
                "indicator": "Reflection & Dynamic API Loading methods found (evasion technique)",
                "type": "Evasion / Obfuscation",
                "severity": "MEDIUM",
                "weight": 10.0
            })

        # 5. Check Package Name
        for kw in self.banking_keywords:
            if kw in package_name.lower():
                # If package claims to be a bank/wallet but doesn't have official domain or signature, it's highly suspicious
                indicators.append({
                    "indicator": f"Package name contains finance keyword '{kw}': {package_name}",
                    "type": "Financial Phishing / Impersonation",
                    "severity": "HIGH",
                    "weight": 15.0
                })

        # Sum up weights to get threat score (capped at 100)
        total_weight = sum([ind["weight"] for ind in indicators])
        threat_score = min(total_weight, 100.0)

        # Determine Severity based on Threat Score
        if threat_score >= 75.0:
            severity = "CRITICAL"
        elif threat_score >= 50.0:
            severity = "HIGH"
        elif threat_score >= 20.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "threat_score": round(threat_score, 1),
            "severity": severity,
            "indicators": indicators
        }
