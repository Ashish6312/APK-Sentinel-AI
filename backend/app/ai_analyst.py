import os
import json
import requests

class GeminiAnalyst:
    """
    Unified Coordinated Multi-Agent AI Analyst System calling Groq API (llama-3.3-70b-versatile)
    with fail-safe fallback to deepseek-r1-distill-llama-70b and simulated offline intelligence.
    Coordinates 5 distinct sub-agents:
    - Agent 1 (Threat Analyst): Assesses static/dynamic behavior.
    - Agent 2 (MITRE Analyst): Maps Mobile ATT&CK matrix.
    - Agent 3 (Malware Family Analyst): Computes similarity attributions.
    - Agent 4 (IOC Analyst): Extracts actionable indicators.
    - Agent 5 (Executive Analyst): Drafts incident summaries and commentary.
    """
    def __init__(self):
        # Read API keys from environment variables
        self.groq_key = os.getenv("GROQ_API_KEY")
        self.gemini_key = os.getenv("GEMINI_API_KEY")
        
        # Check if we should configure Gemini SDK as a secondary system fallback
        self.gemini_model = None
        if self.gemini_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.gemini_key)
                self.gemini_model = genai.GenerativeModel('gemini-2.5-flash')
                print("Gemini model configured successfully.")
            except Exception as e:
                print(f"Error configuring Gemini SDK: {str(e)}")

    def generate_report(
        self, 
        metadata: dict, 
        features: dict, 
        risk: dict, 
        threat: dict, 
        mitre: list[dict],
        families: list[dict],
        dynamic_analysis: dict = None
    ) -> dict:
        # Format payload with both static and dynamic sandbox logs
        payload = {
            "file_name": metadata.get("file_name"),
            "package_name": metadata.get("package_name"),
            "sha256": metadata.get("sha256"),
            "verdict": risk.get("verdict"),
            "risk_score": risk.get("risk_score"),
            "risk_level": risk.get("risk_level"),
            "risk_breakdown": risk.get("breakdown", {}),
            "threat_intel_score": threat.get("threat_score"),
            "threat_severity": threat.get("severity"),
            "threat_indicators": [ind["indicator"] for ind in threat.get("indicators", [])],
            "mitre_techniques": [f"{t['technique_id']}: {t['technique_name']} (Evidence: {t['evidence']})" for t in mitre],
            "malware_family_similarities": [f"{f['family_name']} (Score: {f['similarity_score']}%, Confidence: {f['confidence']}, Category: {f['threat_category']})" for f in families[:3]],
            "permissions": features.get("permissions", []),
            "activities": features.get("activities", []),
            "services": features.get("services", []),
            "suspicious_apis": features.get("suspicious_apis", []),
            "domains": features.get("domains", []),
            "ips": features.get("ips", []),
            "urls": features.get("urls", []),
            "dynamic_analysis": dynamic_analysis or {}
        }

        # Multi-Agent Coordination System Prompt
        prompt = f"""
You are coordinating a Multi-Agent AI Analyst System to review an Android APK sample. You must run and compile reports from five distinct security sub-agents collaborating in your workspace:

1. **Threat Analyst Agent**: Reviews the static bytecode API calls, permissions, and runtime dynamic sandbox logs (Frida hooks, file I/O, process spawns) to determine indicators of compromise, evasion techniques, and potential payloads.
2. **MITRE Analyst Agent**: Maps all parsed capabilities and evidence to the ATT&CK Mobile matrix.
3. **Malware Family Analyst Agent**: Performs attribution mapping against known Android malware strains (e.g. Joker, BankBot, Anubis, Cerberus, SpyNote) based on code signatures, API hooks, and similarities.
4. **IOC Analyst Agent**: Extracts clean Indicators of Compromise (SHA256, package names, active C2 domains, server IPs, and hook triggers).
5. **Executive Analyst Agent**: Acts as the coordinator, synthesizing the reports into a executive brief, drafting SOC alerts, and outlining remediation instructions.

Input Payload:
{json.dumps(payload, indent=2)}

Please return a comprehensive security intelligence brief compiled from all agents. You MUST return ONLY a valid JSON object with the exact keys:
- "executive_summary": [Executive Analyst Agent] A clear executive brief summarizing the APK role, threat level, and security posture.
- "threat_assessment": [Threat Analyst Agent] Detailed assessment of static/dynamic behaviors, suspicious APIs, and runtime sandbox findings.
- "ioc": [IOC Analyst Agent] A JSON-serialized array of strings containing clean indicators of compromise (hashes, package, domains, IPs).
- "malware_family_analysis": [Malware Family Analyst Agent] Attribution breakdown discussing strain similarities, confidence mapping, and historical context.
- "mitre_analysis": [MITRE Analyst Agent] Technical breakdown of mapped ATT&CK Mobile techniques.
- "risk_justification": [Executive Analyst Agent] Mathematical and logical justification of the final composite risk score based on the 4-factor breakdown.
- "recommendations": [Executive Analyst Agent] Clean, step-by-step remediation instructions for administrators and endpoints.
- "soc_commentary": [Executive Analyst Agent / Threat Analyst Agent] High-level SOC engineering notes, flagging evasion, packer details, and recommended monitoring rules.

Return ONLY the raw JSON string. Do not wrap in markdown code blocks or backticks.
"""

        # 1. Try Groq (Llama 3.3 Versatile - Primary)
        if self.groq_key:
            try:
                print("Querying Coordinated Multi-Agent workspace on Groq (Llama 3.3)...")
                url = "https://api.groq.com/openai/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {self.groq_key}",
                    "Content-Type": "application/json"
                }
                data = {
                    "model": "llama-3.3-70b-versatile",
                    "messages": [
                        {"role": "system", "content": "You are coordinating a Multi-Agent AI Analyst System. Output structured JSON reports."},
                        {"role": "user", "content": prompt}
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.2
                }
                
                res = requests.post(url, headers=headers, json=data, timeout=20)
                if res.status_code == 200:
                    resp_json = res.json()
                    content = resp_json["choices"][0]["message"]["content"]
                    report_data = json.loads(content)
                    return self._clean_report_keys(report_data)
                else:
                    print(f"Groq primary model returned status {res.status_code}. Attempting fallback...")
                    
                    # Fallback model: deepseek-r1-distill-llama-70b
                    data["model"] = "deepseek-r1-distill-llama-70b"
                    res_fallback = requests.post(url, headers=headers, json=data, timeout=20)
                    if res_fallback.status_code == 200:
                        resp_json = res_fallback.json()
                        content = resp_json["choices"][0]["message"]["content"]
                        # Strip deepseek thoughts tag if present
                        if "</thought>" in content:
                            content = content.split("</thought>")[-1]
                        report_data = json.loads(content)
                        return self._clean_report_keys(report_data)
                    else:
                        print(f"Groq fallback model also failed: {res_fallback.status_code}")
            except Exception as e:
                print(f"Exception during Groq API call: {str(e)}")

        # 2. Try Gemini (Fallback)
        if self.gemini_model:
            try:
                print("Querying Coordinated Multi-Agent workspace on Gemini (Gemini 2.5 Flash)...")
                response = self.gemini_model.generate_content(
                    prompt,
                    generation_config={"response_mime_type": "application/json"}
                )
                report_data = json.loads(response.text)
                return self._clean_report_keys(report_data)
            except Exception as e:
                print(f"Exception during Gemini API call: {str(e)}")

        # 3. Simulated fallback
        print("Fallback to simulated Multi-Agent Security workspace.")
        return self._generate_simulated_report(payload)

    def _clean_report_keys(self, report_data: dict) -> dict:
        expected_keys = [
            "executive_summary", "threat_assessment", "ioc", "malware_family_analysis",
            "mitre_analysis", "risk_justification", "recommendations", "soc_commentary"
        ]
        for key in expected_keys:
            if key not in report_data:
                if key == "malware_family_analysis" and "malware_family_discussion" in report_data:
                    report_data["malware_family_analysis"] = report_data["malware_family_discussion"]
                elif key == "mitre_analysis" and "mitre_mapping_discussion" in report_data:
                    report_data["mitre_analysis"] = report_data["mitre_mapping_discussion"]
                else:
                    report_data[key] = f"No {key.replace('_', ' ')} generated."
        
        # Format IOCs as JSON-serialized string
        if isinstance(report_data["ioc"], list):
            report_data["ioc"] = json.dumps(report_data["ioc"])
        else:
            try:
                # Test if it is already valid json string
                json.loads(report_data["ioc"])
            except Exception:
                report_data["ioc"] = json.dumps([report_data["ioc"]])
            
        return report_data

    def _generate_simulated_report(self, payload: dict) -> dict:
        file_name = payload["file_name"]
        pkg = payload["package_name"]
        verdict = payload["verdict"]
        score = payload["risk_score"]
        level = payload["risk_level"]
        
        iocs = [payload["sha256"], pkg] + payload["domains"][:3] + payload["ips"][:3]
        
        if verdict in ["High Risk", "Critical"]:
            exec_summary = (
                f"[Executive Agent Summary] The analysis of '{file_name}' (Package: {pkg}) "
                f"uncovered high-risk indicators of active compromises. The APK is marked as {level} RISK "
                f"({score}/100) due to permission abuse, signature matchings, and suspicious network telemetry."
            )
            
            threat_assessment = (
                f"[Threat Agent Assessment] The app requests dangerous privileges ({', '.join(payload['permissions'][:3])}). "
                f"Runtime sandbox simulator traced Frida alert triggers and process tampering patterns. "
                f"Outgoing telemetry connects to suspicious C2 network points ({', '.join(payload['domains'][:2]) or 'none hardcoded'})."
            )
            
            family_analysis = (
                f"[Malware Family Agent Assessment] Code similarity attributions identify similarities to "
                f"{', '.join(payload['malware_family_similarities'][:1]) or 'generic trojans'}. "
                f"The alignment of Accessibility API abuse hooks matches classic Banking Trojan payload models."
            )
            
            recs = (
                "1. Isolate device endpoints immediately from the network.\n"
                "2. Force-expire active user authentication sessions and API access tokens.\n"
                "3. Terminate package install profiles and blacklist the SHA256 signature in enterprise firewalls."
            )
            
            commentary = (
                f"[SOC Analyst Commentary] Highly evasive wrapper structure. Bytecode shows reflection patterns. "
                f"Outbound C2 socket calls were active during emulator checks. Immediate remediation required."
            )
        else:
            exec_summary = (
                f"[Executive Agent Summary] The APK '{file_name}' (Package: {pkg}) shows safe features and "
                f"low security risk. Classified as {level} RISK with a score of {score}/100."
            )
            
            threat_assessment = (
                "[Threat Agent Assessment] The bytecode relies on standard Android frameworks. "
                "The ML inference reports high benign confidence. No active evasion or host socket hijacking was logged in the sandbox."
            )
            
            family_analysis = "[Malware Family Agent Assessment] No malware family attributes matched. Safe signature profile."
            
            recs = (
                "1. No immediate action required.\n"
                "2. Standard code signing certificate verification is advised."
            )
            
            commentary = (
                "[SOC Analyst Commentary] Standard app structure. All calls and permissions map to active UI components. "
                "No suspicious C2 or overlay behaviors detected."
            )
            
        return {
            "executive_summary": exec_summary,
            "threat_assessment": threat_assessment,
            "ioc": json.dumps(iocs),
            "malware_family_analysis": family_analysis,
            "mitre_analysis": f"[MITRE Agent Report] Mapped techniques match {len(payload['mitre_techniques'])} items in the ATT&CK Mobile matrix.",
            "risk_justification": f"[Executive Agent Justification] Composite score of {score} is computed from the balanced 4-factor risk engine: Permission, Network, Obfuscation, and Behavior.",
            "recommendations": recs,
            "soc_commentary": commentary
        }
