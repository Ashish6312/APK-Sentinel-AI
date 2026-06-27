class ObfuscationEngine:
    def __init__(self):
        # API markers indicating reflection usage
        self.reflection_indicators = [
            "invoke", "getMethod", "getDeclaredMethod", "forName", "Class.forName",
            "getDeclaredField", "getDeclaredConstructor"
        ]
        # API markers indicating dynamic dex/class loading
        self.dynamic_loading_indicators = [
            "DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader", 
            "loadClass", "loadDex", "defineClass"
        ]
        # Common cryptographic/decryption indicators
        self.encryption_indicators = [
            "decrypt", "encrypt", "cipher", "SecretKeySpec", "SecretKey", 
            "ivspec", "Cipher.getInstance", "AES", "DES", "rc4", "blowfish"
        ]
        # Packer signatures in package name/classes/methods
        self.packer_indicators = [
            "qihoo", "libjiagu", "StubShell", "tx_shell", "libshell", "baidu.protect", 
            "libbaiduprotect", "secshell", "libsecexe", "libsecmain", "ijiami", "libijm", 
            "ali.mobisec", "libmobisec", "netease.nis", "libyidun", "asgguard", "dexprotect"
        ]

    def analyze(self, package_name: str, permissions: list[str], methods: list[str]) -> dict:
        """
        Analyzes the extracted static metadata to assess obfuscation, packing, and dynamic execution risk.
        Returns a dict containing the obfuscation score (0-100) and findings list.
        """
        findings = []
        score = 0.0

        # 1. Packer / Protector Attributions
        matched_packers = []
        for p in self.packer_indicators:
            if p.lower() in package_name.lower():
                matched_packers.append(p)
        
        # Also check methods for obvious protector class strings if package doesn't catch them
        method_packer_matches = [m for m in methods if any(p.lower() in m.lower() for p in self.packer_indicators)]
        if matched_packers or method_packer_matches:
            evidence = f"Packer signature match: {', '.join(matched_packers + list(set(method_packer_matches[:2])))}"
            findings.append({
                "category": "Protector / Packed Wrapper",
                "evidence": evidence,
                "score": 60.0
            })
            score += 60.0

        # 2. Reflection Usage
        reflection_matches = [m for m in methods if any(r in m for r in self.reflection_indicators)]
        if reflection_matches:
            findings.append({
                "category": "Reflection APIs",
                "evidence": f"Identified reflection APIs: {', '.join(reflection_matches[:3])}",
                "score": 15.0
            })
            score += 15.0

        # 3. Dynamic Code Execution
        dyn_matches = [m for m in methods if any(d in m for d in self.dynamic_loading_indicators)]
        if dyn_matches:
            findings.append({
                "category": "Dynamic Class Loading",
                "evidence": f"Found dynamic loader methods: {', '.join(dyn_matches[:3])}",
                "score": 25.0
            })
            score += 25.0

        # 4. Decryption / Encryption Triggers
        crypto_matches = [m for m in methods if any(e.lower() in m.lower() for e in self.encryption_indicators)]
        if crypto_matches:
            findings.append({
                "category": "Cryptographic Execution",
                "evidence": f"Identified cryptographic operations: {', '.join(crypto_matches[:3])}",
                "score": 15.0
            })
            score += 15.0

        # 5. Evasive Combination scoring
        if len(dyn_matches) > 0 and ("android.permission.RECEIVE_BOOT_COMPLETED" in permissions):
            findings.append({
                "category": "Evasive Combinations",
                "evidence": "Combines dynamic class loading with auto-start permissions",
                "score": 10.0
            })
            score += 10.0

        final_score = min(score, 100.0)

        # Ensure that if the APK is completely normal/benign it stays at 0
        if not findings:
            final_score = 0.0

        return {
            "obfuscation_score": round(final_score, 1),
            "findings": findings
        }
