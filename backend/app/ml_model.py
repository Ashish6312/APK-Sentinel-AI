import os
import joblib
import json
import re

# Set up paths
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_PATH = os.path.join(MODELS_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer.pkl")
LABEL_MAPPING_PATH = os.path.join(MODELS_DIR, "label_mapping.json")

# Precomputed global SHAP features for explanation
GLOBAL_SHAP_FEATURES = {
    "android.permission.read_phone_state": {"importance": 0.3006, "type": "Permission", "description": "Read phone state and hardware IDs (IMEI/IMSI)"},
    "android.permission.system_alert_window": {"importance": 0.2011, "type": "Permission", "description": "Draw screen overlays (overlay hijacking/phishing)"},
    "getloadermanager bumpbackstacknesting": {"importance": 0.1835, "type": "Method", "description": "Complex activity/fragment transition logging"},
    "start getplusonecount": {"importance": 0.1757, "type": "Method", "description": "Google Plus-One click trackers"},
    "android.permission.mount_unmount_filesystems": {"importance": 0.1564, "type": "Permission", "description": "Modify SD card filesystem structures"},
    "stopplaying not": {"importance": 0.1397, "type": "Method", "description": "Silence background system alerts or audio"},
    "getclickurl": {"importance": 0.1307, "type": "Method", "description": "Adware redirection or click-tracking URL"},
    "checkdrawerviewabsolutegravity starttracking": {"importance": 0.1296, "type": "Method", "description": "Intercept drawer UI gestures"},
    "attachfragment getbannerview": {"importance": 0.1202, "type": "Method", "description": "Dynamically load ads banners"},
    "com.google.android.c2dm.permission.receive": {"importance": 0.1193, "type": "Permission", "description": "Receive Cloud-to-Device messages (push command)"},
    "onshowcustomview setphonenumberrequired": {"importance": 0.1190, "type": "Method", "description": "Trigger phone input prompt (phishing)"},
    "setcompassenabled startscroll": {"importance": 0.1188, "type": "Method", "description": "GPS sensor configuration or screen auto-scroll"},
    "savestate evictioncount": {"importance": 0.1085, "type": "Method", "description": "Track cache evictions during activity restore"},
    "getborderthickness hasstableids": {"importance": 0.1048, "type": "Method", "description": "Check UI borders or database cursor IDs"},
    "ondownloadstart": {"importance": 0.0995, "type": "Method", "description": "Triggers when a file download starts from Webview"},
    "android.permission.send_sms": {"importance": 0.2811, "type": "Permission", "description": "Send background SMS messages (premium rate fraud)"},
    "android.permission.receive_sms": {"importance": 0.2541, "type": "Permission", "description": "Intercept incoming SMS verification codes"},
    "android.permission.read_sms": {"importance": 0.2230, "type": "Permission", "description": "Read private messages from SMS inbox"},
    "android.permission.record_audio": {"importance": 0.1982, "type": "Permission", "description": "Record ambient audio via microphone (spyware)"},
    "android.permission.write_external_storage": {"importance": 0.0821, "type": "Permission", "description": "Write to external storage (write payload/logs)"},
    "android.permission.read_contacts": {"importance": 0.1425, "type": "Permission", "description": "Read device contact address book"},
    "android.permission.bind_accessibility_service": {"importance": 0.3200, "type": "Permission", "description": "Abuse Accessibility Service (click hijacking/keylogging)"}
}

# Global placeholders for loaded models
model = None
vectorizer = None
label_mapping = None

def load_ml_assets():
    global model, vectorizer, label_mapping
    
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            vectorizer = joblib.load(VECTORIZER_PATH)
            
            if os.path.exists(LABEL_MAPPING_PATH):
                with open(LABEL_MAPPING_PATH, 'r') as f:
                    label_mapping = json.load(f)
            else:
                label_mapping = {"label_mapping": {"0": "benign", "1": "malware"}}
                
            print("ML model assets loaded successfully.")
            return True
        except Exception as e:
            print(f"Error loading ML assets: {str(e)}")
            return False
    else:
        print(f"ML assets not found at {MODELS_DIR}. Inference will use fallback.")
        return False

# Initialize on import
load_ml_assets()

def predict_apk_malware(combined_text: str) -> dict:
    global model, vectorizer
    
    # Fallback if model not loaded
    if model is None or vectorizer is None:
        # Simulate predictions based on keywords for fallback safety
        prob = 0.15
        if "send_sms" in combined_text.lower() or "read_sms" in combined_text.lower():
            prob += 0.35
        if "system_alert_window" in combined_text.lower():
            prob += 0.25
        if "c2dm" in combined_text.lower() or "telegram" in combined_text.lower():
            prob += 0.20
        prob = min(prob, 0.99)
        
        pred = 1 if prob >= 0.50 else 0
        confidence = prob if pred == 1 else (1.0 - prob)
    else:
        # Vectorize and Predict
        X_trans = vectorizer.transform([combined_text])
        prob = float(model.predict_proba(X_trans)[0, 1])
        pred = int(model.predict(X_trans)[0])
        confidence = prob if pred == 1 else (1.0 - prob)
        
    # Extract active explanation features present in this APK
    explanations = []
    text_lower = combined_text.lower()
    
    # Match tokens (using standard word boundaries, periods, and slashes)
    for feat, info in GLOBAL_SHAP_FEATURES.items():
        # Safe escape for regex matching
        escaped_feat = re.escape(feat)
        if re.search(r'\b' + escaped_feat + r'\b', text_lower):
            explanations.append({
                "feature": feat,
                "importance": info["importance"],
                "type": info["type"],
                "description": info["description"]
            })
            
    # Sort explanations by importance
    explanations = sorted(explanations, key=lambda x: x["importance"], reverse=True)
    
    return {
        "malware_probability": round(prob, 4),
        "prediction": pred,
        "confidence": round(confidence, 4),
        "verdict": "malware" if pred == 1 else "benign",
        "explanations": explanations[:8]  # Limit to top 8 active factors
    }
