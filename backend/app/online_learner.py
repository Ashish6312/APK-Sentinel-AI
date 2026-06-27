"""
Online Learning Engine for APK Sentinel AI

Implements incremental/online machine learning that continuously improves
the malware detection model as new APK samples are analyzed.

Architecture:
  1. Every completed analysis saves its feature vector + label to a TrainingSample table
  2. An SGDClassifier (with hinge or log loss) supports partial_fit for true online learning
  3. After each new sample, the model is incrementally updated without full retraining
  4. Periodically, the model checkpoint is saved to disk
  5. A /model/status API exposes learning metrics and training history

This gives the platform a "living" ML model that gets smarter with every APK upload.
"""

import os
import json
import joblib
import threading
import numpy as np
from datetime import datetime
from sklearn.linear_model import SGDClassifier
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.calibration import CalibratedClassifierCV
from collections import deque


# Paths
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
ONLINE_MODEL_PATH = os.path.join(MODELS_DIR, "online_model.pkl")
ONLINE_VECTORIZER_PATH = os.path.join(MODELS_DIR, "online_vectorizer.pkl")
ONLINE_META_PATH = os.path.join(MODELS_DIR, "online_meta.json")

# Thread lock for safe concurrent updates
_lock = threading.Lock()


class OnlineLearner:
    """
    Incremental ML learner that improves with every new APK sample.
    
    Uses:
      - HashingVectorizer: Stateless vectorizer that doesn't need to be refit (ideal for online learning)
      - SGDClassifier: Supports partial_fit for true incremental learning
    """

    def __init__(self):
        self.vectorizer = HashingVectorizer(
            n_features=2**14,  # 16384 feature dimensions
            alternate_sign=False,
            ngram_range=(1, 2),
            lowercase=True,
            stop_words=None
        )
        
        self.classifier = SGDClassifier(
            loss="modified_huber",  # Produces probability estimates like logistic regression
            penalty="l2",
            alpha=1e-4,
            max_iter=1,
            tol=None,
            random_state=42,
            warm_start=True
        )
        
        # Training metadata
        self.meta = {
            "total_samples_learned": 0,
            "malware_samples": 0,
            "benign_samples": 0,
            "last_trained_at": None,
            "model_version": 0,
            "accuracy_history": [],  # Rolling accuracy on recent predictions
            "created_at": datetime.utcnow().isoformat()
        }
        
        self._is_fitted = False
        self._recent_predictions = deque(maxlen=50)  # Track last 50 for rolling accuracy
        
        # Try to load existing online model
        self._load_checkpoint()

    def _load_checkpoint(self):
        """Load a previously saved online model checkpoint if it exists."""
        try:
            if os.path.exists(ONLINE_MODEL_PATH) and os.path.exists(ONLINE_META_PATH):
                self.classifier = joblib.load(ONLINE_MODEL_PATH)
                with open(ONLINE_META_PATH, "r") as f:
                    self.meta = json.load(f)
                self._is_fitted = self.meta.get("total_samples_learned", 0) > 0
                print(f"[ONLINE_LEARNER] Loaded checkpoint: v{self.meta['model_version']}, "
                      f"{self.meta['total_samples_learned']} samples learned.")
        except Exception as e:
            print(f"[ONLINE_LEARNER] No checkpoint found, starting fresh: {e}")

    def _save_checkpoint(self):
        """Persist the current model state to disk."""
        try:
            os.makedirs(MODELS_DIR, exist_ok=True)
            joblib.dump(self.classifier, ONLINE_MODEL_PATH)
            with open(ONLINE_META_PATH, "w") as f:
                json.dump(self.meta, f, indent=2)
        except Exception as e:
            print(f"[ONLINE_LEARNER] Checkpoint save failed: {e}")

    def build_feature_text(self, features: dict) -> str:
        """
        Convert extracted APK features into a single text string for vectorization.
        This mirrors the feature construction in predict_apk_malware().
        """
        components = []
        
        # Permissions (most important signal)
        permissions = features.get("permissions", [])
        components.extend(permissions)
        
        # Activities, Services, Receivers
        components.extend(features.get("activities", []))
        components.extend(features.get("services", []))
        components.extend(features.get("receivers", []))
        
        # Methods (API calls)
        components.extend(features.get("methods", []))
        
        # Suspicious APIs (weighted by repeating)
        suspicious = features.get("suspicious_apis", [])
        components.extend(suspicious * 3)  # Weight suspicious APIs higher
        
        # Network indicators
        components.extend(features.get("urls", []))
        components.extend(features.get("domains", []))
        
        # Intent filters
        components.extend(features.get("intent_filters", []))
        
        return " ".join(components)

    def derive_label(self, risk_score: float, verdict: str, malware_probability: float) -> int:
        """
        Derive a training label from the analysis results.
        Uses a consensus of multiple signals to produce a reliable label.
        
        Returns: 1 for malware, 0 for benign
        """
        votes = 0
        
        # Risk score vote
        if risk_score >= 60.0:
            votes += 1
        
        # Verdict vote
        if verdict in ("High Risk", "Critical", "malware"):
            votes += 1
        
        # ML probability vote
        if malware_probability >= 0.5:
            votes += 1
        
        # Majority vote (2 out of 3 signals agree)
        return 1 if votes >= 2 else 0

    def learn(self, feature_text: str, label: int) -> dict:
        """
        Perform one step of online/incremental learning.
        
        Args:
            feature_text: The combined feature text string
            label: 0 = benign, 1 = malware
            
        Returns:
            dict with learning result metadata
        """
        with _lock:
            try:
                # Vectorize the feature text
                X = self.vectorizer.transform([feature_text])
                y = np.array([label])
                
                # Incremental fit
                if not self._is_fitted:
                    # First call must specify all classes
                    self.classifier.partial_fit(X, y, classes=np.array([0, 1]))
                    self._is_fitted = True
                else:
                    self.classifier.partial_fit(X, y)
                
                # Update metadata
                self.meta["total_samples_learned"] += 1
                if label == 1:
                    self.meta["malware_samples"] += 1
                else:
                    self.meta["benign_samples"] += 1
                self.meta["last_trained_at"] = datetime.utcnow().isoformat()
                self.meta["model_version"] += 1
                
                # Save checkpoint every sample for immediate persistence
                self._save_checkpoint()
                
                result = {
                    "status": "learned",
                    "label": "malware" if label == 1 else "benign",
                    "model_version": self.meta["model_version"],
                    "total_samples": self.meta["total_samples_learned"],
                    "timestamp": self.meta["last_trained_at"]
                }
                
                print(f"[ONLINE_LEARNER] Learned sample #{self.meta['total_samples_learned']}: "
                      f"{'malware' if label == 1 else 'benign'} (v{self.meta['model_version']})")
                
                return result
                
            except Exception as e:
                print(f"[ONLINE_LEARNER] Learning failed: {e}")
                return {"status": "error", "error": str(e)}

    def predict(self, feature_text: str) -> dict:
        """
        Make a prediction using the online model.
        Falls back to heuristic if model isn't trained yet.
        """
        if not self._is_fitted:
            return {
                "online_prediction": None,
                "online_confidence": 0.0,
                "model_version": 0,
                "status": "not_trained"
            }
        
        with _lock:
            try:
                X = self.vectorizer.transform([feature_text])
                prediction = int(self.classifier.predict(X)[0])
                
                # SGDClassifier with modified_huber loss supports predict_proba via decision_function
                try:
                    probas = self.classifier.predict_proba(X)[0]
                    confidence = float(max(probas))
                    malware_prob = float(probas[1]) if len(probas) > 1 else float(probas[0])
                except Exception:
                    # Fallback to decision function
                    decision = float(self.classifier.decision_function(X)[0])
                    confidence = min(abs(decision), 1.0)
                    malware_prob = 1.0 / (1.0 + np.exp(-decision))
                
                return {
                    "online_prediction": "malware" if prediction == 1 else "benign",
                    "online_confidence": round(confidence, 4),
                    "online_malware_probability": round(malware_prob, 4),
                    "model_version": self.meta["model_version"],
                    "total_training_samples": self.meta["total_samples_learned"],
                    "status": "active"
                }
            except Exception as e:
                return {
                    "online_prediction": None,
                    "online_confidence": 0.0,
                    "model_version": self.meta["model_version"],
                    "status": f"error: {str(e)}"
                }

    def get_status(self) -> dict:
        """Return the current status and metrics of the online learning model."""
        return {
            "is_active": self._is_fitted,
            "model_version": self.meta["model_version"],
            "total_samples_learned": self.meta["total_samples_learned"],
            "malware_samples": self.meta["malware_samples"],
            "benign_samples": self.meta["benign_samples"],
            "last_trained_at": self.meta["last_trained_at"],
            "created_at": self.meta["created_at"],
            "class_balance": {
                "malware_ratio": round(self.meta["malware_samples"] / max(1, self.meta["total_samples_learned"]), 3),
                "benign_ratio": round(self.meta["benign_samples"] / max(1, self.meta["total_samples_learned"]), 3)
            },
            "checkpoint_path": ONLINE_MODEL_PATH if os.path.exists(ONLINE_MODEL_PATH) else None
        }

    def force_save(self):
        """Force save the current model checkpoint."""
        with _lock:
            self._save_checkpoint()
            return {"status": "saved", "model_version": self.meta["model_version"]}
