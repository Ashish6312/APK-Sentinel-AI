print("Testing backend import pipeline...")
try:
    import fastapi
    print("[OK] fastapi imported")
    import sqlalchemy
    print("[OK] sqlalchemy imported")
    import joblib
    print("[OK] joblib imported")
    import androguard
    print("[OK] androguard imported")
    import reportlab
    print("[OK] reportlab imported")
    import xgboost
    print("[OK] xgboost imported")
    import shap
    print("[OK] shap imported")
    
    # Import app components
    from app.database import Base, init_db
    print("[OK] app.database imported")
    from app.analyzer import APKAnalyzer
    print("[OK] app.analyzer imported")
    from app.threat_intel import ThreatIntelEngine
    print("[OK] app.threat_intel imported")
    from app.mitre_mapper import MITREMapper
    print("[OK] app.mitre_mapper imported")
    from app.ml_model import predict_apk_malware
    print("[OK] app.ml_model imported")
    from app.risk_engine import RiskEngine
    print("[OK] app.risk_engine imported")
    from app.ai_analyst import GeminiAnalyst
    print("[OK] app.ai_analyst imported")
    from app.pdf_generator import PDFReportGenerator
    print("[OK] app.pdf_generator imported")
    from app.main import app
    print("[OK] app.main imported")
    
    print("\nSUCCESS: All backend modules and dependencies imported successfully!")
except Exception as e:
    import traceback
    print("\nERROR: Verification failed:")
    traceback.print_exc()
