import os
import sys

sys.path.append(r"C:\Users\window 11\.gemini\antigravity\scratch\apk_sentinel_ai\backend")
os.environ["DATABASE_URL"] = "postgresql://neondb_owner:npg_vL9BcFYjC0xu@ep-fancy-mode-aht53rb3-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require"

try:
    from app.database import SessionLocal, APKAnalysis, TrainingSample
    db = SessionLocal()
    apk_count = db.query(APKAnalysis).count()
    ts_count = db.query(TrainingSample).count()
    print(f"[OK] Database connection successful!")
    print(f"APKAnalysis records: {apk_count}")
    print(f"TrainingSample records: {ts_count}")
    db.close()
except Exception as e:
    print(f"[ERROR] Database connection failed: {e}")
