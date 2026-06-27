import os
import sys

print("Configuring sys.path...")
sys.path.append(r"C:\Users\window 11\.gemini\antigravity\scratch\apk_sentinel_ai\backend")

print("Setting DATABASE_URL...")
os.environ["DATABASE_URL"] = "postgresql://neondb_owner:npg_vL9BcFYjC0xu@ep-fancy-mode-aht53rb3-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require"

print("Importing database engines...")
from app.database import engine, init_db, SessionLocal, APKAnalysis, TrainingSample
from app.seeding import seed_db_if_empty

print("Initializing DB...")
init_db()

print("Creating session...")
db = SessionLocal()

print("Querying APKAnalysis count...")
apk_count = db.query(APKAnalysis).count()
print(f"APKAnalysis count: {apk_count}")

print("Querying TrainingSample count...")
ts_count = db.query(TrainingSample).count()
print(f"TrainingSample count: {ts_count}")

if apk_count == 0:
    print("Seeding database...")
    seed_db_if_empty(db)
    print("Seeding complete.")
else:
    print("Database already seeded.")

db.close()
print("Success!")
