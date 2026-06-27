# Task List - APK Sentinel AI Platform (National Cybersecurity Hackathon 2026 Update)

## Backend Update
- [x] Configure SQLite and PostgreSQL schemas for `family_similarity` table
- [x] Integrate `FamilyClassifier` rules-based strain attribution engine in `backend/app/family_classifier.py`
- [x] Update `APKAnalyzer` in `backend/app/analyzer.py` to parse intent filters, certificate metadata (subject, issuer, serial, sig_algo), version names, code tags, and compile attack chains
- [x] Update Groq AI Analyst in `backend/app/ai_analyst.py` supporting `llama-3.3-70b-versatile` and `deepseek-r1-distill-llama-70b` fallback
- [x] Modify PDF generator in `backend/app/pdf_generator.py` supporting executive SOC summary banners, score breakdown tables, malware family attribution tables, and attack chains
- [x] Register new route `GET /family/{id}` in `backend/app/main.py`
- [x] Expand dashboard metrics to calculate family attribution metrics and top families in `backend/app/main.py`
- [x] Verify backend imports diagnostic passing successfully

## Frontend Update
- [x] Re-design `frontend/src/app/page.tsx` client component with dark mode glassmorphism
- [x] Add Top Malware Families stat cards and family distribution charts (Recharts) on the main SOC dashboard
- [x] Add Executive SOC Summary and composite Score Breakdown meters on the Analysis overview sub-tab
- [x] Render horizontal, step-based Attack Chain flowchart visual
- [x] Implement Family Attribution similarity charts and detail tables
- [x] Integrate client with `/family/{id}` API route and fallbacks
- [x] Verify Next.js frontend builds and compiles successfully
