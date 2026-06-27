# APK Sentinel AI — Enterprise SOC Mobile Threat Analysis Platform

**APK Sentinel AI** is an advanced, enterprise-grade Security Operations Center (SOC) dashboard and analysis pipeline for reverse-engineering, detecting, and reporting mobile malware in Android application packages (APKs). 

Combining static decompilation, dynamic execution logging simulation, machine learning classification, SHAP explanations, and a coordinated multi-agent LLM reasoning system, it turns raw binary telemetry into actionable security briefings in under 10 seconds.

---

## 🚀 Key Features

*   **Fast Native Decompilation**: Uses Androguard for direct Python-native extraction of permissions, certificates, native libraries (`.so`), intent filters, and suspicious bytecode API calls.
*   **Weighted ML Classification**: Predicts malware probability using a feature-attribution model, backed by an explainable **SHAP Contribution Model** visualizer.
*   **Incremental Online Learning**: Implements an active `SGDClassifier` that learns continuously from verified files, adapting to new variants in real-time.
*   **Coordinated Multi-Agent GenAI Reporting**: Outlines risks, Att&CK matrices, IOC list extractions, and remediation recommendations using an ensemble of 5 specialized AI sub-agents.
*   **Interactive SOC Terminal**: Features WebSocket live progress streaming, responsive charts, threat history lookup, CSV exports, and customized ReportLab PDF report generation.

---

## 🏗️ System Architecture

```
                                [ Next.js Frontend Dashboard ]
                                       ▲              │
                        (WebSockets)   │              │ (Upload APK / Analyze)
                                       │              ▼
                                [ FastAPI Backend Gateway ]
                                              │
                        ┌─────────────────────┴─────────────────────┐
                        ▼                                           ▼
             [ Static analysis ]                            [ Dynamic Analysis ]
         - Androguard DEX Extraction                     - Heuristic Frida & FS Sandbox
         - Certificate DN Extraction                     - Process Call Logging
         - Hardcoded Secret Matching                     - Network C2 handshakes
                        │                                           │
                        └─────────────────────┬─────────────────────┘
                                              ▼
                                 [ Risk Engine v2 Aggregator ]
                                - SHAP Feature Importance
                                - SGD Online Adaptation Training
                                - Multi-Agent GenAI Briefing (Groq/Gemini)
                                - ReportLab PDF Generator
```

---

## 🛠️ Technology Stack

*   **Frontend**: Next.js, React, Recharts (Responsive charts), Vanilla CSS.
*   **Backend**: FastAPI, SQLAlchemy (SQLite storage), WatchFiles, Uvicorn.
*   **Malware Analysis**: Androguard, Scikit-learn (SGDClassifier, TF-IDF Vectorization).
*   **AI Inference**: Groq API (`llama-3.3-70b-versatile`), Google Gemini SDK (`gemini-2.5-flash` secondary fallback).

---

## 📦 Installation & Setup

### Prerequisites
*   Python 3.10+
*   Node.js 18+

### 1. Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up environment variables (create a `.env` file):
   ```env
   GROQ_API_KEY=your_groq_api_key
   GEMINI_API_KEY=your_gemini_api_key
   ```
5. Run the server:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

### 2. Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd ../frontend
   ```
2. Install npm packages:
   ```bash
   npm install
   ```
3. Run the development server:
   ```bash
   npm run dev
   ```
4. Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🔍 Verification & Demo Path
For testing without uploading live malware, the platform is seeded with 4 threat profiles corresponding to standard malware classes:
1.  **Safe Utility Tool**: Ad-free, system call verified safe.
2.  **Free Wallpapers Pro**: Adware payload displaying high activity frequencies.
3.  **Spy Tracker Agent**: Surveillance toolkit intercepting GPS, camera, and voice.
4.  **Apex Crypto Wallet**: Critical banking trojan utilizing overlays and accessibility keyloggers.
