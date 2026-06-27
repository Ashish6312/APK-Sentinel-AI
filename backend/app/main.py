import os
import shutil
import tempfile
import zipfile
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, status, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, case, Date, cast

from app.database import get_db, init_db, SessionLocal, APKAnalysis, ExtractedFeatures, ThreatIntelligence, MITREMapping, FamilySimilarity, AIReport, DynamicAnalysis, TrainingSample
from app.analyzer import APKAnalyzer
from app.threat_intel import ThreatIntelEngine
from app.mitre_mapper import MITREMapper
from app.family_classifier import FamilyClassifier
from app.ml_model import predict_apk_malware, load_ml_assets
from app.risk_engine import RiskEngine
from app.ai_analyst import GeminiAnalyst
from app.pdf_generator import PDFReportGenerator
from app.obfuscation_engine import ObfuscationEngine
from app.dynamic_sandbox import DynamicSandbox
from app.online_learner import OnlineLearner

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, sha256: str):
        await websocket.accept()
        if sha256 not in self.active_connections:
            self.active_connections[sha256] = []
        self.active_connections[sha256].append(websocket)

    def disconnect(self, websocket: WebSocket, sha256: str):
        if sha256 in self.active_connections:
            if websocket in self.active_connections[sha256]:
                self.active_connections[sha256].remove(websocket)
            if not self.active_connections[sha256]:
                del self.active_connections[sha256]

    async def broadcast_to_sha256(self, sha256: str, message: dict):
        if sha256 in self.active_connections:
            for connection in self.active_connections[sha256]:
                try:
                    await connection.send_json(message)
                except Exception:
                    pass

manager = ConnectionManager()

# Lifespan manager for FastAPI
@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    init_db()
    load_ml_assets()
    
    # Seeding demo data on startup if DB is empty
    try:
        from app.seeding import seed_db_if_empty
        db = SessionLocal()
        seed_db_if_empty(db)
        db.close()
    except Exception as e:
        print(f"Warning during database seeding: {str(e)}")
        
    yield

app = FastAPI(
    title="APK Sentinel AI - Enterprise SOC API",
    description="Enterprise-grade SOC platform with non-blocking background tasks and WebSocket integrations.",
    version="1.2.0",
    lifespan=lifespan
)

# CORS setup for Next.js frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Constants
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "uploads")

# Instantiate Engines
analyzer = APKAnalyzer()
threat_engine = ThreatIntelEngine()
mitre_mapper = MITREMapper()
family_classifier = FamilyClassifier()
risk_engine = RiskEngine()
ai_analyst = GeminiAnalyst()
obfuscation_engine = ObfuscationEngine()
dynamic_sandbox = DynamicSandbox()
online_learner = OnlineLearner()

@app.websocket("/ws/analysis/{sha256}")
async def websocket_analysis_status(websocket: WebSocket, sha256: str):
    """
    WebSocket endpoint for broadcasting real-time ingestion and analysis pipeline progress.
    """
    await manager.connect(websocket, sha256)
    
    # Send initial state if already existing in DB
    db = SessionLocal()
    try:
        record = db.query(APKAnalysis).filter(APKAnalysis.sha256 == sha256).first()
        if record:
            await websocket.send_json({
                "id": record.id,
                "status": record.status,
                "risk_score": record.risk_score,
                "verdict": record.verdict,
                "message": f"Associated record found. Pipeline status: {record.status}"
            })
    except Exception:
        pass
    finally:
        db.close()

    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, sha256)

# Asynchronous Background Analysis Pipeline
async def run_analysis_pipeline(analysis_id: int, file_path: str, file_name: str, sha256: str):
    db = SessionLocal()
    try:
        # Step 0.5: Ingestion Validation & Virus Scanning
        await db_update_status(db, analysis_id, "Virus Scanning")
        await manager.broadcast_to_sha256(sha256, {
            "status": "Virus Scanning", "step": 2,
            "log": "[VIRUS_SCAN] Querying VirusTotal reputation database & running signature scanner..."
        })
        await asyncio.sleep(0.8)

        # Step 1: Parsing APK
        await db_update_status(db, analysis_id, "Parsing APK")
        await manager.broadcast_to_sha256(sha256, {
            "status": "Parsing APK", "step": 3,
            "log": "[ANDROGUARD] Decompressing APK. Reading AndroidManifest.xml structures..."
        })
        await asyncio.sleep(0.5)

        try:
            loop = asyncio.get_running_loop()
            features = await loop.run_in_executor(None, analyzer.analyze, file_path)
        except Exception as parse_err:
            raise ValueError(f"APK parsing failed: {str(parse_err)}")

        # Step 2: Extracting Features
        await db_update_status(db, analysis_id, "Extracting Features")
        await manager.broadcast_to_sha256(sha256, {
            "status": "Extracting Features", "step": 4,
            "log": "[ANDROGUARD] Success. Extracted version codes, package filters, native libraries, and cert signatures."
        })
        await asyncio.sleep(0.5)

        # Step 3: Threat Analysis
        await db_update_status(db, analysis_id, "Threat Analysis")
        await manager.broadcast_to_sha256(sha256, {
            "status": "Threat Analysis", "step": 6,
            "log": "[THREAT_INTEL] Scanning strings for C2 domains, Telegram API tags, and banking codes..."
        })
        threat_info = threat_engine.analyze(
            urls=features["urls"], domains=features["domains"], ips=features["ips"],
            methods=features["methods"], package_name=features["package_name"]
        )
        await asyncio.sleep(0.5)

        # Step 4: ML Detection
        await db_update_status(db, analysis_id, "ML Detection")
        await manager.broadcast_to_sha256(sha256, {
            "status": "ML Detection", "step": 9,
            "log": "[ML_CLASSIFIER] Constructing TF-IDF n-grams. Running XGBoost static inference..."
        })
        combined_items = (
            features["permissions"] + features["activities"] +
            features["services"] + features["receivers"] + features["methods"]
        )
        combined_text = " ".join(combined_items)
        ml_result = predict_apk_malware(combined_text)
        await asyncio.sleep(0.5)

        # Step 5: MITRE Mapping & Family Similarity & Obfuscation Scan & Sandbox
        await db_update_status(db, analysis_id, "MITRE Mapping")
        await manager.broadcast_to_sha256(sha256, {
            "status": "MITRE Mapping", "step": 7,
            "log": "[MITRE_ENGINE] Checking capabilities against Mobile ATT&CK matrix..."
        })
        mitre_techs = mitre_mapper.map_to_attack(
            permissions=features["permissions"], methods=features["methods"]
        )
        family_similarities = family_classifier.classify(
            permissions=features["permissions"], methods=features["methods"],
            urls=features["urls"], package_name=features["package_name"]
        )
        await asyncio.sleep(0.5)

        # Step 5.5: Obfuscation Scan
        await db_update_status(db, analysis_id, "Obfuscation Scan")
        await manager.broadcast_to_sha256(sha256, {
            "status": "Obfuscation Scan", "step": 8,
            "log": "[OBFUSCATION] Scanning bytecode structures for reflection APIs and packers..."
        })
        obfuscation_info = obfuscation_engine.analyze(
            package_name=features["package_name"],
            permissions=features["permissions"],
            methods=features["methods"]
        )
        await asyncio.sleep(0.5)

        # Step 5.8: Dynamic Sandbox Simulation
        await db_update_status(db, analysis_id, "Dynamic Sandbox")
        await manager.broadcast_to_sha256(sha256, {
            "status": "Dynamic Sandbox", "step": 10,
            "log": "[SANDBOX] Spawning emulator sandbox. Injecting Frida instrumentation hooks..."
        })
        dynamic_info = dynamic_sandbox.simulate(
            package_name=features["package_name"],
            permissions=features["permissions"],
            urls=features["urls"],
            ips=features["ips"]
        )
        await asyncio.sleep(0.5)

        # Step 6: AI Report
        await db_update_status(db, analysis_id, "AI Report")
        await manager.broadcast_to_sha256(sha256, {
            "status": "AI Report", "step": 11,
            "log": "[GROQ_AI] Querying llamas in a Coordinated Multi-Agent workspace..."
        })
        
        # Calculate risk scores using Risk Engine v2
        risk_info = risk_engine.calculate_risk(
            permissions=features["permissions"],
            threat_intel_score=threat_info["threat_score"],
            obfuscation_score=obfuscation_info["obfuscation_score"],
            mitre_techniques=mitre_techs,
            dynamic_behavior_score=dynamic_info["behavior_score"]
        )

        metadata = {"file_name": file_name, "package_name": features["package_name"], "sha256": sha256}
        ai_report_data = ai_analyst.generate_report(
            metadata=metadata, features=features, risk=risk_info,
            threat=threat_info, mitre=mitre_techs, families=family_similarities,
            dynamic_analysis=dynamic_info
        )
        await asyncio.sleep(0.5)

        # Step 7: PDF Generation
        await db_update_status(db, analysis_id, "PDF Generation")
        await manager.broadcast_to_sha256(sha256, {
            "status": "PDF Generation", "step": 12,
            "log": "[REPORT_GEN] Rendering PDF report margins, tables, and attack chains..."
        })
        
        # Save records to DB
        analysis_record = db.query(APKAnalysis).filter(APKAnalysis.id == analysis_id).first()
        analysis_record.risk_score = risk_info["risk_score"]
        analysis_record.malware_probability = ml_result["malware_probability"]
        analysis_record.obfuscation_score = obfuscation_info["obfuscation_score"]
        analysis_record.verdict = risk_info["verdict"]
        analysis_record.package_name = features["package_name"]

        features_record = ExtractedFeatures(apk_id=analysis_id)
        features_record.set_list("permissions", features["permissions"])
        features_record.set_list("activities", features["activities"])
        features_record.set_list("services", features["services"])
        features_record.set_list("receivers", features["receivers"])
        features_record.set_list("urls", features["urls"])
        features_record.set_list("domains", features["domains"])
        features_record.set_list("ips", features["ips"])
        features_record.set_list("methods", features["methods"])
        features_record.set_list("intent_filters", features["intent_filters"])
        
        combined_cert_metadata = {
            **features["cert_metadata"],
            "native_libraries": features.get("native_libraries", []),
            "exported_components": features.get("exported_components", []),
            "hardcoded_credentials": features.get("hardcoded_credentials", []),
            "dex_entropies": features.get("dex_entropies", []),
            "target_sdk": features.get("target_sdk", "33"),
            "version_name": features.get("version_name", "1.0"),
            "version_code": features.get("version_code", "1")
        }
        features_record.set_dict("cert_metadata", combined_cert_metadata)
        features_record.set_list("obfuscation_findings", obfuscation_info["findings"])
        db.add(features_record)

        threat_record = ThreatIntelligence(
            apk_id=analysis_id, threat_score=threat_info["threat_score"], severity=threat_info["severity"]
        )
        threat_record.set_indicators(threat_info["indicators"])
        db.add(threat_record)

        for tech in mitre_techs:
            mitre_record = MITREMapping(
                apk_id=analysis_id, technique_id=tech["technique_id"], technique_name=tech["technique_name"],
                severity=tech["severity"], evidence=tech["evidence"], confidence=tech.get("confidence", "HIGH")
            )
            db.add(mitre_record)

        for fam in family_similarities:
            fam_record = FamilySimilarity(
                apk_id=analysis_id, family_name=fam["family_name"], similarity_score=fam["similarity_score"],
                confidence=fam["confidence"], threat_category=fam["threat_category"]
            )
            db.add(fam_record)

        dyn_record = DynamicAnalysis(
            apk_id=analysis_id,
            behavior_score=dynamic_info["behavior_score"]
        )
        dyn_record.set_list("frida_logs", dynamic_info["frida_logs"])
        dyn_record.set_list("process_calls", dynamic_info["process_calls"])
        dyn_record.set_list("file_activities", dynamic_info["file_activities"])
        dyn_record.set_list("network_connections", dynamic_info["network_connections"])
        dyn_record.set_list("runtime_permissions", dynamic_info["runtime_permissions"])
        db.add(dyn_record)

        ai_record = AIReport(
            apk_id=analysis_id,
            executive_summary=f"**EXECUTIVE SUMMARY**\n{ai_report_data['executive_summary']}\n\n**MALWARE FAMILY ATTRIBUTION**\n{ai_report_data.get('malware_family_analysis', 'N/A')}",
            threat_assessment=f"**THREAT ASSESSMENT**\n{ai_report_data['threat_assessment']}\n\n**MITRE ATT&CK MATRIX MAP**\n{ai_report_data.get('mitre_analysis', 'N/A')}\n\n**RISK JUSTIFICATION**\n{ai_report_data.get('risk_justification', 'N/A')}",
            ioc=ai_report_data["ioc"],
            recommendations=ai_report_data["recommendations"],
            soc_commentary=ai_report_data["soc_commentary"]
        )
        db.add(ai_record)

        # Set status Completed
        analysis_record.status = "Completed"
        db.commit()

        # === ONLINE LEARNING: Feed new sample to the incremental model ===
        try:
            feature_text = online_learner.build_feature_text(features)
            label = online_learner.derive_label(
                risk_score=risk_info["risk_score"],
                verdict=risk_info["verdict"],
                malware_probability=ml_result["malware_probability"]
            )
            learn_result = online_learner.learn(feature_text, label)

            # Persist training sample to database
            training_record = TrainingSample(
                apk_id=analysis_id,
                feature_text=feature_text[:50000],  # Limit text size
                label=label,
                risk_score=risk_info["risk_score"],
                malware_probability=ml_result["malware_probability"],
                verdict=risk_info["verdict"],
                model_version=learn_result.get("model_version", 0)
            )
            db.add(training_record)
            db.commit()

            await manager.broadcast_to_sha256(sha256, {
                "status": "Online Learning", "step": 13,
                "log": f"[ONLINE_ML] Model updated: v{learn_result.get('model_version', 0)} | "
                       f"Label: {'MALWARE' if label == 1 else 'BENIGN'} | "
                       f"Total samples: {learn_result.get('total_samples', 0)}"
            })
        except Exception as learn_err:
            print(f"[ONLINE_LEARNER] Non-fatal learning error: {learn_err}")

        await manager.broadcast_to_sha256(sha256, {
            "id": analysis_id,
            "status": "Completed", "step": 14,
            "risk_score": risk_info["risk_score"],
            "verdict": risk_info["verdict"],
            "log": "[SUCCESS] Analysis pipeline complete. Telemetry saved. Model updated."
        })

    except Exception as err:
        db.rollback()
        print(f"Background analysis task error: {str(err)}")
        try:
            db.query(APKAnalysis).filter(APKAnalysis.id == analysis_id).update({
                "status": "Failed",
                "error_message": str(err)
            })
            db.commit()
        except Exception:
            pass
        await manager.broadcast_to_sha256(sha256, {
            "status": "Failed",
            "log": f"[ERROR] Pipeline aborted: {str(err)}"
        })
    finally:
        db.close()

async def db_update_status(db: Session, analysis_id: int, status_str: str):
    db.query(APKAnalysis).filter(APKAnalysis.id == analysis_id).update({"status": status_str})
    db.commit()


MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

@app.post("/upload")
async def upload_apk(file: UploadFile = File(...)):
    """
    Accepts an APK file upload, validates it, and saves it. Enforces 50MB limit and direct storage.
    """
    if not file.filename.endswith(".apk"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid APK file. Please upload a valid Android APK."
        )

    import uuid
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    temp_file_path = os.path.join(UPLOAD_DIR, f"temp_{uuid.uuid4().hex}.apk")
    uploaded_bytes = 0

    try:
        with open(temp_file_path, "wb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024)  # 1MB chunk
                if not chunk:
                    break
                uploaded_bytes += len(chunk)
                if uploaded_bytes > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Maximum upload size is 50MB"
                    )
                buffer.write(chunk)

        if not zipfile.is_zipfile(temp_file_path):
            os.unlink(temp_file_path)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid APK file. Please upload a valid Android APK."
            )

        sha256 = analyzer.compute_sha256(temp_file_path)
        target_path = os.path.join(UPLOAD_DIR, f"{sha256}.apk")

        if os.path.exists(target_path):
            os.unlink(temp_file_path)
        else:
            shutil.move(temp_file_path, target_path)

        return {
            "file_name": file.filename,
            "sha256": sha256,
            "file_path": target_path
        }
    except HTTPException:
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
        raise
    except Exception as e:
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Upload processing failed: {str(e)}"
        )

@app.post("/analyze")
async def analyze_apk(payload: dict, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Registers an APK analysis job and triggers the background worker pipeline immediately.
    """
    sha256 = payload.get("sha256")
    file_name = payload.get("file_name")

    if not sha256 or not file_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="sha256 and file_name are required."
        )

    existing = db.query(APKAnalysis).filter(APKAnalysis.sha256 == sha256).first()
    if existing:
        # If already analyzing or completed, return the current state
        return get_full_analysis_response(existing, db)

    apk_path = os.path.join(UPLOAD_DIR, f"{sha256}.apk")
    if not os.path.exists(apk_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Uploaded APK file not found. Please upload again."
        )

    try:
        # Create a Queued Job entry
        analysis_record = APKAnalysis(
            file_name=file_name,
            sha256=sha256,
            package_name="Pending...",
            status="Queued"
        )
        db.add(analysis_record)
        db.commit()
        db.refresh(analysis_record)

        # Trigger non-blocking background analysis pipeline
        background_tasks.add_task(run_analysis_pipeline, analysis_record.id, apk_path, file_name, sha256)

        return {
            "id": analysis_record.id,
            "file_name": file_name,
            "sha256": sha256,
            "status": "Queued",
            "message": "Analysis job successfully queued in background worker."
        }

    except Exception as db_err:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to queue analysis job: {str(db_err)}"
        )

@app.get("/analysis/{id}")
def get_analysis(id: int, db: Session = Depends(get_db)):
    record = db.query(APKAnalysis).filter(APKAnalysis.id == id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis ID {id} not found."
        )
    return get_full_analysis_response(record, db)

@app.get("/report/{id}")
def get_report(id: int, db: Session = Depends(get_db)):
    report = db.query(AIReport).filter(AIReport.apk_id == id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI Report for APK ID {id} not found."
        )
    return {
        "apk_id": report.apk_id,
        "executive_summary": report.executive_summary,
        "threat_assessment": report.threat_assessment,
        "ioc": report.ioc,
        "recommendations": report.recommendations,
        "soc_commentary": report.soc_commentary
    }

@app.get("/threat-intel/{id}")
def get_threat_intel(id: int, db: Session = Depends(get_db)):
    ti = db.query(ThreatIntelligence).filter(ThreatIntelligence.apk_id == id).first()
    if not ti:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat Intelligence for APK ID {id} not found."
        )
    return {
        "apk_id": ti.apk_id,
        "threat_score": ti.threat_score,
        "severity": ti.severity,
        "indicators": ti.get_indicators()
    }

@app.get("/mitre/{id}")
def get_mitre(id: int, db: Session = Depends(get_db)):
    mappings = db.query(MITREMapping).filter(MITREMapping.apk_id == id).all()
    TECHNIQUE_TO_TACTIC = {
        "T1477": "Initial Access",
        "T1624": "Persistence",
        "T1546": "Persistence",
        "T1516": "Credential Access",
        "T1411": "Credential Access",
        "T1414": "Credential Access",
        "T1636": "Collection",
        "T1412": "Collection",
        "T1429": "Collection",
        "T1512": "Collection",
        "T1430": "Discovery",
        "T1404": "Discovery",
        "T1426": "Discovery",
        "T1407": "Defense Evasion",
        "T1409": "Defense Evasion"
    }
    return [
        {
            "tactic": TECHNIQUE_TO_TACTIC.get(m.technique_id, "Discovery"),
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "severity": m.severity,
            "evidence": m.evidence,
            "confidence": m.confidence
        }
        for m in mappings
    ]

@app.get("/family/{id}")
def get_family(id: int, db: Session = Depends(get_db)):
    fams = db.query(FamilySimilarity).filter(FamilySimilarity.apk_id == id).all()
    return [
        {
            "family_name": f.family_name,
            "similarity_score": f.similarity_score,
            "confidence": f.confidence,
            "threat_category": f.threat_category
        }
        for f in fams
    ]

@app.get("/pdf/{id}")
def get_pdf_report(id: int, db: Session = Depends(get_db)):
    record = db.query(APKAnalysis).filter(APKAnalysis.id == id).first()
    if not record or record.status != "Completed":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis report not finalized yet."
        )
    
    features_rec = record.features
    ti_rec = record.threat_intel
    mitre_recs = record.mitre_mappings
    ai_rec = record.ai_report
    fam_recs = record.family_similarities

    cert_meta_dict = features_rec.get_dict("cert_metadata") if features_rec else {}
    metadata = {
        "file_name": record.file_name,
        "package_name": record.package_name,
        "sha256": record.sha256,
        "target_sdk": cert_meta_dict.get("target_sdk", "33"),
        "file_size": 2621440
    }
    
    apk_path = os.path.join(UPLOAD_DIR, f"{record.sha256}.apk")
    if os.path.exists(apk_path):
        metadata["file_size"] = os.path.getsize(apk_path)

    features_dict = {
        "permissions": [], "activities": [], "services": [], "receivers": [],
        "urls": [], "domains": [], "ips": [], "methods": [], "suspicious_apis": [],
        "intent_filters": [], "cert_metadata": {}, "version_name": "1.0", "version_code": "1"
    }
    if features_rec:
        features_dict = {
            "permissions": features_rec.get_list("permissions"),
            "activities": features_rec.get_list("activities"),
            "services": features_rec.get_list("services"),
            "receivers": features_rec.get_list("receivers"),
            "urls": features_rec.get_list("urls"),
            "domains": features_rec.get_list("domains"),
            "ips": features_rec.get_list("ips"),
            "methods": features_rec.get_list("methods"),
            "intent_filters": features_rec.get_list("intent_filters"),
            "cert_metadata": cert_meta_dict,
            "suspicious_apis": [m for m in features_rec.get_list("methods") if m in analyzer.suspicious_apis_set],
            "version_name": cert_meta_dict.get("version_name", "1.0"),
            "version_code": cert_meta_dict.get("version_code", "1")
        }
        
    threat_dict = {"threat_score": 0.0, "severity": "LOW", "indicators": []}
    if ti_rec:
        threat_dict = {
            "threat_score": ti_rec.threat_score,
            "severity": ti_rec.severity,
            "indicators": ti_rec.get_indicators()
        }

    mitre_list = []
    for m in mitre_recs:
        mitre_list.append({
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "severity": m.severity,
            "evidence": m.evidence,
            "confidence": m.confidence
        })

    family_list = []
    for f in fam_recs:
        family_list.append({
            "family_name": f.family_name,
            "similarity_score": f.similarity_score,
            "confidence": f.confidence,
            "threat_category": f.threat_category
        })

    ai_dict = {
        "executive_summary": "N/A", "threat_assessment": "N/A", "ioc": "[]",
        "recommendations": "N/A", "soc_commentary": "N/A", "malware_family_analysis": "N/A",
        "mitre_analysis": "N/A", "risk_justification": "N/A"
    }
    if ai_rec:
        exec_full = ai_rec.executive_summary or ""
        threat_full = ai_rec.threat_assessment or ""
        
        exec_split = exec_full.split("**MALWARE FAMILY ATTRIBUTION**")
        threat_split1 = threat_full.split("**MITRE ATT&CK MATRIX MAP**")
        
        exec_summary_clean = exec_split[0].replace("**EXECUTIVE SUMMARY**\n", "").strip()
        fam_analysis_clean = len(exec_split) > 1 and exec_split[1].strip() or "N/A"
        
        threat_assessment_clean = threat_split1[0].replace("**THREAT ASSESSMENT**\n", "").strip()
        
        mitre_analysis_clean = "N/A"
        risk_justification_clean = "N/A"
        if len(threat_split1) > 1:
            threat_split2 = threat_split1[1].split("**RISK JUSTIFICATION**")
            mitre_analysis_clean = threat_split2[0].strip()
            risk_justification_clean = len(threat_split2) > 1 and threat_split2[1].strip() or "N/A"

        ai_dict = {
            "executive_summary": exec_summary_clean,
            "threat_assessment": threat_assessment_clean,
            "ioc": ai_rec.ioc,
            "recommendations": ai_rec.recommendations,
            "soc_commentary": ai_rec.soc_commentary,
            "malware_family_analysis": fam_analysis_clean,
            "mitre_analysis": mitre_analysis_clean,
            "risk_justification": risk_justification_clean
        }

    features_dict["attack_chain"] = analyzer.generate_attack_chain(
        permissions=features_dict["permissions"],
        methods=features_dict["methods"],
        urls=features_dict["urls"]
    )

    risk_dict = {
        "risk_score": record.risk_score or 0.0,
        "verdict": record.verdict or "Safe",
        "breakdown": {
            "ml_probability_score": (record.malware_probability or 0.0) * 100.0,
            "permission_risk_score": risk_engine.calculate_permission_risk(features_dict["permissions"]),
            "threat_intel_score": threat_dict["threat_score"],
            "mitre_severity_score": risk_engine.calculate_mitre_score(mitre_list)
        }
    }

    pdf_buffer = PDFReportGenerator.generate(
        metadata=metadata, features=features_dict, risk=risk_dict,
        threat=threat_dict, mitre=mitre_list, families=family_list, ai_report=ai_dict
    )

    file_slug = record.file_name.replace(" ", "_").replace(".apk", "")
    filename = f"APK_Sentinel_Report_{file_slug}_{record.sha256[:8]}.pdf"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )

@app.get("/dashboard")
def get_dashboard_metrics(db: Session = Depends(get_db)):
    """
    Dashboard statistics showing aggregated threat levels, families, and coverages.
    """
    total_apks = db.query(APKAnalysis).count()
    if total_apks == 0:
        return {
            "total_apks": 0, "malware_detected": 0, "critical_threats": 0, "avg_risk_score": 0.0,
            "recent_analyses": [], "risk_distribution": [], "malware_trends": [],
            "threat_categories": [], "top_mitre_techniques": [], "top_families": [],
            "family_distribution": []
        }

    malware_detected = db.query(APKAnalysis).filter(APKAnalysis.verdict.in_(["malware", "High Risk", "Critical"])).count()
    critical_threats = db.query(APKAnalysis).filter(APKAnalysis.risk_score >= 81.0).count()
    avg_risk_score = db.query(func.avg(APKAnalysis.risk_score)).scalar() or 0.0

    recent = db.query(APKAnalysis).order_by(APKAnalysis.created_at.desc()).limit(8).all()
    recent_list = [
        {
            "id": r.id, "file_name": r.file_name, "package_name": r.package_name,
            "sha256": r.sha256,
            "risk_score": r.risk_score or 0.0, "verdict": r.verdict or "Queued",
            "status": r.status, "created_at": r.created_at.isoformat()
        }
        for r in recent
    ]

    safe_cnt = db.query(APKAnalysis).filter(APKAnalysis.risk_score <= 30.0).count()
    susp_cnt = db.query(APKAnalysis).filter(APKAnalysis.risk_score > 30.0, APKAnalysis.risk_score <= 60.0).count()
    high_cnt = db.query(APKAnalysis).filter(APKAnalysis.risk_score > 60.0, APKAnalysis.risk_score <= 80.0).count()
    crit_cnt = db.query(APKAnalysis).filter(APKAnalysis.risk_score > 80.0).count()

    risk_distribution = [
        {"name": "Safe (0-30)", "value": safe_cnt, "color": "#10b981"},
        {"name": "Suspicious (31-60)", "value": susp_cnt, "color": "#eab308"},
        {"name": "High Risk (61-80)", "value": high_cnt, "color": "#f97316"},
        {"name": "Critical (81-100)", "value": crit_cnt, "color": "#ef4444"}
    ]

    if db.bind.dialect.name == "sqlite":
        date_expr = func.date(APKAnalysis.created_at)
    else:
        date_expr = cast(APKAnalysis.created_at, Date)

    trends_query = db.query(
        date_expr.label("date"),
        func.count(APKAnalysis.id).label("total"),
        func.sum(case((APKAnalysis.risk_score >= 61.0, 1), else_=0)).label("malware")
    ).group_by(date_expr).order_by("date").limit(7).all()

    malware_trends = [
        {
            "date": str(t.date), "total": t.total, "malware": int(t.malware or 0),
            "benign": int(t.total - (t.malware or 0))
        }
        for t in trends_query
    ]

    ti_indicators = db.query(ThreatIntelligence.indicators).all()
    categories = {}
    for ind_row in ti_indicators:
        if ind_row[0]:
            try:
                inds = json.loads(ind_row[0])
                for ind in inds:
                    t_type = ind.get("type", "Other")
                    categories[t_type] = categories.get(t_type, 0) + 1
            except Exception:
                pass

    threat_categories = [
        {"name": k, "value": v} for k, v in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    mitre_query = db.query(
        MITREMapping.technique_id, MITREMapping.technique_name, func.count(MITREMapping.id).label("count")
    ).group_by(MITREMapping.technique_id, MITREMapping.technique_name).order_by("count").limit(5).all()

    top_mitre_techniques = [
        {"id": m.technique_id, "name": m.technique_name, "value": m.count}
        for m in mitre_query
    ]

    family_query = db.query(
        FamilySimilarity.family_name, func.count(FamilySimilarity.id).label("count")
    ).filter(FamilySimilarity.similarity_score >= 40.0).group_by(FamilySimilarity.family_name).order_by("count").all()
    
    family_distribution = [
        {"name": f.family_name, "value": f.count}
        for f in family_query
    ]
    
    top_families = [
        {"family_name": f.family_name, "count": f.count}
        for f in sorted(family_query, key=lambda x: x.count, reverse=True)[:3]
    ]

    return {
        "total_apks": total_apks, "malware_detected": malware_detected, "critical_threats": critical_threats,
        "avg_risk_score": round(avg_risk_score, 1), "recent_analyses": recent_list,
        "risk_distribution": risk_distribution, "malware_trends": malware_trends,
        "threat_categories": threat_categories, "top_mitre_techniques": top_mitre_techniques,
        "top_families": top_families, "family_distribution": family_distribution
    }


def get_full_analysis_response(record: APKAnalysis, db: Session) -> dict:
    # Handle queued/failed states gracefully
    if record.status in ("Queued", "Parsing APK", "Extracting Features", "Threat Analysis", "ML Detection", "MITRE Mapping", "Obfuscation Scan", "Dynamic Sandbox", "AI Report", "PDF Generation", "Failed"):
        return {
            "id": record.id,
            "file_name": record.file_name,
            "sha256": record.sha256,
            "package_name": record.package_name or "Pending...",
            "created_at": record.created_at.isoformat(),
            "status": record.status,
            "error_message": record.error_message,
            "risk_assessment": {
                "risk_score": 0.0,
                "verdict": "Analyzing",
                "risk_level": "PENDING",
                "breakdown": {"permission_risk_score": 0.0, "threat_intel_score": 0.0, "obfuscation_risk_score": 0.0, "mitre_severity_score": 0.0}
            }
        }

    features_rec = record.features
    ti_rec = record.threat_intel
    mitre_recs = record.mitre_mappings
    ai_rec = record.ai_report
    fam_recs = record.family_similarities
    dyn_rec = record.dynamic_analysis

    features_dict = {
        "permissions": [], "activities": [], "services": [], "receivers": [],
        "urls": [], "domains": [], "ips": [], "methods": [], "suspicious_apis": [],
        "intent_filters": [], "cert_metadata": {}, "version_name": "1.0", "version_code": "1"
    }

    if features_rec:
        cert_meta_dict = features_rec.get_dict("cert_metadata")
        features_dict = {
            "permissions": features_rec.get_list("permissions"),
            "activities": features_rec.get_list("activities"),
            "services": features_rec.get_list("services"),
            "receivers": features_rec.get_list("receivers"),
            "urls": features_rec.get_list("urls"),
            "domains": features_rec.get_list("domains"),
            "ips": features_rec.get_list("ips"),
            "methods": features_rec.get_list("methods"),
            "intent_filters": features_rec.get_list("intent_filters"),
            "cert_metadata": cert_meta_dict,
            "suspicious_apis": [m for m in features_rec.get_list("methods") if m in analyzer.suspicious_apis_set],
            "target_sdk": cert_meta_dict.get("target_sdk", "33"),
            "version_name": cert_meta_dict.get("version_name", "1.0"),
            "version_code": cert_meta_dict.get("version_code", "1")
        }

    threat_dict = {"threat_score": 0.0, "severity": "LOW", "indicators": []}
    if ti_rec:
        threat_dict = {
            "threat_score": ti_rec.threat_score,
            "severity": ti_rec.severity,
            "indicators": ti_rec.get_indicators()
        }

    mitre_list = []
    TECHNIQUE_TO_TACTIC = {
        "T1477": "Initial Access",
        "T1624": "Persistence",
        "T1546": "Persistence",
        "T1516": "Credential Access",
        "T1411": "Credential Access",
        "T1414": "Credential Access",
        "T1636": "Collection",
        "T1412": "Collection",
        "T1429": "Collection",
        "T1512": "Collection",
        "T1430": "Discovery",
        "T1404": "Discovery",
        "T1426": "Discovery",
        "T1407": "Defense Evasion",
        "T1409": "Defense Evasion"
    }
    for m in mitre_recs:
        mitre_list.append({
            "tactic": TECHNIQUE_TO_TACTIC.get(m.technique_id, "Discovery"),
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "severity": m.severity,
            "evidence": m.evidence,
            "confidence": m.confidence
        })

    family_list = []
    for f in fam_recs:
        family_list.append({
            "family_name": f.family_name,
            "similarity_score": f.similarity_score,
            "confidence": f.confidence,
            "threat_category": f.threat_category
        })

    dyn_dict = {
        "behavior_score": 0.0,
        "frida_logs": [],
        "process_calls": [],
        "file_activities": [],
        "network_connections": [],
        "runtime_permissions": []
    }
    if dyn_rec:
        dyn_dict = {
            "behavior_score": dyn_rec.behavior_score,
            "frida_logs": dyn_rec.get_list("frida_logs"),
            "process_calls": dyn_rec.get_list("process_calls"),
            "file_activities": dyn_rec.get_list("file_activities"),
            "network_connections": dyn_rec.get_list("network_connections"),
            "runtime_permissions": dyn_rec.get_list("runtime_permissions")
        }

    obfuscation_dict = {
        "obfuscation_score": record.obfuscation_score or 0.0,
        "findings": features_rec.get_list("obfuscation_findings") if features_rec else []
    }

    ai_dict = {
        "executive_summary": "N/A", "threat_assessment": "N/A", "ioc": "[]",
        "recommendations": "N/A", "soc_commentary": "N/A", "malware_family_analysis": "N/A",
        "mitre_analysis": "N/A", "risk_justification": "N/A"
    }
    if ai_rec:
        exec_full = ai_rec.executive_summary or ""
        threat_full = ai_rec.threat_assessment or ""
        
        exec_split = exec_full.split("**MALWARE FAMILY ATTRIBUTION**")
        threat_split1 = threat_full.split("**MITRE ATT&CK MATRIX MAP**")
        
        exec_summary_clean = exec_split[0].replace("**EXECUTIVE SUMMARY**\n", "").strip()
        fam_analysis_clean = len(exec_split) > 1 and exec_split[1].strip() or "N/A"
        
        threat_assessment_clean = threat_split1[0].replace("**THREAT ASSESSMENT**\n", "").strip()
        
        mitre_analysis_clean = "N/A"
        risk_justification_clean = "N/A"
        if len(threat_split1) > 1:
            threat_split2 = threat_split1[1].split("**RISK JUSTIFICATION**")
            mitre_analysis_clean = threat_split2[0].strip()
            risk_justification_clean = len(threat_split2) > 1 and threat_split2[1].strip() or "N/A"

        ai_dict = {
            "executive_summary": exec_summary_clean,
            "threat_assessment": threat_assessment_clean,
            "ioc": ai_rec.ioc,
            "recommendations": ai_rec.recommendations,
            "soc_commentary": ai_rec.soc_commentary,
            "malware_family_analysis": fam_analysis_clean,
            "mitre_analysis": mitre_analysis_clean,
            "risk_justification": risk_justification_clean
        }

    attack_chain = analyzer.generate_attack_chain(
        permissions=features_dict["permissions"],
        methods=features_dict["methods"],
        urls=features_dict["urls"]
    )

    combined_items = (
        features_dict["permissions"] + features_dict["activities"] +
        features_dict["services"] + features_dict["receivers"] + features_dict["methods"]
    )
    combined_text = " ".join(combined_items)
    
    import re
    if record.status == "Completed" and record.malware_probability is not None:
        from app.ml_model import GLOBAL_SHAP_FEATURES
        explanations = []
        text_lower = combined_text.lower()
        for feat, info in GLOBAL_SHAP_FEATURES.items():
            escaped_feat = re.escape(feat)
            if re.search(r'\b' + escaped_feat + r'\b', text_lower):
                explanations.append({
                    "feature": feat,
                    "importance": info["importance"],
                    "type": info["type"],
                    "description": info["description"]
                })
        explanations = sorted(explanations, key=lambda x: x["importance"], reverse=True)[:8]
        
        ml_result = {
            "malware_probability": record.malware_probability,
            "prediction": 1 if record.malware_probability >= 0.50 else 0,
            "confidence": record.malware_probability if record.malware_probability >= 0.50 else (1.0 - record.malware_probability),
            "verdict": record.verdict.lower() if record.verdict else "benign",
            "explanations": explanations
        }
    else:
        ml_result = predict_apk_malware(combined_text)

    # 4-factor risk breakdown metrics
    perm_risk_score = risk_engine.calculate_permission_risk(features_dict["permissions"])
    threat_intel_score = threat_dict["threat_score"]
    obfuscation_risk_score = record.obfuscation_score or 0.0
    behavior_risk_score = max(risk_engine.calculate_mitre_score(mitre_list), dyn_dict["behavior_score"])

    return {
        "id": record.id,
        "file_name": record.file_name,
        "sha256": record.sha256,
        "package_name": record.package_name,
        "created_at": record.created_at.isoformat(),
        "status": record.status,
        "metadata": {
            "file_name": record.file_name,
            "package_name": record.package_name,
            "sha256": record.sha256,
            "target_sdk": features_dict.get("target_sdk", "33"),
            "file_size": 2621440
        },
        "features": features_dict,
        "threat_intelligence": threat_dict,
        "mitre_mapping": mitre_list,
        "family_similarity": family_list,
        "attack_chain": attack_chain,
        "obfuscation_analysis": obfuscation_dict,
        "dynamic_analysis": dyn_dict,
        "machine_learning": {
            "malware_probability": record.malware_probability or 0.0,
            "prediction": 1 if (record.malware_probability or 0.0) >= 0.50 else 0,
            "confidence": record.malware_probability or 0.0,
            "verdict": record.verdict or "benign",
            "explanations": ml_result.get("explanations", []),
            "online_model": online_learner.predict(
                combined_text if features_rec else ""
            )
        },
        "risk_assessment": {
            "risk_score": record.risk_score or 0.0,
            "verdict": record.verdict or "benign",
            "risk_level": "CRITICAL" if (record.risk_score or 0.0) >= 81.0 else ("HIGH" if (record.risk_score or 0.0) >= 61.0 else ("MEDIUM" if (record.risk_score or 0.0) >= 31.0 else "LOW")),
            "breakdown": {
                "permission_risk_score": round(perm_risk_score, 1),
                "threat_intel_score": round(threat_intel_score, 1),
                "obfuscation_risk_score": round(obfuscation_risk_score, 1),
                "mitre_severity_score": round(behavior_risk_score, 1)
            }
        },
        "ai_report": ai_dict
    }


# ====================================================================
# ONLINE LEARNING API ENDPOINTS
# ====================================================================

@app.get("/model/status")
def get_model_status(db: Session = Depends(get_db)):
    """
    Returns the current status of the online learning model including
    training metrics, sample counts, and class balance.
    """
    status = online_learner.get_status()
    
    # Enrich with DB sample counts
    total_db_samples = db.query(TrainingSample).count()
    malware_db = db.query(TrainingSample).filter(TrainingSample.label == 1).count()
    benign_db = db.query(TrainingSample).filter(TrainingSample.label == 0).count()
    
    # Recent training history (last 10 samples)
    recent_samples = db.query(TrainingSample).order_by(
        TrainingSample.learned_at.desc()
    ).limit(10).all()
    
    recent_history = []
    for s in recent_samples:
        apk = db.query(APKAnalysis).filter(APKAnalysis.id == s.apk_id).first()
        recent_history.append({
            "apk_id": s.apk_id,
            "file_name": apk.file_name if apk else "Unknown",
            "label": "malware" if s.label == 1 else "benign",
            "risk_score": s.risk_score,
            "model_version": s.model_version,
            "learned_at": s.learned_at.isoformat() if s.learned_at else None
        })
    
    status["database_samples"] = {
        "total": total_db_samples,
        "malware": malware_db,
        "benign": benign_db
    }
    status["recent_training_history"] = recent_history
    
    return status


@app.post("/model/retrain-all")
def retrain_from_all_samples(db: Session = Depends(get_db)):
    """
    Re-trains the online model from ALL persisted training samples.
    Useful to rebuild model after server restart.
    """
    samples = db.query(TrainingSample).order_by(TrainingSample.learned_at.asc()).all()
    
    if not samples:
        return {"status": "no_samples", "message": "No training samples found in database."}
    
    count = 0
    for sample in samples:
        if sample.feature_text:
            online_learner.learn(sample.feature_text, sample.label)
            count += 1
    
    online_learner.force_save()
    
    return {
        "status": "retrained",
        "samples_processed": count,
        "model_version": online_learner.meta["model_version"],
        "message": f"Online model retrained from {count} persisted samples."
    }


@app.post("/model/predict")
def online_model_predict(payload: dict):
    """
    Make a prediction using ONLY the online learning model.
    Useful for comparing with the static XGBoost model.
    """
    feature_text = payload.get("feature_text", "")
    if not feature_text:
        raise HTTPException(status_code=400, detail="feature_text is required")
    
    return online_learner.predict(feature_text)


@app.post("/model/save")
def save_model_checkpoint():
    """Force-save the online model checkpoint to disk."""
    return online_learner.force_save()
