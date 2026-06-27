import os
import json
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

# Database connection URL - Default to SQLite for local development, fall back if PostgreSQL not configured
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./apk_sentinel.db")

# Fix postgres:// dialect resolution for SQLAlchemy 1.4+
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Create engine
if DATABASE_URL.startswith("postgresql"):
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
else:
    # SQLite requires check_same_thread=False for multi-threaded FastAPI
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class APKAnalysis(Base):
    __tablename__ = "apk_analysis"

    id = Column(Integer, primary_key=True, index=True)
    file_name = Column(String, index=True)
    sha256 = Column(String, unique=True, index=True)
    package_name = Column(String, index=True)
    risk_score = Column(Float, nullable=True) # Nullable because it is calculated in background
    malware_probability = Column(Float, nullable=True)
    obfuscation_score = Column(Float, nullable=True) # Added for Obfuscation Engine
    verdict = Column(String, nullable=True)
    status = Column(String, default="Queued") # Queued, Parsing APK, Extracting Features, Threat Analysis, ML Detection, MITRE Mapping, AI Report, PDF Generation, Completed, Failed
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    features = relationship("ExtractedFeatures", back_populates="apk", uselist=False, cascade="all, delete-orphan")
    threat_intel = relationship("ThreatIntelligence", back_populates="apk", uselist=False, cascade="all, delete-orphan")
    mitre_mappings = relationship("MITREMapping", back_populates="apk", cascade="all, delete-orphan")
    family_similarities = relationship("FamilySimilarity", back_populates="apk", cascade="all, delete-orphan")
    ai_report = relationship("AIReport", back_populates="apk", uselist=False, cascade="all, delete-orphan")
    dynamic_analysis = relationship("DynamicAnalysis", back_populates="apk", uselist=False, cascade="all, delete-orphan")
    training_sample = relationship("TrainingSample", back_populates="apk", uselist=False, cascade="all, delete-orphan")

class ExtractedFeatures(Base):
    __tablename__ = "extracted_features"

    id = Column(Integer, primary_key=True, index=True)
    apk_id = Column(Integer, ForeignKey("apk_analysis.id", ondelete="CASCADE"), unique=True)
    
    permissions = Column(Text)  # JSON serialized list of strings
    activities = Column(Text)   # JSON serialized list of strings
    services = Column(Text)     # JSON serialized list of strings
    receivers = Column(Text)    # JSON serialized list of strings
    urls = Column(Text)         # JSON serialized list of strings
    domains = Column(Text)      # JSON serialized list of strings
    ips = Column(Text)          # JSON serialized list of strings
    methods = Column(Text)      # JSON serialized list of strings
    intent_filters = Column(Text) # JSON serialized list of strings
    cert_metadata = Column(Text)  # JSON serialized metadata dict
    obfuscation_findings = Column(Text, nullable=True) # JSON serialized list of dicts

    apk = relationship("APKAnalysis", back_populates="features")

    def get_list(self, field_name: str) -> list:
        field_val = getattr(self, field_name)
        if not field_val:
            return []
        try:
            return json.loads(field_val)
        except Exception:
            return []

    def set_list(self, field_name: str, value: list):
        setattr(self, field_name, json.dumps(value))

    def get_dict(self, field_name: str) -> dict:
        field_val = getattr(self, field_name)
        if not field_val:
            return {}
        try:
            return json.loads(field_val)
        except Exception:
            return {}

    def set_dict(self, field_name: str, value: dict):
        setattr(self, field_name, json.dumps(value))

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"

    id = Column(Integer, primary_key=True, index=True)
    apk_id = Column(Integer, ForeignKey("apk_analysis.id", ondelete="CASCADE"), unique=True)
    threat_score = Column(Float)
    severity = Column(String)
    indicators = Column(Text)   # JSON serialized list of dicts

    apk = relationship("APKAnalysis", back_populates="threat_intel")

    def get_indicators(self) -> list:
        if not self.indicators:
            return []
        try:
            return json.loads(self.indicators)
        except Exception:
            return []

    def set_indicators(self, value: list):
        self.indicators = json.dumps(value)

class MITREMapping(Base):
    __tablename__ = "mitre_mapping"

    id = Column(Integer, primary_key=True, index=True)
    apk_id = Column(Integer, ForeignKey("apk_analysis.id", ondelete="CASCADE"))
    technique_id = Column(String)
    technique_name = Column(String)
    severity = Column(String)
    evidence = Column(String)
    confidence = Column(String)

    apk = relationship("APKAnalysis", back_populates="mitre_mappings")

class FamilySimilarity(Base):
    __tablename__ = "family_similarity"

    id = Column(Integer, primary_key=True, index=True)
    apk_id = Column(Integer, ForeignKey("apk_analysis.id", ondelete="CASCADE"))
    family_name = Column(String)
    similarity_score = Column(Float)
    confidence = Column(String)
    threat_category = Column(String)

    apk = relationship("APKAnalysis", back_populates="family_similarities")

class DynamicAnalysis(Base):
    __tablename__ = "dynamic_analysis"

    id = Column(Integer, primary_key=True, index=True)
    apk_id = Column(Integer, ForeignKey("apk_analysis.id", ondelete="CASCADE"), unique=True)
    behavior_score = Column(Float)
    frida_logs = Column(Text)           # JSON serialized list of dicts
    process_calls = Column(Text)         # JSON serialized list of dicts
    file_activities = Column(Text)       # JSON serialized list of dicts
    network_connections = Column(Text)   # JSON serialized list of dicts
    runtime_permissions = Column(Text)   # JSON serialized list of dicts

    apk = relationship("APKAnalysis", back_populates="dynamic_analysis")

    def get_list(self, field_name: str) -> list:
        field_val = getattr(self, field_name)
        if not field_val:
            return []
        try:
            return json.loads(field_val)
        except Exception:
            return []

    def set_list(self, field_name: str, value: list):
        setattr(self, field_name, json.dumps(value))

class AIReport(Base):
    __tablename__ = "ai_reports"

    id = Column(Integer, primary_key=True, index=True)
    apk_id = Column(Integer, ForeignKey("apk_analysis.id", ondelete="CASCADE"), unique=True)
    
    executive_summary = Column(Text)
    threat_assessment = Column(Text)
    ioc = Column(Text)            # JSON serialized list or dict of IOCs
    recommendations = Column(Text)
    soc_commentary = Column(Text)

    apk = relationship("APKAnalysis", back_populates="ai_report")

class TrainingSample(Base):
    """
    Stores feature vectors and labels from completed analyses for online learning.
    Every completed APK analysis generates a training sample that feeds the
    incremental SGDClassifier via partial_fit.
    """
    __tablename__ = "training_samples"

    id = Column(Integer, primary_key=True, index=True)
    apk_id = Column(Integer, ForeignKey("apk_analysis.id", ondelete="CASCADE"), unique=True)
    feature_text = Column(Text)         # Combined feature text for vectorization
    label = Column(Integer)             # 0 = benign, 1 = malware
    risk_score = Column(Float)          # Risk score at time of labeling
    malware_probability = Column(Float) # ML probability at time of labeling
    verdict = Column(String)            # Verdict at time of labeling
    model_version = Column(Integer)     # Which model version learned this sample
    learned_at = Column(DateTime, default=datetime.utcnow)

    apk = relationship("APKAnalysis", back_populates="training_sample")

# Dependency helper
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize database tables
def init_db():
    Base.metadata.create_all(bind=engine)
