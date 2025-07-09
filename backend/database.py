from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import json

# Configuración de la base de datos
DATABASE_URL = "sqlite:///./devsecops.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True)
    scan_type = Column(String, nullable=False)
    target = Column(String, nullable=False)
    status = Column(String, nullable=False, default="pending")
    timestamp = Column(DateTime, default=datetime.utcnow)
    results_summary = Column(Text)  # JSON string
    
    # Relación con findings
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    
    def get_summary_dict(self):
        """Convertir results_summary de JSON string a dict"""
        if self.results_summary:
            try:
                return json.loads(self.results_summary)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def set_summary_dict(self, summary_dict):
        """Convertir dict a JSON string para results_summary"""
        self.results_summary = json.dumps(summary_dict)

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, ForeignKey("scans.scan_id"))
    tool = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    category = Column(String)
    description = Column(Text, nullable=False)
    location = Column(String)
    solution = Column(Text)
    cve_id = Column(String)
    
    # Relación con scan
    scan = relationship("Scan", back_populates="findings")

# Crear las tablas
def create_tables():
    Base.metadata.create_all(bind=engine)

# Dependency para obtener la sesión de base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

