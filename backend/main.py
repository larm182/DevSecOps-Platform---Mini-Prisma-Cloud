from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.orm import Session
import json
import os
import uuid
from datetime import datetime
import logging
from scanners import ScannerFactory
from database import get_db, create_tables
from services import ScanService, FindingService, DashboardService
from alerts import alert_manager

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear tablas al iniciar
create_tables()

app = FastAPI(title="DevSecOps Platform API", version="1.0.0")

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción, especificar dominios específicos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelos de datos
class ScanRequest(BaseModel):
    scan_type: str  # 'sast', 'sca', 'docker', 'secrets'
    target: str  # Ruta del código, nombre de la imagen, etc.

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class Finding(BaseModel):
    id: Optional[int] = None
    scan_id: str
    tool: str
    severity: str
    category: Optional[str] = None
    description: str
    location: Optional[str] = None
    solution: Optional[str] = None
    cve_id: Optional[str] = None

class ScanResult(BaseModel):
    scan_id: str
    scan_type: str
    timestamp: datetime
    target: str
    status: str
    findings: List[Finding]
    summary: dict

def run_security_scan(scan_id: str, scan_type: str, target: str):
    """Ejecutar escaneo de seguridad en segundo plano"""
    db = next(get_db())
    try:
        logger.info(f"Starting {scan_type} scan for {target}")
        
        # Actualizar estado a "running"
        ScanService.update_scan_status(db, scan_id, "running")
        
        # Crear scanner apropiado
        scanner = ScannerFactory.create_scanner(scan_type)
        
        # Ejecutar escaneo
        result = scanner.scan(target, scan_type)
        
        # Actualizar resultados en la base de datos
        if result["status"] == "completed":
            ScanService.update_scan_results(
                db, 
                scan_id, 
                result.get("findings", []), 
                result.get("summary", {})
            )
            
            # Enviar alertas si hay vulnerabilidades críticas
            findings = result.get("findings", [])
            if findings:
                scan_data = {
                    "scan_id": scan_id,
                    "scan_type": scan_type,
                    "target": target
                }
                alert_result = alert_manager.send_alert(scan_data, findings)
                logger.info(f"Alert result: {alert_result}")
        else:
            ScanService.update_scan_status(db, scan_id, "failed")
        
        logger.info(f"Completed {scan_type} scan for {target}: {len(result.get('findings', []))} findings")
        
    except Exception as e:
        logger.error(f"Error in scan {scan_id}: {str(e)}")
        ScanService.update_scan_status(db, scan_id, "failed")
    finally:
        db.close()

@app.get("/")
async def root():
    return {"message": "DevSecOps Platform API", "version": "1.0.0"}

@app.post("/api/upload", response_model=dict)
async def upload_file(file: UploadFile = File(...)):
    """Subir archivo para escaneo"""
    try:
        # Crear directorio de uploads si no existe
        upload_dir = "uploads"
        os.makedirs(upload_dir, exist_ok=True)
        
        # Generar nombre único para el archivo
        file_id = str(uuid.uuid4())
        file_extension = os.path.splitext(file.filename)[1]
        file_path = os.path.join(upload_dir, f"{file_id}{file_extension}")
        
        # Guardar archivo
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        return {
            "file_id": file_id,
            "filename": file.filename,
            "file_path": file_path,
            "size": len(content)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error uploading file: {str(e)}")

@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Iniciar un escaneo"""
    try:
        scan_id = str(uuid.uuid4())
        
        # Validar tipo de escaneo
        valid_scan_types = ["sast", "sca", "docker", "secrets"]
        if scan_request.scan_type not in valid_scan_types:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid scan type. Must be one of: {valid_scan_types}"
            )
        
        # Crear registro de escaneo en la base de datos
        ScanService.create_scan(db, scan_id, scan_request.scan_type, scan_request.target)
        
        # Ejecutar escaneo en segundo plano
        background_tasks.add_task(
            run_security_scan, 
            scan_id, 
            scan_request.scan_type, 
            scan_request.target
        )
        
        return ScanResponse(
            scan_id=scan_id,
            status="pending",
            message=f"Scan {scan_request.scan_type} initiated for {scan_request.target}"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting scan: {str(e)}")

@app.get("/api/scan/{scan_id}", response_model=ScanResult)
async def get_scan_result(scan_id: str, db: Session = Depends(get_db)):
    """Obtener resultado de un escaneo"""
    scan = ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Convertir findings de SQLAlchemy a dict
    findings = [
        {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "tool": finding.tool,
            "severity": finding.severity,
            "category": finding.category,
            "description": finding.description,
            "location": finding.location,
            "solution": finding.solution,
            "cve_id": finding.cve_id
        }
        for finding in scan.findings
    ]
    
    return ScanResult(
        scan_id=scan.scan_id,
        scan_type=scan.scan_type,
        timestamp=scan.timestamp,
        target=scan.target,
        status=scan.status,
        findings=findings,
        summary=scan.get_summary_dict()
    )

@app.get("/api/scans", response_model=List[dict])
async def list_scans(db: Session = Depends(get_db)):
    """Listar todos los escaneos"""
    scans = ScanService.get_scans(db)
    return [
        {
            "scan_id": scan.scan_id,
            "scan_type": scan.scan_type,
            "target": scan.target,
            "status": scan.status,
            "timestamp": scan.timestamp,
            "findings_count": len(scan.findings)
        }
        for scan in scans
    ]

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Obtener estadísticas para el dashboard"""
    return DashboardService.get_dashboard_stats(db)

@app.post("/api/test-alert")
async def test_alert():
    """Endpoint para probar el sistema de alertas"""
    # Crear datos de prueba
    scan_data = {
        "scan_id": "test-scan-123",
        "scan_type": "sast",
        "target": "test_application.py"
    }
    
    test_findings = [
        {
            "tool": "Semgrep",
            "severity": "critical",
            "category": "SQL Injection",
            "description": "Potential SQL injection vulnerability detected in user input handling",
            "location": "app.py:42",
            "solution": "Use parameterized queries"
        },
        {
            "tool": "Semgrep",
            "severity": "high",
            "category": "XSS",
            "description": "Cross-site scripting vulnerability in template rendering",
            "location": "templates/user.html:15",
            "solution": "Escape user input properly"
        }
    ]
    
    result = alert_manager.send_alert(scan_data, test_findings)
    return {"message": "Test alert sent", "result": result}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

