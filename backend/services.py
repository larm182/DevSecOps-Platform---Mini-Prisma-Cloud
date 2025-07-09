from sqlalchemy.orm import Session
from database import Scan, Finding
from typing import List, Optional
import json

class ScanService:
    """Servicio para operaciones CRUD de escaneos"""
    
    @staticmethod
    def create_scan(db: Session, scan_id: str, scan_type: str, target: str) -> Scan:
        """Crear un nuevo escaneo"""
        db_scan = Scan(
            scan_id=scan_id,
            scan_type=scan_type,
            target=target,
            status="pending"
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        return db_scan
    
    @staticmethod
    def get_scan(db: Session, scan_id: str) -> Optional[Scan]:
        """Obtener un escaneo por ID"""
        return db.query(Scan).filter(Scan.scan_id == scan_id).first()
    
    @staticmethod
    def get_scans(db: Session, skip: int = 0, limit: int = 100) -> List[Scan]:
        """Obtener lista de escaneos"""
        return db.query(Scan).offset(skip).limit(limit).all()
    
    @staticmethod
    def update_scan_status(db: Session, scan_id: str, status: str) -> Optional[Scan]:
        """Actualizar el estado de un escaneo"""
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if db_scan:
            db_scan.status = status
            db.commit()
            db.refresh(db_scan)
        return db_scan
    
    @staticmethod
    def update_scan_results(db: Session, scan_id: str, findings: List[dict], summary: dict) -> Optional[Scan]:
        """Actualizar los resultados de un escaneo"""
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if db_scan:
            # Actualizar estado y resumen
            db_scan.status = "completed"
            db_scan.set_summary_dict(summary)
            
            # Eliminar findings anteriores
            db.query(Finding).filter(Finding.scan_id == scan_id).delete()
            
            # Agregar nuevos findings
            for finding_data in findings:
                db_finding = Finding(
                    scan_id=scan_id,
                    tool=finding_data.get("tool", ""),
                    severity=finding_data.get("severity", "info"),
                    category=finding_data.get("category"),
                    description=finding_data.get("description", ""),
                    location=finding_data.get("location"),
                    solution=finding_data.get("solution"),
                    cve_id=finding_data.get("cve_id")
                )
                db.add(db_finding)
            
            db.commit()
            db.refresh(db_scan)
        return db_scan

class FindingService:
    """Servicio para operaciones CRUD de hallazgos"""
    
    @staticmethod
    def get_findings_by_scan(db: Session, scan_id: str) -> List[Finding]:
        """Obtener todos los hallazgos de un escaneo"""
        return db.query(Finding).filter(Finding.scan_id == scan_id).all()
    
    @staticmethod
    def get_findings_by_severity(db: Session, severity: str) -> List[Finding]:
        """Obtener hallazgos por severidad"""
        return db.query(Finding).filter(Finding.severity == severity).all()

class DashboardService:
    """Servicio para estadísticas del dashboard"""
    
    @staticmethod
    def get_dashboard_stats(db: Session) -> dict:
        """Obtener estadísticas para el dashboard"""
        # Total de escaneos
        total_scans = db.query(Scan).count()
        
        # Contar por tipo de escaneo
        scan_types = {}
        scans = db.query(Scan).all()
        for scan in scans:
            scan_types[scan.scan_type] = scan_types.get(scan.scan_type, 0) + 1
        
        # Contar por severidad
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        findings = db.query(Finding).all()
        for finding in findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1
        
        # Escaneos recientes
        recent_scans = db.query(Scan).order_by(Scan.timestamp.desc()).limit(5).all()
        
        return {
            "total_scans": total_scans,
            "scan_types": scan_types,
            "severity_distribution": severity_counts,
            "recent_scans": [
                {
                    "scan_id": scan.scan_id,
                    "scan_type": scan.scan_type,
                    "target": scan.target,
                    "status": scan.status,
                    "timestamp": scan.timestamp,
                    "findings_count": len(scan.findings)
                }
                for scan in recent_scans
            ]
        }

