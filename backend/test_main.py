import pytest
import asyncio
from httpx import AsyncClient
from fastapi.testclient import TestClient
from main import app
from database import get_db, create_tables, Base, engine
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import tempfile
import os

# Configurar base de datos de prueba
TEST_DATABASE_URL = "sqlite:///./test.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="module")
def test_client():
    """Cliente de prueba para FastAPI"""
    # Crear tablas de prueba
    Base.metadata.create_all(bind=test_engine)
    with TestClient(app) as client:
        yield client
    # Limpiar base de datos de prueba
    if os.path.exists("test.db"):
        os.remove("test.db")

@pytest.fixture
def sample_scan_data():
    """Datos de prueba para escaneos"""
    return {
        "scan_type": "sast",
        "target": "/tmp/test_file.py"
    }

class TestAPI:
    """Tests para la API principal"""
    
    def test_root_endpoint(self, test_client):
        """Test del endpoint raíz"""
        response = test_client.get("/")
        assert response.status_code == 200
        assert response.json()["message"] == "DevSecOps Platform API"
    
    def test_dashboard_stats(self, test_client):
        """Test del endpoint de estadísticas"""
        response = test_client.get("/api/dashboard/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "scan_types" in data
        assert "severity_distribution" in data
    
    def test_list_scans_empty(self, test_client):
        """Test de listado de escaneos vacío"""
        response = test_client.get("/api/scans")
        assert response.status_code == 200
        assert response.json() == []
    
    def test_create_scan(self, test_client, sample_scan_data):
        """Test de creación de escaneo"""
        response = test_client.post("/api/scan", json=sample_scan_data)
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "pending"
        return data["scan_id"]
    
    def test_get_scan_result(self, test_client, sample_scan_data):
        """Test de obtención de resultado de escaneo"""
        # Crear escaneo
        create_response = test_client.post("/api/scan", json=sample_scan_data)
        assert create_response.status_code == 200
        scan_id = create_response.json()["scan_id"]
        
        # Obtener resultado
        response = test_client.get(f"/api/scan/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id
        assert data["scan_type"] == sample_scan_data["scan_type"]
    
    def test_get_nonexistent_scan(self, test_client):
        """Test de obtención de escaneo inexistente"""
        response = test_client.get("/api/scan/nonexistent-id")
        assert response.status_code == 404
    
    def test_invalid_scan_type(self, test_client):
        """Test de tipo de escaneo inválido"""
        invalid_data = {
            "scan_type": "invalid_type",
            "target": "/tmp/test_file.py"
        }
        response = test_client.post("/api/scan", json=invalid_data)
        assert response.status_code == 400
    
    def test_upload_file(self, test_client):
        """Test de subida de archivo"""
        # Crear archivo temporal
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("print('Hello, World!')")
            temp_file = f.name
        
        try:
            with open(temp_file, 'rb') as f:
                response = test_client.post(
                    "/api/upload",
                    files={"file": ("test.py", f, "text/plain")}
                )
            assert response.status_code == 200
            data = response.json()
            assert "file_id" in data
            assert "filename" in data
            assert data["filename"] == "test.py"
        finally:
            os.unlink(temp_file)

class TestScanners:
    """Tests para los escáneres de seguridad"""
    
    def test_semgrep_scanner(self):
        """Test del scanner Semgrep"""
        from scanners import SemgrepScanner
        scanner = SemgrepScanner()
        
        # Crear archivo de prueba con vulnerabilidad
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
import sqlite3
def get_user(user_id):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
""")
            temp_file = f.name
        
        try:
            result = scanner.scan(temp_file, "sast")
            assert result["status"] == "completed"
            assert "findings" in result
        finally:
            os.unlink(temp_file)
    
    def test_gitleaks_scanner(self):
        """Test del scanner Gitleaks"""
        from scanners import GitleaksScanner
        scanner = GitleaksScanner()
        
        # Crear archivo de prueba con secreto
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
API_KEY = "sk-1234567890abcdef1234567890abcdef"
DATABASE_PASSWORD = "super_secret_password_123"
""")
            temp_file = f.name
        
        try:
            result = scanner.scan(temp_file, "secrets")
            assert result["status"] == "completed"
            assert "findings" in result
        finally:
            os.unlink(temp_file)

class TestAlerts:
    """Tests para el sistema de alertas"""
    
    def test_alert_manager_initialization(self):
        """Test de inicialización del gestor de alertas"""
        from alerts import AlertManager
        alert_manager = AlertManager()
        assert alert_manager is not None
    
    def test_should_alert_critical(self):
        """Test de detección de vulnerabilidades críticas"""
        from alerts import AlertManager
        alert_manager = AlertManager()
        
        findings = [
            {"severity": "critical", "description": "Critical vulnerability"},
            {"severity": "medium", "description": "Medium vulnerability"}
        ]
        
        assert alert_manager.should_alert(findings) == True
    
    def test_should_alert_many_high(self):
        """Test de detección de muchas vulnerabilidades altas"""
        from alerts import AlertManager
        alert_manager = AlertManager()
        
        findings = [{"severity": "high", "description": f"High vulnerability {i}"} for i in range(6)]
        
        assert alert_manager.should_alert(findings) == True
    
    def test_should_not_alert_low_severity(self):
        """Test de no alerta para vulnerabilidades de baja severidad"""
        from alerts import AlertManager
        alert_manager = AlertManager()
        
        findings = [
            {"severity": "low", "description": "Low vulnerability"},
            {"severity": "medium", "description": "Medium vulnerability"}
        ]
        
        assert alert_manager.should_alert(findings) == False
    
    def test_format_alert_message(self):
        """Test de formato de mensaje de alerta"""
        from alerts import AlertManager
        alert_manager = AlertManager()
        
        scan_data = {
            "scan_id": "test-123",
            "scan_type": "sast",
            "target": "test.py"
        }
        
        findings = [
            {
                "severity": "critical",
                "category": "SQL Injection",
                "description": "Potential SQL injection vulnerability"
            }
        ]
        
        alert_data = alert_manager.format_alert_message(scan_data, findings)
        
        assert "title" in alert_data
        assert "🚨" in alert_data["title"]
        assert "SAST" in alert_data["title"]
        assert "🔴 1 Críticas" in alert_data["severity_summary"]

class TestDatabase:
    """Tests para operaciones de base de datos"""
    
    def test_scan_service_create(self):
        """Test de creación de escaneo en base de datos"""
        from services import ScanService
        
        db = TestingSessionLocal()
        try:
            scan = ScanService.create_scan(db, "test-scan-123", "sast", "/tmp/test.py")
            assert scan.scan_id == "test-scan-123"
            assert scan.scan_type == "sast"
            assert scan.status == "pending"
        finally:
            db.close()
    
    def test_scan_service_get(self):
        """Test de obtención de escaneo de base de datos"""
        from services import ScanService
        
        db = TestingSessionLocal()
        try:
            # Crear escaneo
            created_scan = ScanService.create_scan(db, "test-scan-456", "sca", "/tmp/test.py")
            
            # Obtener escaneo
            retrieved_scan = ScanService.get_scan(db, "test-scan-456")
            
            assert retrieved_scan is not None
            assert retrieved_scan.scan_id == created_scan.scan_id
        finally:
            db.close()

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

