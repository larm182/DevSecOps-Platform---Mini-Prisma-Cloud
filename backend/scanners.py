import subprocess
import json
import tempfile
import os
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class SecurityScanner:
    """Clase base para todos los escáneres de seguridad"""
    
    def __init__(self):
        self.name = "BaseScanner"
    
    def scan(self, target: str, scan_type: str) -> Dict[str, Any]:
        """Método base para realizar escaneos"""
        raise NotImplementedError("Subclasses must implement scan method")
    
    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        """Método base para parsear resultados"""
        raise NotImplementedError("Subclasses must implement parse_results method")

class SemgrepScanner(SecurityScanner):
    """Scanner para análisis de código fuente (SAST) usando Semgrep"""
    
    def __init__(self):
        super().__init__()
        self.name = "Semgrep"
    
    def scan(self, target: str, scan_type: str = "sast") -> Dict[str, Any]:
        """Ejecutar escaneo SAST con Semgrep"""
        try:
            # Comando Semgrep con reglas automáticas
            cmd = [
                "semgrep",
                "--config=auto",
                "--json",
                "--quiet",
                target
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutos timeout
            )
            
            if result.returncode != 0 and result.returncode != 1:  # Semgrep retorna 1 si encuentra issues
                logger.error(f"Semgrep error: {result.stderr}")
                return {
                    "status": "error",
                    "message": f"Semgrep scan failed: {result.stderr}",
                    "findings": []
                }
            
            findings = self.parse_results(result.stdout)
            
            return {
                "status": "completed",
                "tool": self.name,
                "findings": findings,
                "summary": {
                    "total_findings": len(findings),
                    "critical": len([f for f in findings if f.get("severity") == "critical"]),
                    "high": len([f for f in findings if f.get("severity") == "high"]),
                    "medium": len([f for f in findings if f.get("severity") == "medium"]),
                    "low": len([f for f in findings if f.get("severity") == "low"])
                }
            }
            
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "message": "Semgrep scan timed out",
                "findings": []
            }
        except Exception as e:
            logger.error(f"Semgrep scan error: {str(e)}")
            return {
                "status": "error",
                "message": f"Semgrep scan failed: {str(e)}",
                "findings": []
            }
    
    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parsear resultados JSON de Semgrep"""
        try:
            if not raw_output.strip():
                return []
            
            data = json.loads(raw_output)
            findings = []
            
            for result in data.get("results", []):
                finding = {
                    "tool": self.name,
                    "severity": self._map_severity(result.get("extra", {}).get("severity", "info")),
                    "category": result.get("check_id", "Unknown"),
                    "description": result.get("extra", {}).get("message", "No description"),
                    "location": f"{result.get('path', 'Unknown')}:{result.get('start', {}).get('line', 0)}",
                    "solution": result.get("extra", {}).get("fix", "No solution provided"),
                    "cve_id": None
                }
                findings.append(finding)
            
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Semgrep JSON: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Error processing Semgrep results: {str(e)}")
            return []
    
    def _map_severity(self, semgrep_severity: str) -> str:
        """Mapear severidades de Semgrep a nuestro estándar"""
        mapping = {
            "ERROR": "high",
            "WARNING": "medium",
            "INFO": "low"
        }
        return mapping.get(semgrep_severity.upper(), "info")

class TrivyScanner(SecurityScanner):
    """Scanner para dependencias (SCA) e imágenes Docker usando Trivy"""
    
    def __init__(self):
        super().__init__()
        self.name = "Trivy"
    
    def scan(self, target: str, scan_type: str) -> Dict[str, Any]:
        """Ejecutar escaneo con Trivy"""
        try:
            if scan_type == "sca":
                return self._scan_dependencies(target)
            elif scan_type == "docker":
                return self._scan_docker_image(target)
            else:
                return {
                    "status": "error",
                    "message": f"Unsupported scan type for Trivy: {scan_type}",
                    "findings": []
                }
                
        except Exception as e:
            logger.error(f"Trivy scan error: {str(e)}")
            return {
                "status": "error",
                "message": f"Trivy scan failed: {str(e)}",
                "findings": []
            }
    
    def _scan_dependencies(self, target: str) -> Dict[str, Any]:
        """Escanear dependencias en un directorio"""
        cmd = [
            "trivy",
            "fs",
            "--format", "json",
            "--quiet",
            target
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            return {
                "status": "error",
                "message": f"Trivy dependency scan failed: {result.stderr}",
                "findings": []
            }
        
        findings = self.parse_results(result.stdout)
        
        return {
            "status": "completed",
            "tool": self.name,
            "findings": findings,
            "summary": {
                "total_findings": len(findings),
                "critical": len([f for f in findings if f.get("severity") == "critical"]),
                "high": len([f for f in findings if f.get("severity") == "high"]),
                "medium": len([f for f in findings if f.get("severity") == "medium"]),
                "low": len([f for f in findings if f.get("severity") == "low"])
            }
        }
    
    def _scan_docker_image(self, image_name: str) -> Dict[str, Any]:
        """Escanear imagen Docker"""
        cmd = [
            "trivy",
            "image",
            "--format", "json",
            "--quiet",
            image_name
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # Las imágenes pueden tardar más
        )
        
        if result.returncode != 0:
            return {
                "status": "error",
                "message": f"Trivy image scan failed: {result.stderr}",
                "findings": []
            }
        
        findings = self.parse_results(result.stdout)
        
        return {
            "status": "completed",
            "tool": self.name,
            "findings": findings,
            "summary": {
                "total_findings": len(findings),
                "critical": len([f for f in findings if f.get("severity") == "critical"]),
                "high": len([f for f in findings if f.get("severity") == "high"]),
                "medium": len([f for f in findings if f.get("severity") == "medium"]),
                "low": len([f for f in findings if f.get("severity") == "low"])
            }
        }
    
    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parsear resultados JSON de Trivy"""
        try:
            if not raw_output.strip():
                return []
            
            data = json.loads(raw_output)
            findings = []
            
            # Trivy puede retornar múltiples resultados
            results = data.get("Results", [])
            if not results:
                return []
            
            for result in results:
                vulnerabilities = result.get("Vulnerabilities", [])
                target = result.get("Target", "Unknown")
                
                for vuln in vulnerabilities:
                    finding = {
                        "tool": self.name,
                        "severity": vuln.get("Severity", "unknown").lower(),
                        "category": "Dependency Vulnerability",
                        "description": vuln.get("Description", vuln.get("Title", "No description")),
                        "location": f"{target} - {vuln.get('PkgName', 'Unknown package')}",
                        "solution": vuln.get("FixedVersion", "No fix available"),
                        "cve_id": vuln.get("VulnerabilityID", None)
                    }
                    findings.append(finding)
            
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Trivy JSON: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Error processing Trivy results: {str(e)}")
            return []

class GitleaksScanner(SecurityScanner):
    """Scanner para secretos usando Gitleaks"""
    
    def __init__(self):
        super().__init__()
        self.name = "Gitleaks"
    
    def scan(self, target: str, scan_type: str = "secrets") -> Dict[str, Any]:
        """Ejecutar escaneo de secretos con Gitleaks"""
        try:
            # Crear archivo temporal para resultados
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                temp_path = temp_file.name
            
            cmd = [
                "gitleaks",
                "detect",
                "--source", target,
                "--report-format", "json",
                "--report-path", temp_path,
                "--no-git"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Gitleaks retorna código 1 si encuentra secretos, esto es normal
            if result.returncode not in [0, 1]:
                os.unlink(temp_path)
                return {
                    "status": "error",
                    "message": f"Gitleaks scan failed: {result.stderr}",
                    "findings": []
                }
            
            # Leer resultados del archivo temporal
            findings = []
            if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                with open(temp_path, 'r') as f:
                    raw_output = f.read()
                findings = self.parse_results(raw_output)
            
            # Limpiar archivo temporal
            os.unlink(temp_path)
            
            return {
                "status": "completed",
                "tool": self.name,
                "findings": findings,
                "summary": {
                    "total_findings": len(findings),
                    "critical": len([f for f in findings if f.get("severity") == "critical"]),
                    "high": len([f for f in findings if f.get("severity") == "high"]),
                    "medium": len([f for f in findings if f.get("severity") == "medium"]),
                    "low": len([f for f in findings if f.get("severity") == "low"])
                }
            }
            
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "message": "Gitleaks scan timed out",
                "findings": []
            }
        except Exception as e:
            logger.error(f"Gitleaks scan error: {str(e)}")
            return {
                "status": "error",
                "message": f"Gitleaks scan failed: {str(e)}",
                "findings": []
            }
    
    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parsear resultados JSON de Gitleaks"""
        try:
            if not raw_output.strip():
                return []
            
            data = json.loads(raw_output)
            findings = []
            
            # Gitleaks retorna una lista de secretos encontrados
            if isinstance(data, list):
                for secret in data:
                    finding = {
                        "tool": self.name,
                        "severity": "high",  # Los secretos siempre son de alta severidad
                        "category": "Secret Exposure",
                        "description": f"Secret detected: {secret.get('Description', 'Unknown secret type')}",
                        "location": f"{secret.get('File', 'Unknown')}:{secret.get('StartLine', 0)}",
                        "solution": "Remove or encrypt the secret, rotate if necessary",
                        "cve_id": None
                    }
                    findings.append(finding)
            
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Gitleaks JSON: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Error processing Gitleaks results: {str(e)}")
            return []

# Factory para crear escáneres
class ScannerFactory:
    """Factory para crear instancias de escáneres"""
    
    @staticmethod
    def create_scanner(scan_type: str) -> SecurityScanner:
        """Crear scanner apropiado según el tipo de escaneo"""
        if scan_type == "sast":
            return SemgrepScanner()
        elif scan_type in ["sca", "docker"]:
            return TrivyScanner()
        elif scan_type == "secrets":
            return GitleaksScanner()
        else:
            raise ValueError(f"Unsupported scan type: {scan_type}")

