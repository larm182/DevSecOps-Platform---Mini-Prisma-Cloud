import requests
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class AlertManager:
    """Gestor de alertas para notificaciones de vulnerabilidades críticas"""
    
    def __init__(self):
        self.discord_webhook_url = None
        self.slack_webhook_url = None
        self.email_config = None
        
        # Configurar URLs de webhook desde variables de entorno o configuración
        # En producción, estas deberían venir de variables de entorno
        self.discord_webhook_url = "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"
        self.slack_webhook_url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    
    def should_alert(self, findings: List[Dict]) -> bool:
        """Determinar si se debe enviar una alerta basada en los hallazgos"""
        critical_count = len([f for f in findings if f.get("severity") == "critical"])
        high_count = len([f for f in findings if f.get("severity") == "high"])
        
        # Enviar alerta si hay vulnerabilidades críticas o más de 5 altas
        return critical_count > 0 or high_count > 5
    
    def format_alert_message(self, scan_data: Dict, findings: List[Dict]) -> Dict:
        """Formatear mensaje de alerta"""
        critical_count = len([f for f in findings if f.get("severity") == "critical"])
        high_count = len([f for f in findings if f.get("severity") == "high"])
        medium_count = len([f for f in findings if f.get("severity") == "medium"])
        
        severity_summary = []
        if critical_count > 0:
            severity_summary.append(f"🔴 {critical_count} Críticas")
        if high_count > 0:
            severity_summary.append(f"🟠 {high_count} Altas")
        if medium_count > 0:
            severity_summary.append(f"🟡 {medium_count} Medias")
        
        severity_text = " | ".join(severity_summary) if severity_summary else "Sin vulnerabilidades críticas"
        
        # Obtener las vulnerabilidades más críticas para mostrar
        critical_findings = [f for f in findings if f.get("severity") == "critical"][:3]
        high_findings = [f for f in findings if f.get("severity") == "high"][:2]
        
        findings_text = ""
        if critical_findings:
            findings_text += "**Vulnerabilidades Críticas:**\n"
            for finding in critical_findings:
                findings_text += f"• {finding.get('category', 'Unknown')}: {finding.get('description', 'No description')[:100]}...\n"
        
        if high_findings and len(findings_text) < 1500:  # Limitar longitud del mensaje
            findings_text += "\n**Vulnerabilidades Altas:**\n"
            for finding in high_findings:
                findings_text += f"• {finding.get('category', 'Unknown')}: {finding.get('description', 'No description')[:100]}...\n"
        
        return {
            "title": f"🚨 Alerta de Seguridad - {scan_data.get('scan_type', 'Unknown').upper()}",
            "description": f"Se han detectado vulnerabilidades en el escaneo de {scan_data.get('target', 'Unknown')}",
            "severity_summary": severity_text,
            "findings_detail": findings_text,
            "scan_id": scan_data.get('scan_id'),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def send_discord_alert(self, alert_data: Dict) -> bool:
        """Enviar alerta a Discord"""
        if not self.discord_webhook_url or "YOUR_WEBHOOK" in self.discord_webhook_url:
            logger.warning("Discord webhook URL not configured")
            return False
        
        try:
            embed = {
                "title": alert_data["title"],
                "description": alert_data["description"],
                "color": 15158332,  # Color rojo
                "fields": [
                    {
                        "name": "Resumen de Severidades",
                        "value": alert_data["severity_summary"],
                        "inline": False
                    },
                    {
                        "name": "Scan ID",
                        "value": alert_data["scan_id"],
                        "inline": True
                    },
                    {
                        "name": "Timestamp",
                        "value": alert_data["timestamp"],
                        "inline": True
                    }
                ],
                "footer": {
                    "text": "DevSecOps Platform - Mini Prisma Cloud"
                }
            }
            
            if alert_data["findings_detail"]:
                embed["fields"].append({
                    "name": "Detalles de Vulnerabilidades",
                    "value": alert_data["findings_detail"][:1024],  # Discord limit
                    "inline": False
                })
            
            payload = {
                "embeds": [embed]
            }
            
            response = requests.post(
                self.discord_webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 204:
                logger.info("Discord alert sent successfully")
                return True
            else:
                logger.error(f"Failed to send Discord alert: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending Discord alert: {str(e)}")
            return False
    
    def send_slack_alert(self, alert_data: Dict) -> bool:
        """Enviar alerta a Slack"""
        if not self.slack_webhook_url or "YOUR/SLACK" in self.slack_webhook_url:
            logger.warning("Slack webhook URL not configured")
            return False
        
        try:
            payload = {
                "text": alert_data["title"],
                "attachments": [
                    {
                        "color": "danger",
                        "fields": [
                            {
                                "title": "Descripción",
                                "value": alert_data["description"],
                                "short": False
                            },
                            {
                                "title": "Severidades",
                                "value": alert_data["severity_summary"],
                                "short": True
                            },
                            {
                                "title": "Scan ID",
                                "value": alert_data["scan_id"],
                                "short": True
                            }
                        ],
                        "footer": "DevSecOps Platform",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
            
            if alert_data["findings_detail"]:
                payload["attachments"][0]["fields"].append({
                    "title": "Vulnerabilidades Detectadas",
                    "value": alert_data["findings_detail"][:2000],  # Slack limit
                    "short": False
                })
            
            response = requests.post(
                self.slack_webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Slack alert sent successfully")
                return True
            else:
                logger.error(f"Failed to send Slack alert: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending Slack alert: {str(e)}")
            return False
    
    def send_console_alert(self, alert_data: Dict) -> bool:
        """Enviar alerta a la consola (para testing)"""
        try:
            print("\n" + "="*60)
            print(f"🚨 {alert_data['title']}")
            print("="*60)
            print(f"📝 {alert_data['description']}")
            print(f"📊 {alert_data['severity_summary']}")
            print(f"🆔 Scan ID: {alert_data['scan_id']}")
            print(f"⏰ Timestamp: {alert_data['timestamp']}")
            
            if alert_data["findings_detail"]:
                print("\n📋 Detalles de Vulnerabilidades:")
                print(alert_data["findings_detail"])
            
            print("="*60)
            logger.info("Console alert sent successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error sending console alert: {str(e)}")
            return False
    
    def send_alert(self, scan_data: Dict, findings: List[Dict]) -> Dict[str, bool]:
        """Enviar alertas a todos los canales configurados"""
        if not self.should_alert(findings):
            logger.info("No critical vulnerabilities found, skipping alert")
            return {"alert_sent": False, "reason": "No critical vulnerabilities"}
        
        alert_data = self.format_alert_message(scan_data, findings)
        
        results = {
            "discord": self.send_discord_alert(alert_data),
            "slack": self.send_slack_alert(alert_data),
            "console": self.send_console_alert(alert_data)
        }
        
        logger.info(f"Alert results: {results}")
        return {
            "alert_sent": any(results.values()),
            "channels": results,
            "alert_data": alert_data
        }

# Instancia global del gestor de alertas
alert_manager = AlertManager()

