# DevSecOps Platform - Mini Prisma Cloud

Una plataforma completa de DevSecOps que automatiza el escaneo de vulnerabilidades en código fuente, dependencias, imágenes Docker y secretos.

## 🚀 Inicio Rápido con Docker

### Prerrequisitos
- Docker 20.10+
- Docker Compose 2.0+

### Deployment
```bash
# Clonar el repositorio
git clone <repository-url>
cd devsecops_platform

# Ejecutar deployment automatizado
./deploy.sh
```

### Acceso a la Aplicación
- **Dashboard**: http://localhost:3000
- **API Backend**: http://localhost:8000
- **Documentación API**: http://localhost:8000/docs

## 🛠️ Desarrollo Local

### Backend (FastAPI)
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
uvicorn main:app --reload
```

### Frontend (React)
```bash
cd frontend
npm install
npm start
```

## 🔧 Configuración

### Variables de Entorno
Crear archivo `.env` en el directorio raíz:
```env
# Webhooks de alertas
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# Base de datos (opcional para PostgreSQL)
DATABASE_URL=postgresql://user:password@localhost/devsecops
```

### Configuración de Alertas
1. **Discord**: Crear webhook en tu servidor de Discord
2. **Slack**: Crear webhook en tu workspace de Slack
3. Actualizar las URLs en el archivo de configuración

## 📊 Funcionalidades

### Tipos de Escaneo
- **SAST**: Análisis estático de código fuente (Semgrep)
- **SCA**: Análisis de dependencias (Trivy)
- **Docker**: Análisis de imágenes de contenedores (Trivy)
- **Secrets**: Detección de secretos hardcodeados (Gitleaks)

### Dashboard
- Estadísticas en tiempo real
- Gráficos de distribución por severidad
- Historial de escaneos
- Alertas centralizadas

### Sistema de Alertas
- Notificaciones automáticas para vulnerabilidades críticas
- Soporte para Discord, Slack y consola
- Formato rico con detalles de vulnerabilidades

## 🐳 Comandos Docker

```bash
# Construir imágenes
docker-compose build

# Iniciar servicios
docker-compose up -d

# Ver logs
docker-compose logs -f

# Detener servicios
docker-compose down

# Reiniciar servicios
docker-compose restart
```

## 🔍 API Endpoints

### Escaneos
- `POST /api/scan` - Iniciar nuevo escaneo
- `GET /api/scan/{scan_id}` - Obtener resultado de escaneo
- `GET /api/scans` - Listar todos los escaneos

### Dashboard
- `GET /api/dashboard/stats` - Estadísticas del dashboard

### Archivos
- `POST /api/upload` - Subir archivo para escaneo

### Alertas
- `POST /api/test-alert` - Probar sistema de alertas

## 🛡️ Herramientas de Seguridad

### Semgrep
- Análisis estático de código
- Detección de vulnerabilidades comunes
- Soporte para múltiples lenguajes

### Trivy
- Escaneo de dependencias
- Análisis de imágenes Docker
- Base de datos de CVEs actualizada

### Gitleaks
- Detección de secretos
- Análisis de repositorios Git
- Patrones configurables

## 📈 Monitoreo

### Health Checks
Los servicios incluyen health checks automáticos:
- Backend: `GET /`
- Frontend: Verificación de nginx

### Logs
```bash
# Ver logs del backend
docker-compose logs backend

# Ver logs del frontend
docker-compose logs frontend

# Ver todos los logs
docker-compose logs
```

## 🔧 Troubleshooting

### Problemas Comunes

1. **Puerto ocupado**
   ```bash
   # Cambiar puertos en docker-compose.yml
   ports:
     - "8001:8000"  # Backend
     - "3001:80"    # Frontend
   ```

2. **Permisos de Docker**
   ```bash
   sudo usermod -aG docker $USER
   # Reiniciar sesión
   ```

3. **Espacio en disco**
   ```bash
   # Limpiar imágenes no utilizadas
   docker system prune -a
   ```

## 🚀 Deployment en Producción

### Consideraciones
- Usar PostgreSQL en lugar de SQLite
- Configurar HTTPS con certificados SSL
- Implementar autenticación y autorización
- Configurar backup de base de datos
- Monitoreo con Prometheus/Grafana

### Variables de Entorno de Producción
```env
ENVIRONMENT=production
DATABASE_URL=postgresql://user:password@postgres:5432/devsecops
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/REAL_WEBHOOK
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/REAL/SLACK/WEBHOOK
```


## 🤝 Contribución

1. Fork el proyecto
2. Crear rama de feature (`git checkout -b feature/AmazingFeature`)
3. Commit cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abrir Pull Request

## 📞 Soporte

Para soporte y preguntas:
- Crear issue en GitHub
- Documentación: http://localhost:8000/docs
- Logs: `docker-compose logs`
