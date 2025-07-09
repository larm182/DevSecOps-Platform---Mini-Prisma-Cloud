#!/bin/bash

# Script de deployment para DevSecOps Platform
set -e

echo "🚀 Iniciando deployment de DevSecOps Platform..."

# Verificar que Docker esté instalado
if ! command -v docker &> /dev/null; then
    echo "❌ Docker no está instalado. Por favor instala Docker primero."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose no está instalado. Por favor instala Docker Compose primero."
    exit 1
fi

# Crear directorios necesarios
echo "📁 Creando directorios necesarios..."
mkdir -p backend/uploads backend/logs

# Detener contenedores existentes
echo "🛑 Deteniendo contenedores existentes..."
docker-compose down --remove-orphans

# Construir imágenes
echo "🔨 Construyendo imágenes Docker..."
docker-compose build --no-cache

# Iniciar servicios
echo "🚀 Iniciando servicios..."
docker-compose up -d

# Esperar a que los servicios estén listos
echo "⏳ Esperando a que los servicios estén listos..."
sleep 30

# Verificar estado de los servicios
echo "🔍 Verificando estado de los servicios..."
docker-compose ps

# Verificar conectividad
echo "🌐 Verificando conectividad..."
if curl -f http://localhost:8000/ > /dev/null 2>&1; then
    echo "✅ Backend está funcionando en http://localhost:8000"
else
    echo "❌ Backend no responde"
fi

if curl -f http://localhost:3000/ > /dev/null 2>&1; then
    echo "✅ Frontend está funcionando en http://localhost:3000"
else
    echo "❌ Frontend no responde"
fi

echo ""
echo "🎉 Deployment completado!"
echo ""
echo "📊 Dashboard: http://localhost:3000"
echo "🔧 API Backend: http://localhost:8000"
echo "📚 Documentación API: http://localhost:8000/docs"
echo ""
echo "Para ver logs: docker-compose logs -f"
echo "Para detener: docker-compose down"

