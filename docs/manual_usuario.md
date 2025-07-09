# Manual de Usuario - Plataforma DevSecOps All-in-One

## Introducción

Bienvenido a la Plataforma DevSecOps All-in-One, una solución integral de análisis de seguridad diseñada para automatizar la detección de vulnerabilidades en aplicaciones y sistemas. Este manual le guiará a través de todas las funcionalidades de la plataforma, desde la configuración inicial hasta el uso avanzado de características especializadas.

La plataforma proporciona cuatro tipos principales de análisis de seguridad: análisis estático de código fuente (SAST), análisis de dependencias (SCA), evaluación de imágenes Docker, y detección de secretos hardcodeados. Cada tipo de análisis utiliza herramientas especializadas líderes en la industria para proporcionar resultados precisos y accionables.

## Primeros Pasos

### Acceso a la Plataforma

Para acceder a la plataforma, abra su navegador web y navegue a la URL proporcionada por su administrador de sistemas. La interfaz principal mostrará el dashboard con estadísticas generales de seguridad y acceso a todas las funcionalidades principales.

La navegación principal incluye tres secciones principales:
- **Dashboard**: Vista general con métricas y estadísticas
- **Nuevo Escaneo**: Formulario para iniciar análisis de seguridad
- **Resultados**: Visualización detallada de hallazgos de seguridad

### Dashboard Principal

El dashboard proporciona una vista consolidada del estado de seguridad de sus proyectos. Las métricas principales incluyen:

**Total de Escaneos**: Número total de análisis ejecutados en el sistema
**Total de Hallazgos**: Suma de todas las vulnerabilidades detectadas
**Críticos**: Número de vulnerabilidades de severidad crítica que requieren atención inmediata
**Altos**: Vulnerabilidades de alta severidad que deben ser priorizadas

Los gráficos interactivos muestran la distribución de vulnerabilidades por severidad y la frecuencia de diferentes tipos de escaneos. Esta información le ayuda a identificar tendencias y áreas que requieren mayor atención de seguridad.

## Tipos de Escaneo

### Análisis Estático de Código Fuente (SAST)

El análisis SAST examina el código fuente de sus aplicaciones para identificar vulnerabilidades de seguridad sin ejecutar el programa. Este tipo de análisis es especialmente efectivo para detectar:

- Vulnerabilidades de inyección SQL
- Cross-site scripting (XSS)
- Problemas de validación de entrada
- Uso inseguro de funciones criptográficas
- Configuraciones de seguridad incorrectas

Para ejecutar un análisis SAST:
1. Navegue a la sección "Nuevo Escaneo"
2. Seleccione "SAST" como tipo de escaneo
3. Proporcione la ruta al archivo o directorio de código fuente
4. Haga clic en "Iniciar Escaneo"

El sistema procesará automáticamente el código y generará un reporte detallado con todas las vulnerabilidades detectadas, incluyendo la ubicación exacta del problema y recomendaciones para su corrección.

### Análisis de Dependencias (SCA)

El análisis SCA evalúa las bibliotecas y dependencias de terceros utilizadas en sus proyectos para identificar vulnerabilidades conocidas. Este análisis es crucial porque la mayoría de aplicaciones modernas dependen extensivamente de componentes de código abierto.

El análisis SCA puede detectar:
- Vulnerabilidades conocidas en bibliotecas de terceros
- Dependencias obsoletas con problemas de seguridad
- Licencias incompatibles o problemáticas
- Configuraciones inseguras en dependencias

Para ejecutar un análisis SCA:
1. Seleccione "SCA" como tipo de escaneo
2. Proporcione la ruta al archivo de dependencias (requirements.txt, package.json, etc.)
3. El sistema analizará automáticamente todas las dependencias listadas

### Análisis de Imágenes Docker

Este tipo de análisis evalúa imágenes de contenedores Docker para identificar vulnerabilidades en el sistema operativo base, bibliotecas del sistema, y configuraciones inseguras.

El análisis de imágenes Docker incluye:
- Escaneo de vulnerabilidades en capas del sistema operativo
- Análisis de bibliotecas y paquetes instalados
- Detección de configuraciones inseguras
- Identificación de secretos en capas de imagen

Para analizar una imagen Docker:
1. Seleccione "Docker" como tipo de escaneo
2. Ingrese el nombre de la imagen (ej: nginx:latest, myapp:v1.0)
3. El sistema descargará y analizará automáticamente la imagen

### Detección de Secretos

La detección de secretos identifica credenciales, tokens de API, contraseñas y otros datos sensibles que podrían haber sido inadvertidamente incluidos en el código fuente o archivos de configuración.

Este análisis puede detectar:
- Claves de API hardcodeadas
- Contraseñas en texto plano
- Tokens de autenticación
- Certificados y claves privadas
- Cadenas de conexión de base de datos

Para ejecutar detección de secretos:
1. Seleccione "Secrets" como tipo de escaneo
2. Proporcione la ruta al archivo o directorio a analizar
3. El sistema escaneará todos los archivos en busca de patrones de secretos conocidos

## Interpretación de Resultados

### Niveles de Severidad

Los resultados de escaneos se clasifican en cuatro niveles de severidad:

**Crítico**: Vulnerabilidades que pueden ser explotadas remotamente sin autenticación y que podrían resultar en compromiso completo del sistema. Estas vulnerabilidades requieren corrección inmediata.

**Alto**: Vulnerabilidades significativas que podrían permitir acceso no autorizado o compromiso parcial del sistema. Deben ser priorizadas para corrección en el próximo ciclo de desarrollo.

**Medio**: Vulnerabilidades que representan riesgos moderados y que deben ser corregidas como parte del mantenimiento regular de seguridad.

**Bajo**: Problemas menores de seguridad o mejores prácticas que deben ser considerados para futuras mejoras.

### Información Detallada de Vulnerabilidades

Cada vulnerabilidad detectada incluye información detallada:

- **Descripción**: Explicación clara del problema de seguridad
- **Ubicación**: Archivo específico y número de línea donde se encuentra el problema
- **Severidad**: Nivel de riesgo asociado con la vulnerabilidad
- **Categoría**: Tipo de vulnerabilidad (ej: SQL Injection, XSS, etc.)
- **Solución**: Recomendaciones específicas para corregir el problema
- **CVE ID**: Identificador de vulnerabilidad común cuando aplique

### Exportación de Resultados

Los resultados pueden ser exportados en múltiples formatos para facilitar la integración con otros sistemas y procesos:

- **JSON**: Formato estructurado para integración programática
- **PDF**: Reporte formateado para presentaciones y documentación
- **CSV**: Datos tabulares para análisis en hojas de cálculo

## Sistema de Alertas

### Configuración de Alertas

El sistema de alertas puede ser configurado para notificar automáticamente cuando se detectan vulnerabilidades críticas. Las alertas pueden ser enviadas a través de múltiples canales:

**Discord**: Notificaciones en tiempo real a canales de Discord específicos
**Slack**: Mensajes automáticos a canales de Slack del equipo
**Email**: Notificaciones por correo electrónico a listas de distribución

### Criterios de Alerta

Las alertas se activan automáticamente cuando:
- Se detecta al menos una vulnerabilidad de severidad crítica
- Se detectan más de 5 vulnerabilidades de severidad alta en un solo escaneo
- Se encuentran secretos hardcodeados en el código fuente

### Personalización de Mensajes

Los mensajes de alerta incluyen información contextual relevante:
- Resumen de vulnerabilidades por severidad
- Detalles de las vulnerabilidades más críticas
- Información del proyecto y tipo de escaneo
- Enlaces directos a resultados detallados

## Mejores Prácticas

### Frecuencia de Escaneos

Para obtener máximo beneficio de la plataforma, se recomienda:

- Ejecutar análisis SAST en cada commit o pull request
- Realizar análisis SCA semanalmente o cuando se actualicen dependencias
- Escanear imágenes Docker antes de deployment a producción
- Ejecutar detección de secretos en cada push al repositorio

### Integración con CI/CD

La plataforma puede ser integrada con pipelines de CI/CD utilizando la API REST. Esto permite automatizar completamente los análisis de seguridad como parte del proceso de desarrollo.

### Gestión de Falsos Positivos

Cuando encuentre resultados que considera falsos positivos:
1. Verifique cuidadosamente que realmente no representa un riesgo
2. Documente la razón por la cual considera que es un falso positivo
3. Considere implementar controles compensatorios si es apropiado
4. Revise periódicamente las excepciones para asegurar que siguen siendo válidas

### Priorización de Correcciones

Para priorizar efectivamente las correcciones:
1. Corrija primero todas las vulnerabilidades críticas
2. Priorice vulnerabilidades altas en componentes expuestos públicamente
3. Considere el contexto de uso al evaluar el riesgo real
4. Implemente controles de mitigación temporales cuando la corrección completa requiera tiempo significativo

## Solución de Problemas

### Problemas Comunes

**Error de Archivo No Encontrado**: Verifique que la ruta proporcionada sea correcta y que el archivo sea accesible

**Timeout de Escaneo**: Para proyectos grandes, el análisis puede tomar tiempo considerable. Considere dividir el análisis en componentes más pequeños

**Resultados Vacíos**: Verifique que el tipo de escaneo sea apropiado para el contenido analizado

### Contacto de Soporte

Para asistencia técnica adicional, contacte al equipo de soporte proporcionando:
- Descripción detallada del problema
- Pasos para reproducir el issue
- Logs relevantes del sistema
- Información del entorno (navegador, sistema operativo, etc.)

