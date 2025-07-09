## Esquema de la Base de Datos (PostgreSQL/SQLite)

```sql
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL, -- 'sast', 'sca', 'docker', 'secrets'
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    target TEXT NOT NULL, -- Ruta del código, nombre de la imagen, etc.
    status TEXT NOT NULL, -- 'pending', 'running', 'completed', 'failed'
    results_summary JSONB -- Resumen de hallazgos (ej. total de vulnerabilidades por severidad)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    tool TEXT NOT NULL, -- Herramienta que encontró el hallazgo (Semgrep, Trivy, Gitleaks)
    severity TEXT NOT NULL, -- 'critical', 'high', 'medium', 'low', 'info'
    category TEXT, -- Tipo de vulnerabilidad (ej. 'SQL Injection', 'Outdated Dependency')
    description TEXT NOT NULL,
    location TEXT, -- Archivo, línea, capa de Docker, etc.
    solution TEXT, -- Sugerencia de solución
    cve_id TEXT, -- Si aplica (para SCA/Docker)
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```


