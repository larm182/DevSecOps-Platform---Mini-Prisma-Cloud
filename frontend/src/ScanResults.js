import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './ScanResults.css';

const API_BASE_URL = 'http://localhost:8000';

const ScanResults = ({ scanId }) => {
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (scanId) {
      fetchScanResult();
      const interval = setInterval(fetchScanResult, 3000); // Actualizar cada 3 segundos
      return () => clearInterval(interval);
    }
  }, [scanId]);

  const fetchScanResult = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/scan/${scanId}`);
      setScanResult(response.data);
      setLoading(false);
      
      // Si el escaneo está completo, dejar de hacer polling
      if (response.data.status === 'completed' || response.data.status === 'failed') {
        setLoading(false);
      }
    } catch (err) {
      setError('Error fetching scan results');
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#d97706',
      low: '#65a30d',
      info: '#0891b2'
    };
    return colors[severity] || '#6b7280';
  };

  const getSeverityIcon = (severity) => {
    const icons = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      info: '🔵'
    };
    return icons[severity] || '⚪';
  };

  if (!scanId) {
    return (
      <div className="scan-results-empty">
        <p>Selecciona un escaneo para ver los resultados</p>
      </div>
    );
  }

  if (loading && !scanResult) {
    return (
      <div className="scan-results-loading">
        <div className="spinner"></div>
        <p>Cargando resultados del escaneo...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="scan-results-error">
        <h3>Error</h3>
        <p>{error}</p>
        <button onClick={fetchScanResult}>Reintentar</button>
      </div>
    );
  }

  return (
    <div className="scan-results">
      <div className="scan-header">
        <h2>Resultados del Escaneo</h2>
        <div className="scan-info">
          <div className="info-item">
            <strong>ID:</strong> {scanResult.scan_id}
          </div>
          <div className="info-item">
            <strong>Tipo:</strong> 
            <span className={`scan-type ${scanResult.scan_type}`}>
              {scanResult.scan_type.toUpperCase()}
            </span>
          </div>
          <div className="info-item">
            <strong>Target:</strong> {scanResult.target}
          </div>
          <div className="info-item">
            <strong>Estado:</strong>
            <span className={`status ${scanResult.status}`}>
              {scanResult.status}
              {scanResult.status === 'running' && <div className="spinner-inline"></div>}
            </span>
          </div>
          <div className="info-item">
            <strong>Fecha:</strong> {new Date(scanResult.timestamp).toLocaleString()}
          </div>
        </div>
      </div>

      {scanResult.summary && (
        <div className="scan-summary">
          <h3>Resumen</h3>
          <div className="summary-grid">
            <div className="summary-item">
              <span className="summary-label">Total de Hallazgos</span>
              <span className="summary-value">{scanResult.summary.total_findings || 0}</span>
            </div>
            <div className="summary-item critical">
              <span className="summary-label">Críticos</span>
              <span className="summary-value">{scanResult.summary.critical || 0}</span>
            </div>
            <div className="summary-item high">
              <span className="summary-label">Altos</span>
              <span className="summary-value">{scanResult.summary.high || 0}</span>
            </div>
            <div className="summary-item medium">
              <span className="summary-label">Medios</span>
              <span className="summary-value">{scanResult.summary.medium || 0}</span>
            </div>
            <div className="summary-item low">
              <span className="summary-label">Bajos</span>
              <span className="summary-value">{scanResult.summary.low || 0}</span>
            </div>
          </div>
        </div>
      )}

      <div className="findings-section">
        <h3>Hallazgos Detallados</h3>
        {scanResult.findings && scanResult.findings.length > 0 ? (
          <div className="findings-list">
            {scanResult.findings.map((finding, index) => (
              <div key={index} className="finding-card">
                <div className="finding-header">
                  <div className="finding-severity">
                    <span 
                      className="severity-badge"
                      style={{ backgroundColor: getSeverityColor(finding.severity) }}
                    >
                      {getSeverityIcon(finding.severity)} {finding.severity.toUpperCase()}
                    </span>
                  </div>
                  <div className="finding-tool">
                    {finding.tool}
                  </div>
                </div>
                
                <div className="finding-content">
                  <h4>{finding.category || 'Vulnerabilidad'}</h4>
                  <p className="finding-description">{finding.description}</p>
                  
                  {finding.location && (
                    <div className="finding-location">
                      <strong>Ubicación:</strong> {finding.location}
                    </div>
                  )}
                  
                  {finding.cve_id && (
                    <div className="finding-cve">
                      <strong>CVE:</strong> 
                      <a 
                        href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${finding.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="cve-link"
                      >
                        {finding.cve_id}
                      </a>
                    </div>
                  )}
                  
                  {finding.solution && (
                    <div className="finding-solution">
                      <strong>Solución:</strong> {finding.solution}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="no-findings">
            <p>No se encontraron vulnerabilidades en este escaneo.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanResults;

