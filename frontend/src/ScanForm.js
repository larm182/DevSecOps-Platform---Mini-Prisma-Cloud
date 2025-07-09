import React, { useState } from 'react';
import axios from 'axios';
import './ScanForm.css';

const API_BASE_URL = 'http://localhost:8000';

const ScanForm = ({ onScanStarted }) => {
  const [scanType, setScanType] = useState('sast');
  const [target, setTarget] = useState('');
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const scanTypes = [
    { value: 'sast', label: 'SAST - Análisis de Código Fuente', description: 'Busca vulnerabilidades en el código fuente' },
    { value: 'sca', label: 'SCA - Análisis de Dependencias', description: 'Escanea vulnerabilidades en dependencias' },
    { value: 'docker', label: 'Docker - Análisis de Imágenes', description: 'Analiza vulnerabilidades en imágenes Docker' },
    { value: 'secrets', label: 'Secrets - Detección de Secretos', description: 'Busca credenciales y secretos expuestos' }
  ];

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    setFile(selectedFile);
    if (selectedFile) {
      setTarget(selectedFile.name);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      let finalTarget = target;

      // Si hay un archivo, subirlo primero
      if (file) {
        const formData = new FormData();
        formData.append('file', file);

        const uploadResponse = await axios.post(`${API_BASE_URL}/api/upload`, formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        });

        finalTarget = uploadResponse.data.file_path;
      }

      // Iniciar el escaneo
      const scanResponse = await axios.post(`${API_BASE_URL}/api/scan`, {
        scan_type: scanType,
        target: finalTarget
      });

      setMessage(`Escaneo iniciado exitosamente. ID: ${scanResponse.data.scan_id}`);
      
      // Limpiar formulario
      setTarget('');
      setFile(null);
      document.getElementById('file-input').value = '';

      // Notificar al componente padre
      if (onScanStarted) {
        onScanStarted(scanResponse.data);
      }

    } catch (error) {
      setMessage(`Error: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="scan-form-container">
      <div className="scan-form">
        <h2>Iniciar Nuevo Escaneo</h2>
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="scan-type">Tipo de Escaneo</label>
            <select
              id="scan-type"
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="form-select"
            >
              {scanTypes.map((type) => (
                <option key={type.value} value={type.value}>
                  {type.label}
                </option>
              ))}
            </select>
            <p className="form-description">
              {scanTypes.find(t => t.value === scanType)?.description}
            </p>
          </div>

          <div className="form-group">
            <label htmlFor="target">Target</label>
            {scanType === 'docker' ? (
              <input
                id="target"
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Ej: python:3.11, nginx:latest, usuario/imagen:tag"
                className="form-input"
                required
              />
            ) : (
              <>
                <input
                  id="target"
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="Ruta del directorio o archivo"
                  className="form-input"
                />
                <div className="file-upload">
                  <label htmlFor="file-input" className="file-label">
                    O subir archivo/ZIP
                  </label>
                  <input
                    id="file-input"
                    type="file"
                    onChange={handleFileChange}
                    accept=".py,.js,.java,.zip,.tar.gz"
                    className="file-input"
                  />
                </div>
              </>
            )}
          </div>

          <button
            type="submit"
            disabled={loading || (!target && !file)}
            className="submit-button"
          >
            {loading ? (
              <>
                <div className="spinner-small"></div>
                Iniciando Escaneo...
              </>
            ) : (
              'Iniciar Escaneo'
            )}
          </button>
        </form>

        {message && (
          <div className={`message ${message.includes('Error') ? 'error' : 'success'}`}>
            {message}
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanForm;

