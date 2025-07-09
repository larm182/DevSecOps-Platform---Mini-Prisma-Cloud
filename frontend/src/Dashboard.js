import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import './Dashboard.css';

const API_BASE_URL = 'http://localhost:8000';

const COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#65a30d',
  info: '#0891b2'
};

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 5000); // Actualizar cada 5 segundos
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [statsResponse, scansResponse] = await Promise.all([
        axios.get(`${API_BASE_URL}/api/dashboard/stats`),
        axios.get(`${API_BASE_URL}/api/scans`)
      ]);
      
      setStats(statsResponse.data);
      setScans(scansResponse.data);
      setLoading(false);
    } catch (err) {
      setError('Error fetching dashboard data');
      setLoading(false);
    }
  };

  const formatSeverityData = (severityDistribution) => {
    return Object.entries(severityDistribution).map(([severity, count]) => ({
      name: severity.charAt(0).toUpperCase() + severity.slice(1),
      value: count,
      color: COLORS[severity]
    }));
  };

  const formatScanTypesData = (scanTypes) => {
    return Object.entries(scanTypes).map(([type, count]) => ({
      name: type.toUpperCase(),
      count: count
    }));
  };

  if (loading) {
    return (
      <div className="dashboard-loading">
        <div className="spinner"></div>
        <p>Cargando dashboard...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="dashboard-error">
        <h2>Error</h2>
        <p>{error}</p>
        <button onClick={fetchDashboardData}>Reintentar</button>
      </div>
    );
  }

  const severityData = formatSeverityData(stats.severity_distribution);
  const scanTypesData = formatScanTypesData(stats.scan_types);
  const totalFindings = Object.values(stats.severity_distribution).reduce((a, b) => a + b, 0);

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>DevSecOps Platform Dashboard</h1>
        <p>Monitoreo de seguridad en tiempo real</p>
      </header>

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total de Escaneos</h3>
          <div className="stat-number">{stats.total_scans}</div>
        </div>
        
        <div className="stat-card">
          <h3>Total de Hallazgos</h3>
          <div className="stat-number">{totalFindings}</div>
        </div>
        
        <div className="stat-card critical">
          <h3>Críticos</h3>
          <div className="stat-number">{stats.severity_distribution.critical}</div>
        </div>
        
        <div className="stat-card high">
          <h3>Altos</h3>
          <div className="stat-number">{stats.severity_distribution.high}</div>
        </div>
      </div>

      <div className="charts-grid">
        <div className="chart-container">
          <h3>Distribución por Severidad</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, value }) => `${name}: ${value}`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-container">
          <h3>Escaneos por Tipo</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={scanTypesData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="recent-scans">
        <h3>Escaneos Recientes</h3>
        <div className="scans-table">
          <table>
            <thead>
              <tr>
                <th>Tipo</th>
                <th>Target</th>
                <th>Estado</th>
                <th>Hallazgos</th>
                <th>Fecha</th>
              </tr>
            </thead>
            <tbody>
              {scans.slice(0, 10).map((scan) => (
                <tr key={scan.scan_id}>
                  <td>
                    <span className={`scan-type ${scan.scan_type}`}>
                      {scan.scan_type.toUpperCase()}
                    </span>
                  </td>
                  <td className="target-cell">{scan.target}</td>
                  <td>
                    <span className={`status ${scan.status}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td>{scan.findings_count}</td>
                  <td>{new Date(scan.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

