import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import Dashboard from './Dashboard';
import ScanForm from './ScanForm';
import ScanResults from './ScanResults';
import './App.css';

function App() {
  const [selectedScanId, setSelectedScanId] = useState(null);

  const handleScanStarted = (scanData) => {
    setSelectedScanId(scanData.scan_id);
  };

  return (
    <Router>
      <div className="App">
        <nav className="navbar">
          <div className="nav-container">
            <Link to="/" className="nav-logo">
              🛡️ DevSecOps Platform
            </Link>
            <div className="nav-links">
              <Link to="/" className="nav-link">Dashboard</Link>
              <Link to="/scan" className="nav-link">Nuevo Escaneo</Link>
              {selectedScanId && (
                <Link to="/results" className="nav-link">Resultados</Link>
              )}
            </div>
          </div>
        </nav>

        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route 
              path="/scan" 
              element={<ScanForm onScanStarted={handleScanStarted} />} 
            />
            <Route 
              path="/results" 
              element={<ScanResults scanId={selectedScanId} />} 
            />
          </Routes>
        </main>

        <footer className="footer">
          <p>&copy; 2024 DevSecOps Platform - Mini Prisma Cloud</p>
        </footer>
      </div>
    </Router>
  );
}

export default App;
