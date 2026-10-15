import React from 'react';

interface NavbarProps {
  currentTab: 'dashboard' | 'settings';
  setCurrentTab: (tab: 'dashboard' | 'settings') => void;
  onOpenHealth: () => void;
  onOpenUpload: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  setCurrentTab,
  onOpenHealth,
  onOpenUpload,
}) => {
  return (
    <header className="cyber-navbar">
      <div className="brand-container" onClick={() => setCurrentTab('dashboard')} style={{ cursor: 'pointer' }}>
        <div className="brand-icon">🛡️</div>
        <div className="brand-text">
          <h1>AI FORENSICS // TIMELINE ENGINE</h1>
          <p>Attack Timeline Reconstruction &amp; Digital Forensic Reporting</p>
        </div>
      </div>
      <nav className="nav-links" style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        <button
          className={`nav-link ${currentTab === 'dashboard' ? 'active' : ''}`}
          onClick={() => setCurrentTab('dashboard')}
        >
          SOC Dashboard
        </button>

        <button
          className="nav-link"
          onClick={onOpenUpload}
          title="Upload custom CSV/JSON log file or download sample attack dataset"
        >
          📁 Upload Logs
        </button>

        <button
          className={`nav-link ${currentTab === 'settings' ? 'active' : ''}`}
          onClick={() => setCurrentTab('settings')}
        >
          Configuration
        </button>

        <button className="nav-link" onClick={onOpenHealth} title="Check local forensic engine diagnostics">
          Health API
        </button>
      </nav>
    </header>
  );
};

