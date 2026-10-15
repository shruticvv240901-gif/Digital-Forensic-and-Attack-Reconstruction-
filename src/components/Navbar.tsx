import React from 'react';

interface NavbarProps {
  currentTab: 'dashboard' | 'settings';
  setCurrentTab: (tab: 'dashboard' | 'settings') => void;
  onOpenHealth: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ currentTab, setCurrentTab, onOpenHealth }) => {
  return (
    <header className="cyber-navbar">
      <div className="brand-container" onClick={() => setCurrentTab('dashboard')}>
        <div className="brand-icon">🛡️</div>
        <div className="brand-text">
          <h1>AI FORENSICS // TIMELINE ENGINE</h1>
          <p>Attack Timeline Reconstruction &amp; Reporting (Offline Demo Mode)</p>
        </div>
      </div>
      <nav className="nav-links">
        <button
          className={`nav-link ${currentTab === 'dashboard' ? 'active' : ''}`}
          onClick={() => setCurrentTab('dashboard')}
        >
          Dashboard
        </button>
        <button
          className={`nav-link ${currentTab === 'settings' ? 'active' : ''}`}
          onClick={() => setCurrentTab('settings')}
        >
          Configuration
        </button>
        <button className="nav-link" onClick={onOpenHealth}>
          Health API
        </button>
      </nav>
    </header>
  );
};
