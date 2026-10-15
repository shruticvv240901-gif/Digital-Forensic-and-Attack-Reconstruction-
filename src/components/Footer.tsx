import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer className="cyber-footer">
      <div>
        <strong>AI-Assisted Automated Attack Timeline Reconstruction</strong> &bull; Offline Forensics &amp; Incident Reporting
      </div>
      <div style={{ fontFamily: 'var(--font-mono)' }}>
        Mode: 100% Standalone (Offline Demo Telemetry)
      </div>
    </footer>
  );
};
