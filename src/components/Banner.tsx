import React from 'react';

export const Banner: React.FC = () => {
  return (
    <div className="system-banner banner-demo">
      <div className="banner-info">
        <span className="badge-pulse"></span>
        <span>
          <strong>OFFLINE FORENSIC SIMULATION MODE ACTIVE</strong> &mdash; Operating exclusively on high-fidelity security log datasets. Zero Splunk license or external API required.
        </span>
      </div>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
        DEMO_ONLY=True (100% Offline)
      </span>
    </div>
  );
};
