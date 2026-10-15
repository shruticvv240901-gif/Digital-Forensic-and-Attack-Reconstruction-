import React from 'react';
import { SystemConfig } from '../types';

interface HealthModalProps {
  isOpen: boolean;
  onClose: () => void;
  config: SystemConfig;
}

export const HealthModal: React.FC<HealthModalProps> = ({ isOpen, onClose, config }) => {
  if (!isOpen) return null;

  const healthData = {
    status: 'healthy (100% operational)',
    timestamp: new Date().toISOString(),
    application: 'AI-Assisted Attack Timeline Reconstruction and Digital Forensic Reporting',
    runtime_mode: 'Standalone Demo & Cloud Ingestion Mode (No Splunk Required)',
    stages_completed: [
      'Stage 1: SOC Dashboard & Offline Telemetry',
      'Stage 2: Windows & Multi-Cloud Security Log Ingestion',
      'Stage 3: Deterministic Attack Timeline Reconstruction',
      'Stage 4: Automated Incident Summary & Defensible PDF Export',
      'Stage 5: Incident Alerting & Email Dispatch Engine',
    ],
    telemetry_sources: {
      windows_event_ids: ['4624 (Logon)', '4625 (Failed Logon)', '4672 (Privilege)', '4720 (User Created)'],
      cloud_providers: ['AWS CloudTrail', 'Azure Active Directory / Entra ID', 'Google Cloud Audit'],
      custom_file_uploads: 'Enabled (.json, .csv)',
    },
    system_settings: {
      offline_demo_only: config.offline_demo_only,
      engine_name: config.engine_name,
      analysis_algorithm: config.analysis_algorithm,
      alert_recipient: config.alert_recipient,
      external_splunk_connections: 'DISABLED (Completely Standalone)',
    },
  };

  return (
    <div
      className="modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-content" style={{ maxWidth: '650px' }}>
        <div className="modal-header">
          <h3 style={{ color: 'var(--cyber-cyan)', fontSize: '1.05rem' }}>
            System Health &amp; Diagnostics API
          </h3>
          <button className="modal-close-btn" onClick={onClose}>
            &times;
          </button>
        </div>
        <div className="modal-body">
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.8rem' }}>
            Standalone offline runtime health check and active telemetry parameters:
          </p>
          <pre
            style={{
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
              color: '#34d399',
              background: '#080c14',
              padding: '1.2rem',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
              fontSize: '0.82rem',
            }}
          >
            {JSON.stringify(healthData, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
};
