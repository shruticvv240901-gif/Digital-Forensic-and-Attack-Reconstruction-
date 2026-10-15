import React, { useState } from 'react';
import { WindowsEvent, CloudLogSource } from '../types';
import { generateCloudEvents, parseCustomUploadedLogs } from '../services/demoData';

interface CloudImportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onImportEvents: (events: WindowsEvent[], sourceLabel: string) => void;
}

export const CloudImportModal: React.FC<CloudImportModalProps> = ({ isOpen, onClose, onImportEvents }) => {
  const [selectedScenario, setSelectedScenario] = useState<CloudLogSource>('aws_cloudtrail');
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [parsedPreview, setParsedPreview] = useState<WindowsEvent[] | null>(null);

  if (!isOpen) return null;

  const handleImportPrebuilt = () => {
    const events = generateCloudEvents(selectedScenario);
    let label = 'AWS CloudTrail Security Logs';
    if (selectedScenario === 'azure_entra') label = 'Azure Active Directory / Entra ID Logs';
    if (selectedScenario === 'gcp_audit') label = 'Google Cloud Audit Logs';
    if (selectedScenario === 'hybrid_cloud') label = 'Hybrid Active Directory + Cloud Pivot';

    onImportEvents(events, label);
    onClose();
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUploadError(null);
    const file = e.target.files?.[0];
    if (!file) return;

    setUploadedFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const text = String(event.target?.result || '');
        const parsed = parseCustomUploadedLogs(text, file.name);
        if (parsed.length === 0) {
          setUploadError('Could not detect valid event records in this file. Please ensure it is JSON or CSV format.');
          setParsedPreview(null);
        } else {
          setParsedPreview(parsed);
        }
      } catch (err: any) {
        setUploadError(`Parsing error: ${err.message}`);
        setParsedPreview(null);
      }
    };
    reader.readAsText(file);
  };

  const handleApplyUpload = () => {
    if (parsedPreview && parsedPreview.length > 0) {
      onImportEvents(parsedPreview, `Custom Upload (${uploadedFileName})`);
      onClose();
    }
  };

  return (
    <div
      className="modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-content" style={{ maxWidth: '800px' }}>
        <div className="modal-header">
          <h3 style={{ color: 'var(--cyber-cyan)', fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>☁️ Cloud Security Log Integration & Custom Import</span>
          </h3>
          <button className="modal-close-btn" onClick={onClose}>
            &times;
          </button>
        </div>

        <div className="modal-body" style={{ maxHeight: '78vh' }}>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1.2rem', lineHeight: 1.6 }}>
            Ingest real or simulated cloud security telemetry from AWS, Azure Entra ID, GCP, or upload your own forensic log files (JSON / CSV). Zero external paid licenses required.
          </p>

          {/* Tab 1: Pre-Configured Cloud Intrusion Scenarios */}
          <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '1.2rem', marginBottom: '1.5rem' }}>
            <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.8rem' }}>
              Select Cloud Scenario / Provider Dataset:
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginBottom: '1.2rem' }}>
              <div
                onClick={() => setSelectedScenario('aws_cloudtrail')}
                style={{
                  padding: '1rem',
                  borderRadius: '6px',
                  border: `2px solid ${selectedScenario === 'aws_cloudtrail' ? 'var(--cyber-cyan)' : 'var(--border-subtle)'}`,
                  background: selectedScenario === 'aws_cloudtrail' ? 'rgba(0, 240, 255, 0.08)' : 'rgba(0,0,0,0.2)',
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                }}
              >
                <div style={{ fontWeight: 700, color: '#ffffff', marginBottom: '4px' }}>AWS CloudTrail</div>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  Root failed console login, IAM AdministratorAccess privilege escalation, and S3 mass bucket exfiltration.
                </p>
              </div>

              <div
                onClick={() => setSelectedScenario('azure_entra')}
                style={{
                  padding: '1rem',
                  borderRadius: '6px',
                  border: `2px solid ${selectedScenario === 'azure_entra' ? 'var(--cyber-cyan)' : 'var(--border-subtle)'}`,
                  background: selectedScenario === 'azure_entra' ? 'rgba(0, 240, 255, 0.08)' : 'rgba(0,0,0,0.2)',
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                }}
              >
                <div style={{ fontWeight: 700, color: '#ffffff', marginBottom: '4px' }}>Azure Entra ID</div>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  Password spray against Global Admin, CA bypass, and rogue Service Principal backdoor registration.
                </p>
              </div>

              <div
                onClick={() => setSelectedScenario('hybrid_cloud')}
                style={{
                  padding: '1rem',
                  borderRadius: '6px',
                  border: `2px solid ${selectedScenario === 'hybrid_cloud' ? 'var(--cyber-cyan)' : 'var(--border-subtle)'}`,
                  background: selectedScenario === 'hybrid_cloud' ? 'rgba(0, 240, 255, 0.08)' : 'rgba(0,0,0,0.2)',
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                }}
              >
                <div style={{ fontWeight: 700, color: '#ffffff', marginBottom: '4px' }}>Hybrid Enterprise Pivot</div>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  On-Premises AD brute force &amp; rogue account creation pivoting directly into Microsoft Cloud SSO tenant.
                </p>
              </div>
            </div>

            <button onClick={handleImportPrebuilt} className="btn btn-cyber-primary">
              <span>⚡ Load Cloud Security Telemetry</span>
            </button>
          </div>

          {/* Tab 2: Custom Log File Drag & Drop / Upload */}
          <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '1.2rem' }}>
            <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.8rem' }}>
              Import Custom Log File (JSON / CSV):
            </div>

            <div
              style={{
                border: '2px dashed var(--border-glow)',
                borderRadius: '6px',
                padding: '1.5rem',
                textAlign: 'center',
                background: 'rgba(0,0,0,0.2)',
                marginBottom: '1rem',
              }}
            >
              <input
                type="file"
                id="file-log-upload"
                accept=".json,.csv,.txt,.log"
                onChange={handleFileUpload}
                style={{ display: 'none' }}
              />
              <label
                htmlFor="file-log-upload"
                className="btn btn-cyber-outline"
                style={{ cursor: 'pointer', marginBottom: '0.5rem' }}
              >
                📁 Choose Log File
              </label>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                {uploadedFileName ? `Selected: ${uploadedFileName}` : 'Supports WinEventLog, AWS CloudTrail JSON, CSV dumps'}
              </p>
            </div>

            {uploadError && (
              <div style={{ color: '#f87171', fontSize: '0.82rem', marginBottom: '0.8rem' }}>
                [!] {uploadError}
              </div>
            )}

            {parsedPreview && (
              <div style={{ marginBottom: '1rem' }}>
                <div style={{ color: 'var(--cyber-green)', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                  ✓ Successfully recognized {parsedPreview.length} forensic records from {uploadedFileName}!
                </div>
                <button onClick={handleApplyUpload} className="btn btn-cyber-green">
                  <span>🚀 Ingest & Reconstruct Timeline ({parsedPreview.length} Events)</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
