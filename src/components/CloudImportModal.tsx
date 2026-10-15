import React, { useState } from 'react';
import { WindowsEvent, CloudLogSource } from '../types';
import {
  generateCloudEvents,
  parseCustomUploadedLogs,
  downloadSampleIncidentJson,
  downloadSampleIncidentCsv,
  getSampleAttackEvents,
} from '../services/demoData';

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

  const handleLoadSampleBenchmarkDataset = () => {
    const sampleEvents = getSampleAttackEvents();
    onImportEvents(sampleEvents, 'Verified Multi-Stage Attack Dataset (APT29 Scenario)');
    onClose();
  };

  return (
    <div
      className="modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-content" style={{ maxWidth: '840px' }}>
        <div className="modal-header">
          <h3 style={{ color: 'var(--cyber-cyan)', fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>☁️ Security Log Ingestion &amp; Custom File Upload</span>
          </h3>
          <button className="modal-close-btn" onClick={onClose}>
            &times;
          </button>
        </div>

        <div className="modal-body" style={{ maxHeight: '78vh' }}>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1.2rem', lineHeight: 1.6 }}>
            Ingest real or simulated cloud security telemetry from AWS, Azure Entra ID, GCP, or upload your own forensic log files (JSON / CSV). Zero external paid Splunk licenses required.
          </p>

          {/* Standard Benchmark Dataset Box */}
          <div
            style={{
              background: 'rgba(0, 240, 255, 0.07)',
              border: '1px solid var(--cyber-cyan)',
              borderRadius: '6px',
              padding: '1.2rem',
              marginBottom: '1.5rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', marginBottom: '8px' }}>
              <div style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--cyber-cyan)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span>🎯</span> Standard Forensic Benchmark Dataset Pack:
              </div>
              <span className="status-pill success" style={{ fontSize: '0.72rem' }}>
                Ready For Ingestion
              </span>
            </div>
            <p style={{ fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.5, marginBottom: '1rem' }}>
              Test dynamic parsing with high-fidelity telemetry. You can download the verified APT29 emulation incident log to your computer, or load it with 1 click:
            </p>
            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={handleLoadSampleBenchmarkDataset}
                className="btn btn-cyber-primary"
                style={{ fontSize: '0.82rem' }}
              >
                <span>⚡ Load Sample Attack Dataset (1-Click)</span>
              </button>
              <button
                type="button"
                onClick={() => downloadSampleIncidentJson()}
                className="btn btn-cyber-outline"
                style={{ fontSize: '0.82rem' }}
                title="Download JSON format security log file to your computer"
              >
                <span>📥 Download Dataset (.JSON)</span>
              </button>
              <button
                type="button"
                onClick={() => downloadSampleIncidentCsv()}
                className="btn btn-cyber-outline"
                style={{ fontSize: '0.82rem' }}
                title="Download CSV format security log file to your computer"
              >
                <span>📥 Download Dataset (.CSV)</span>
              </button>
            </div>
          </div>

          {/* Section 1: Custom Log File Drag & Drop / Upload */}
          <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '1.2rem', marginBottom: '1.5rem' }}>
            <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.8rem' }}>
              Upload Your Own Custom Forensic Log File:
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
                📁 Choose File to Upload (JSON or CSV)
              </label>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                {uploadedFileName ? `Selected: ${uploadedFileName}` : 'Accepts Windows Event Log CSVs, SIEM JSON dumps, and raw audit exports'}
              </p>
            </div>

            {uploadError && (
              <div style={{ color: '#f87171', fontSize: '0.82rem', marginBottom: '0.8rem' }}>
                [!] {uploadError}
              </div>
            )}

            {parsedPreview && (
              <div style={{ marginBottom: '1rem', background: 'rgba(16, 185, 129, 0.08)', padding: '1rem', borderRadius: '4px', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                <div style={{ color: 'var(--cyber-green)', fontSize: '0.88rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                  ✓ Successfully recognized {parsedPreview.length} forensic records from {uploadedFileName}!
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.8rem' }}>
                  Target Accounts: {Array.from(new Set(parsedPreview.map((e) => e.username))).join(', ')} &bull; Source IPs: {Array.from(new Set(parsedPreview.map((e) => e.source_ip))).join(', ')}
                </div>
                <button onClick={handleApplyUpload} className="btn btn-cyber-green">
                  <span>🚀 Ingest &amp; Reconstruct Timeline ({parsedPreview.length} Events)</span>
                </button>
              </div>
            )}
          </div>

          {/* Section 2: Pre-Configured Cloud Intrusion Scenarios */}
          <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '1.2rem' }}>
            <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.8rem' }}>
              Or Ingest Pre-Configured Cloud Provider Scenarios:
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
              <span>⚡ Load Selected Cloud Telemetry</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

