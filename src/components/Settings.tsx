import React, { useState } from 'react';
import { SystemConfig } from '../types';
import { TelemetryService } from '../services/telemetryService';

interface SettingsProps {
  config: SystemConfig;
  onUpdateConfig: (updated: SystemConfig) => void;
  onBackToDashboard: () => void;
}

export const Settings: React.FC<SettingsProps> = ({ config, onUpdateConfig, onBackToDashboard }) => {
  const [timeRange, setTimeRange] = useState(config.default_time_range);
  const [recordLimit, setRecordLimit] = useState(config.default_record_limit);
  const [alertRecipient, setAlertRecipient] = useState(config.alert_recipient);
  const [savedSuccess, setSavedSuccess] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    const updated = TelemetryService.saveConfig({
      default_time_range: timeRange,
      default_record_limit: Number(recordLimit),
      alert_recipient: alertRecipient,
    });
    onUpdateConfig(updated);
    setSavedSuccess(true);
    window.setTimeout(() => setSavedSuccess(false), 3000);
  };

  return (
    <div>
      <div className="dashboard-header">
        <div>
          <h2 className="page-title">System &amp; Forensic Engine Configuration</h2>
          <p className="page-subtitle">Standalone offline forensic parameters &bull; Zero external Splunk connections</p>
        </div>
        <div>
          <button onClick={onBackToDashboard} className="btn btn-cyber-outline">
            &larr; Back to Dashboard
          </button>
        </div>
      </div>

      <div className="grid-cards">
        {/* Engine Parameters Card */}
        <div className="cyber-card">
          <div className="card-header">
            <span className="card-title">⚙️ Forensic Telemetry Engine</span>
            <span className="status-pill success">
              <span className="badge-pulse"></span> 100% Offline
            </span>
          </div>

          <div className="data-list">
            <div className="data-row">
              <span className="data-label">Operational Mode</span>
              <span className="data-value" style={{ color: 'var(--cyber-green)' }}>
                Offline Demo &amp; Cloud Telemetry
              </span>
            </div>
            <div className="data-row">
              <span className="data-label">External Connections</span>
              <span className="data-value" style={{ color: 'var(--cyber-cyan)' }}>
                Disabled (No Splunk Server Required)
              </span>
            </div>
            <div className="data-row">
              <span className="data-label">Analysis Algorithm</span>
              <span className="data-value">{config.analysis_algorithm}</span>
            </div>
            <div className="data-row">
              <span className="data-label">Target Event Log Codes</span>
              <span className="data-value">4624, 4625, 4672, 4720</span>
            </div>
            <div className="data-row">
              <span className="data-label">Cloud Log Parsers</span>
              <span className="data-value">AWS CloudTrail, Azure Entra ID, GCP</span>
            </div>
          </div>
        </div>

        {/* Security Policy Card */}
        <div className="cyber-card">
          <div className="card-header">
            <span className="card-title">🛡️ Data Integrity &amp; Provenance Policy</span>
            <span className="status-pill info">
              Self-Contained
            </span>
          </div>

          <div className="data-list">
            <div className="data-row">
              <span className="data-label">Data Origin</span>
              <span className="data-value">{config.data_origin}</span>
            </div>
            <div className="data-row">
              <span className="data-label">License Requirement</span>
              <span className="data-value" style={{ color: 'var(--cyber-green)' }}>
                Zero (Free &amp; Open)
              </span>
            </div>
            <div className="data-row">
              <span className="data-label">Hardcoded Secrets</span>
              <span className="data-value" style={{ color: 'var(--cyber-green)' }}>
                None (Clean)
              </span>
            </div>
            <div className="data-row">
              <span className="data-label">Alert Notifications</span>
              <span className="data-value">{config.alert_recipient}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Settings Form */}
      <div className="cyber-card" style={{ marginBottom: '2rem' }}>
        <div className="card-header">
          <span className="card-title">✏️ Investigation Preferences</span>
          {savedSuccess && (
            <span className="status-pill success">
              <span className="badge-pulse"></span> Preferences Saved Successfully
            </span>
          )}
        </div>

        <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.2rem' }}>
            <div className="filter-group">
              <label className="filter-label">Default Observation Window</label>
              <select
                className="cyber-select"
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
              >
                <option value="-15m">Last 15 Minutes</option>
                <option value="-1h">Last 1 Hour</option>
                <option value="-24h">Last 24 Hours</option>
                <option value="-7d">Last 7 Days</option>
                <option value="0">All Time</option>
              </select>
            </div>

            <div className="filter-group">
              <label className="filter-label">Default Ingestion Limit</label>
              <select
                className="cyber-select"
                value={recordLimit}
                onChange={(e) => setRecordLimit(Number(e.target.value))}
              >
                <option value={25}>25 Events</option>
                <option value={50}>50 Events</option>
                <option value={100}>100 Events</option>
                <option value={200}>200 Events</option>
              </select>
            </div>

            <div className="filter-group">
              <label className="filter-label">Investigator Alert Email</label>
              <input
                type="email"
                className="cyber-input"
                value={alertRecipient}
                onChange={(e) => setAlertRecipient(e.target.value)}
                placeholder="investigator@domain.com"
              />
            </div>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button type="submit" className="btn btn-cyber-primary">
              💾 Save Preferences
            </button>
            <button
              type="button"
              onClick={onBackToDashboard}
              className="btn btn-cyber-outline"
            >
              Back to Dashboard
            </button>
          </div>
        </form>
      </div>

      {/* Standalone Guide */}
      <div className="cyber-card">
        <div className="card-header">
          <span className="card-title">📖 Standalone Demo Architecture</span>
        </div>
        <div style={{ fontSize: '0.9rem', lineHeight: '1.8', color: 'var(--text-muted)' }}>
          <p style={{ marginBottom: '1rem' }}>
            This application is running in <strong>100% Standalone Offline Mode</strong>. All Splunk server dependencies and external API connection attempts have been completely removed:
          </p>
          <ul style={{ paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <li>
              <strong>No Splunk server needed:</strong> All log queries run locally against realistic Windows Security and Multi-Cloud incident datasets.
            </li>
            <li>
              <strong>Zero license fees:</strong> You do not need any Splunk Enterprise license, universal forwarder, or paid API keys.
            </li>
            <li>
              <strong>Full Forensic Capabilities:</strong> Automated timeline causal ordering, MITRE ATT&CK correlation, court-defensible PDF reports, and incident email notifications work without any internet or cloud service connection.
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};
