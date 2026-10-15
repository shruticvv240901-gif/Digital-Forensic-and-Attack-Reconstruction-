import React, { useState } from 'react';
import { EmailAlertConfig, DispatchedAlert, TimelineResult, InvestigationSummary } from '../types';
import { AlertService } from '../services/alertService';

interface AlertModalProps {
  isOpen: boolean;
  onClose: () => void;
  timelineResult: TimelineResult | null;
  summary: InvestigationSummary | null;
}

export const AlertModal: React.FC<AlertModalProps> = ({ isOpen, onClose, timelineResult, summary }) => {
  const [config, setConfig] = useState<EmailAlertConfig>(() => AlertService.getConfig());
  const [isSending, setIsSending] = useState<boolean>(false);
  const [lastDispatched, setLastDispatched] = useState<DispatchedAlert | null>(null);
  const [showPreview, setShowPreview] = useState<boolean>(false);
  const [history, setHistory] = useState<DispatchedAlert[]>(() => AlertService.getDispatchedHistory());
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSendAlert = () => {
    if (!timelineResult || !summary) {
      setStatusMessage('Please load or reconstruct security logs first.');
      return;
    }

    setIsSending(true);
    setStatusMessage(null);

    // Simulate network latency for SMTP dispatch
    setTimeout(() => {
      AlertService.saveConfig(config);
      const dispatched = AlertService.dispatchIncidentAlert(timelineResult, summary, config);
      setLastDispatched(dispatched);
      setHistory(AlertService.getDispatchedHistory());
      setIsSending(false);
      setStatusMessage(`Incident Alert ${dispatched.id} successfully queued and dispatched to ${config.recipient}!`);
    }, 750);
  };

  return (
    <div
      className="modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-content" style={{ maxWidth: '850px' }}>
        <div className="modal-header">
          <h3 style={{ color: 'var(--cyber-cyan)', fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>🚨 Email Alerting & Incident Notification Engine</span>
          </h3>
          <button className="modal-close-btn" onClick={onClose}>
            &times;
          </button>
        </div>

        <div className="modal-body" style={{ maxHeight: '78vh' }}>
          {statusMessage && (
            <div
              style={{
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid var(--cyber-green)',
                color: '#34d399',
                padding: '0.8rem 1rem',
                borderRadius: '6px',
                marginBottom: '1.2rem',
                fontSize: '0.86rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <span className="badge-pulse" style={{ backgroundColor: 'var(--cyber-green)' }}></span>
              <span>{statusMessage}</span>
            </div>
          )}

          {/* Config Form Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.2rem', marginBottom: '1.5rem' }}>
            <div className="filter-group">
              <label className="filter-label">Alert Recipient Email (Investigator)</label>
              <input
                type="email"
                className="cyber-input"
                value={config.recipient}
                onChange={(e) => setConfig({ ...config, recipient: e.target.value })}
                placeholder="investigator@domain.com"
              />
            </div>

            <div className="filter-group">
              <label className="filter-label">SMTP Relay Server</label>
              <input
                type="text"
                className="cyber-input"
                value={config.smtpServer}
                onChange={(e) => setConfig({ ...config, smtpServer: e.target.value })}
                placeholder="smtp.domain.internal:587"
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.2rem', marginBottom: '1.5rem' }}>
            <div className="filter-group">
              <label className="filter-label">Severity Trigger Threshold</label>
              <select
                className="cyber-select"
                value={config.severityThreshold}
                onChange={(e) => setConfig({ ...config, severityThreshold: e.target.value as any })}
              >
                <option value="Critical">Critical Threats Only (Active Compromise)</option>
                <option value="High">High Suspicion & Critical</option>
                <option value="All">All Anomalies & Baseline Telemetry</option>
              </select>
            </div>

            <div className="filter-group">
              <label className="filter-label">Sender Identity Display</label>
              <input
                type="text"
                className="cyber-input"
                value={config.senderName}
                onChange={(e) => setConfig({ ...config, senderName: e.target.value })}
              />
            </div>
          </div>

          {/* Active Alert Trigger Rules */}
          <div style={{ background: 'rgba(0,0,0,0.3)', padding: '1rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', marginBottom: '1.5rem' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.6rem' }}>
              Enabled Intrusion Detection Triggers:
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.6rem', fontSize: '0.82rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={config.alertRules.bruteForce}
                  onChange={(e) => setConfig({ ...config, alertRules: { ...config.alertRules, bruteForce: e.target.checked } })}
                />
                Event 4625 Brute Force Clusters
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={config.alertRules.initialAccess}
                  onChange={(e) => setConfig({ ...config, alertRules: { ...config.alertRules, initialAccess: e.target.checked } })}
                />
                Event 4624 Post-Brute Logon Breach
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={config.alertRules.privilegeEscalation}
                  onChange={(e) => setConfig({ ...config, alertRules: { ...config.alertRules, privilegeEscalation: e.target.checked } })}
                />
                Event 4672 SeDebugPrivilege Escalation
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={config.alertRules.persistenceRogue}
                  onChange={(e) => setConfig({ ...config, alertRules: { ...config.alertRules, persistenceRogue: e.target.checked } })}
                />
                Event 4720 Rogue Backdoor Account
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={config.alertRules.cloudPolicyAbuse}
                  onChange={(e) => setConfig({ ...config, alertRules: { ...config.alertRules, cloudPolicyAbuse: e.target.checked } })}
                />
                Cloud IAM Policy & Token Abuse
              </label>
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
            <button
              onClick={handleSendAlert}
              disabled={isSending || !timelineResult}
              className="btn btn-cyber-primary"
            >
              <span>{isSending ? '⏳ Dispatching Alert via SMTP...' : '⚡ Dispatch Incident Alert Email Now'}</span>
            </button>

            {lastDispatched && (
              <>
                <button
                  onClick={() => setShowPreview(!showPreview)}
                  className="btn btn-cyber-outline"
                >
                  <span>{showPreview ? 'Hide HTML Preview' : 'Preview Dispatched Email'}</span>
                </button>
                <button
                  onClick={() => AlertService.downloadAlertHtml(lastDispatched)}
                  className="btn btn-cyber-green btn-sm"
                >
                  <span>📥 Save Alert (.html)</span>
                </button>
              </>
            )}
          </div>

          {/* Live Email Preview Box */}
          {showPreview && lastDispatched && (
            <div style={{ marginBottom: '1.5rem', border: '1px solid var(--cyber-cyan)', borderRadius: '6px', overflow: 'hidden' }}>
              <div style={{ background: '#0f172a', padding: '0.6rem 1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                <span>Subject: {lastDispatched.subject}</span>
                <span className="status-pill success">{lastDispatched.status}</span>
              </div>
              <div
                style={{ background: '#090d16', padding: '1rem', maxHeight: '350px', overflowY: 'auto' }}
                dangerouslySetInnerHTML={{ __html: lastDispatched.htmlPreview }}
              />
            </div>
          )}

          {/* Dispatch History Table */}
          {history.length > 0 && (
            <div>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.6rem' }}>
                Recent Alert Dispatch Log
              </div>
              <div className="table-responsive">
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>Alert ID</th>
                      <th>Timestamp</th>
                      <th>Recipient</th>
                      <th>Threat Verdict</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.slice(0, 5).map((item, idx) => (
                      <tr key={idx}>
                        <td className="cyber-mono" style={{ color: 'var(--cyber-cyan)' }}>{item.id}</td>
                        <td className="cyber-mono">{item.timestamp}</td>
                        <td>{item.recipient}</td>
                        <td>
                          <span className="pill-level critical">{item.threatLevel}</span>
                        </td>
                        <td>
                          <span className="status-pill success">{item.status}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
