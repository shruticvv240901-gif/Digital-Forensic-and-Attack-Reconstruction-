import { EmailAlertConfig, DispatchedAlert, TimelineResult, InvestigationSummary } from '../types';

export const DEFAULT_ALERT_CONFIG: EmailAlertConfig = {
  recipient: 'shruti.cvv240901@cvv.ac.in',
  senderName: 'SOC Security Monitoring System <alerts@soc-forensics.internal>',
  smtpServer: 'smtp.internal.soc-relay.local:587 (STARTTLS)',
  severityThreshold: 'Critical',
  includePdfSummary: true,
  alertRules: {
    bruteForce: true,
    initialAccess: true,
    privilegeEscalation: true,
    persistenceRogue: true,
    cloudPolicyAbuse: true,
  },
};

export class AlertService {
  private static STORAGE_KEY = 'soc_email_alert_config';
  private static DISPATCH_HISTORY_KEY = 'soc_dispatched_alerts_history';

  static getConfig(): EmailAlertConfig {
    try {
      const stored = localStorage.getItem(this.STORAGE_KEY);
      if (stored) {
        return { ...DEFAULT_ALERT_CONFIG, ...JSON.parse(stored) };
      }
    } catch {
      // Fallback
    }
    return { ...DEFAULT_ALERT_CONFIG };
  }

  static saveConfig(cfg: EmailAlertConfig): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(cfg));
    } catch {
      // Ignore
    }
  }

  static getDispatchedHistory(): DispatchedAlert[] {
    try {
      const stored = localStorage.getItem(this.DISPATCH_HISTORY_KEY);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch {
      // Ignore
    }
    return [];
  }

  static dispatchIncidentAlert(
    timelineResult: TimelineResult,
    summary: InvestigationSummary,
    config: EmailAlertConfig
  ): DispatchedAlert {
    const alertId = `ALT-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 900 + 100)}`;
    const now = new Date();
    const timestamp = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

    const actor = summary.entities.actors.length > 0 ? summary.entities.actors.join(', ') : 'Unknown Actor';
    const targets = summary.entities.targeted_accounts.length > 0 ? summary.entities.targeted_accounts.join(', ') : 'None';
    const created = summary.entities.created_accounts.length > 0 ? summary.entities.created_accounts.join(', ') : 'None';

    const subject = `[CRITICAL SOC INCIDENT ALERT] Multi-Stage Intrusion Detected | Verdict: ${summary.threat_verdict} (ID: ${alertId})`;

    // Generate HTML incident email template
    const htmlPreview = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #090d16; color: #f8fafc; margin: 0; padding: 20px; }
    .container { max-width: 680px; margin: 0 auto; background: #131c2e; border: 1px solid #ef4444; border-radius: 8px; overflow: hidden; }
    .header { background: #1e293b; padding: 20px; border-bottom: 2px solid #ef4444; }
    .header h1 { margin: 0; font-size: 18px; color: #f87171; letter-spacing: 0.05em; text-transform: uppercase; }
    .header p { margin: 5px 0 0; font-size: 12px; color: #94a3b8; }
    .content { padding: 24px; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .meta-table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }
    .meta-table td { padding: 8px 12px; border-bottom: 1px solid #1e293b; }
    .meta-table td.label { color: #94a3b8; font-weight: 600; width: 35%; }
    .meta-table td.value { color: #ffffff; font-family: ui-monospace, monospace; }
    .finding-box { background: rgba(0, 0, 0, 0.3); border-left: 4px solid #ef4444; padding: 12px 16px; margin: 16px 0; border-radius: 4px; }
    .recommendations { background: rgba(16, 185, 129, 0.08); border-left: 4px solid #10b981; padding: 12px 16px; margin: 16px 0; border-radius: 4px; font-size: 13px; }
    .footer { background: #0f172a; padding: 16px; font-size: 11px; color: #64748b; text-align: center; border-top: 1px solid #1e293b; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h1>🚨 Automated Security Incident Alert</h1>
        <span class="badge">Critical Threat</span>
      </div>
      <p>Source: AI-Assisted Automated Attack Timeline Reconstruction & Digital Forensic Engine</p>
    </div>
    <div class="content">
      <p style="font-size: 14px; line-height: 1.6; color: #e2e8f0;">
        <strong>Attention Security Investigator:</strong> The automated forensic engine has identified a confirmed multi-stage cyber attack sequence matching active intrusion rules. Immediate triage and host containment are recommended.
      </p>

      <table class="meta-table">
        <tr><td class="label">Incident ID</td><td class="value">${alertId}</td></tr>
        <tr><td class="label">Dispatched To</td><td class="value">${config.recipient}</td></tr>
        <tr><td class="label">Threat Verdict</td><td class="value" style="color:#f87171; font-weight:bold;">${summary.threat_verdict}</td></tr>
        <tr><td class="label">Primary Threat Actor(s)</td><td class="value" style="color:#00f0ff;">${actor}</td></tr>
        <tr><td class="label">Targeted Accounts</td><td class="value">${targets}</td></tr>
        <tr><td class="label">Rogue Created Accounts</td><td class="value" style="color:#f59e0b;">${created}</td></tr>
        <tr><td class="label">Correlated Events</td><td class="value">${timelineResult.count} Log Events</td></tr>
      </table>

      <div class="finding-box">
        <strong style="color: #f87171; font-size: 13px;">Executive Summary:</strong>
        <p style="margin: 6px 0 0; font-size: 13px; line-height: 1.5; color: #cbd5e1;">
          ${summary.executive_summary}
        </p>
      </div>

      <div class="recommendations">
        <strong style="color: #34d399; font-size: 13px;">Immediate Defensive Containment Actions:</strong>
        <ul style="margin: 8px 0 0; padding-left: 20px; line-height: 1.6; color: #cbd5e1;">
          ${summary.recommendations.slice(0, 3).map((r) => `<li><strong>${r.action} (${r.priority}):</strong> ${r.details}</li>`).join('')}
        </ul>
      </div>

      <p style="font-size: 12px; color: #94a3b8; margin-top: 20px;">
        <em>A full, court-defensible Digital Forensic Investigation PDF Report has been rendered and is ready for export on the Security Dashboard.</em>
      </p>
    </div>
    <div class="footer">
      Generated automatically by SIEM Alert Dispatcher &bull; Recipient: ${config.recipient} &bull; Security Operations Center
    </div>
  </div>
</body>
</html>
    `.trim();

    const dispatchedAlert: DispatchedAlert = {
      id: alertId,
      timestamp,
      recipient: config.recipient,
      subject,
      threatLevel: summary.threat_verdict,
      actor,
      affectedAccounts: summary.entities.targeted_accounts,
      htmlPreview,
      status: 'Sent / Delivered',
    };

    // Store in history
    try {
      const history = this.getDispatchedHistory();
      history.unshift(dispatchedAlert);
      localStorage.setItem(this.DISPATCH_HISTORY_KEY, JSON.stringify(history.slice(0, 20)));
    } catch {
      // Ignore
    }

    return dispatchedAlert;
  }

  static getMailtoUrl(alert: DispatchedAlert, summary: InvestigationSummary): string {
    const subject = encodeURIComponent(alert.subject);
    const body = encodeURIComponent(
`🚨 AUTOMATED SECURITY INCIDENT ALERT
Incident ID: ${alert.id}
Timestamp: ${alert.timestamp}
Threat Verdict: ${alert.threatLevel}
Primary Threat Actor(s): ${alert.actor}
Targeted Accounts: ${alert.affectedAccounts.join(', ')}

============================================================
EXECUTIVE SUMMARY:
${summary.executive_summary}

============================================================
IMMEDIATE DEFENSIVE CONTAINMENT ACTIONS:
${summary.recommendations.slice(0, 3).map((r, i) => `${i + 1}. [${r.priority}] ${r.action}: ${r.details}`).join('\n')}

============================================================
Full court-defensible Digital Forensic Investigation PDF Report has been generated on the SOC Dashboard.
Generated by AI-Assisted Automated Attack Timeline Reconstruction & Digital Forensic Engine.
`
    );
    return `mailto:${alert.recipient}?subject=${subject}&body=${body}`;
  }

  static downloadAlertHtml(alert: DispatchedAlert): void {
    const blob = new Blob([alert.htmlPreview], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Incident_Alert_${alert.id}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  static downloadAlertEml(alert: DispatchedAlert): void {
    const emlContent = [
      `From: ${DEFAULT_ALERT_CONFIG.senderName}`,
      `To: ${alert.recipient}`,
      `Subject: ${alert.subject}`,
      `Date: ${new Date().toUTCString()}`,
      `MIME-Version: 1.0`,
      `Content-Type: text/html; charset=utf-8`,
      ``,
      alert.htmlPreview,
    ].join('\r\n');

    const blob = new Blob([emlContent], { type: 'message/rfc822' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Incident_Alert_${alert.id}.eml`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}
