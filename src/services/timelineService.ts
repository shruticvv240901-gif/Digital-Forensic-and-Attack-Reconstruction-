import { WindowsEvent, TimelineStep, TimelineResult, TimelineSummary, CorrelationChain } from '../types';

/**
 * Timeline Reconstruction & Forensic Correlation Service.
 * Stage 3: Automated Attack Timeline Reconstruction.
 *
 * Forensic Principles:
 * 1. Strict Separation: Clearly distinguishes Confirmed Forensic Facts from Heuristic Hypotheses.
 * 2. Temporal Causality: Sorts events chronologically (oldest -> newest) to map attack progression.
 * 3. Multi-Entity Correlation: Correlates events across Source IP, User Account, Computer Name, and Event IDs.
 * 4. Baseline Protection: Non-malicious baseline events are categorized as routine activity, not attacks.
 * 5. Deterministic & Explainable: Pure, transparent heuristics.
 */

export class TimelineReconstructionService {
  static readonly PHASE_RECON = 'Reconnaissance / Credential Access';
  static readonly PHASE_INITIAL_ACCESS = 'Initial Access';
  static readonly PHASE_PRIV_ESC = 'Privilege Escalation';
  static readonly PHASE_LATERAL_MOVE = 'Lateral Movement';
  static readonly PHASE_PERSISTENCE = 'Persistence';
  static readonly PHASE_BASELINE = 'Routine Baseline Operations';

  static parseEventTime(timestampStr: string): number {
    if (!timestampStr || timestampStr === 'N/A') return 0;
    try {
      const clean = timestampStr.trim().replace(' ', 'T');
      const d = new Date(clean);
      return isNaN(d.getTime()) ? 0 : d.getTime();
    } catch {
      return 0;
    }
  }

  static reconstructAttackTimeline(
    events: WindowsEvent[],
    reverse: boolean = false
  ): TimelineResult {
    if (!events || events.length === 0) {
      return {
        success: true,
        count: 0,
        timeline: [],
        summary: {
          total_events: 0,
          threat_level: 'None (No Events)',
          unique_actors: [],
          targeted_accounts: [],
          created_accounts: [],
          detected_attack_phases: [],
          earliest_event: null,
          latest_event: null,
        },
        correlation_chains: [],
        message: 'No events provided for timeline reconstruction.',
      };
    }

    // 1. Sort events chronologically (Oldest to Newest for causal reconstruction)
    const sortedEvents = [...events].sort(
      (a, b) => this.parseEventTime(a.timestamp) - this.parseEventTime(b.timestamp)
    );

    // 2. Extract Entities across entire dataset
    const allActors = new Set<string>();
    const allTargets = new Set<string>();
    const allHosts = new Set<string>();
    const createdAccounts = new Set<string>();

    for (const ev of sortedEvents) {
      const src = (ev.source_ip || '').trim();
      if (src && src !== '-' && !src.toLowerCase().includes('localhost') && !src.includes('127.0.0.1')) {
        allActors.add(src);
      }
      const usr = (ev.username || '').trim();
      if (usr && usr !== '-' && usr.toLowerCase() !== 'system') {
        allTargets.add(usr);
      }
      const hst = (ev.computer_name || '').trim();
      if (hst && hst !== '-') {
        allHosts.add(hst);
      }
      if (ev.event_id === '4720') {
        createdAccounts.add(usr);
      }
    }

    // 3. Contextual Pattern Tracking
    const failedAttemptsByIp: Record<string, number[]> = {};
    const failedAttemptsByUser: Record<string, number[]> = {};
    const successfulLogonsByIp: Record<string, number[]> = {};
    const accountsCreatedIndices: number[] = [];

    sortedEvents.forEach((ev, idx) => {
      const eid = ev.event_id;
      const ip = ev.source_ip || '-';
      const user = ev.username || '-';

      if (eid === '4625') {
        if (!failedAttemptsByIp[ip]) failedAttemptsByIp[ip] = [];
        failedAttemptsByIp[ip].push(idx);

        if (!failedAttemptsByUser[user]) failedAttemptsByUser[user] = [];
        failedAttemptsByUser[user].push(idx);
      } else if (eid === '4624') {
        if (!successfulLogonsByIp[ip]) successfulLogonsByIp[ip] = [];
        successfulLogonsByIp[ip].push(idx);
      } else if (eid === '4720') {
        accountsCreatedIndices.push(idx);
      }
    });

    // 4. Correlation & Heuristic Analysis Pass
    const detectedPhases = new Set<string>();
    let hasCritical = false;
    let hasHigh = false;

    const timelineItems: TimelineStep[] = [];

    sortedEvents.forEach((ev, idx) => {
      const stepNum = idx + 1;
      const eid = ev.event_id;
      const evName = ev.event_name || `Windows Event ${eid}`;
      const user = ev.username || 'Unknown User';
      const srcIp = ev.source_ip || '-';
      const host = ev.computer_name || 'Unknown Host';
      const logonType = ev.logon_type || 'N/A';
      const logonCode = ev.logon_type_code || '';
      const timestamp = ev.timestamp || 'N/A';
      const rawSnippet = ev.raw_snippet || '';

      let confirmedFacts = '';
      let correlationReason = '';
      let suspicionLevel: string = 'Informational / Baseline';
      let killChainPhase: string = this.PHASE_BASELINE;
      let investigationGuidance = '';

      const ipFailures = failedAttemptsByIp[srcIp] || [];
      const priorFailuresFromIp = ipFailures.filter((f) => f < idx);
      const isExternalIp =
        srcIp !== '-' &&
        !srcIp.includes('127.0.0.1') &&
        !srcIp.includes('::1') &&
        !srcIp.includes('Localhost') &&
        !srcIp.startsWith('10.0.');

      if (eid === '4625') {
        // Failed Logon
        killChainPhase = this.PHASE_RECON;
        detectedPhases.add(this.PHASE_RECON);
        confirmedFacts =
          `Authentication failure recorded on '${host}'. ` +
          `Account targeted: '${user}'. ` +
          `Network source IP: '${srcIp}'. ` +
          `Logon mechanism: ${logonType}.`;

        if (priorFailuresFromIp.length >= 2 || ipFailures.length >= 3) {
          suspicionLevel = 'High';
          hasHigh = true;
          correlationReason =
            `Part of a repeated failure cluster (${ipFailures.length} failed attempts total from ${srcIp}). ` +
            `Matches password spraying or brute force pattern targeting user '${user}'.`;
          investigationGuidance =
            `1. Check perimeter firewall logs for connections from ${srcIp} on port 445 (SMB) and 3389 (RDP).\n` +
            `2. Inspect if account lockout policies were triggered on '${host}'.\n` +
            `3. Verify if ${srcIp} originates from a VPN, proxy, or unrecognized external network.`;
        } else {
          suspicionLevel = 'Suspicious';
          correlationReason = `Isolated authentication failure from source ${srcIp}.`;
          investigationGuidance =
            'Monitor whether this failure is followed by additional attempts or a logon success.';
        }
      } else if (eid === '4624') {
        // Successful Logon
        confirmedFacts =
          `Authentication succeeded for account '${user}' on '${host}'. ` +
          `Source network address: '${srcIp}'. ` +
          `Logon Type: ${logonType}.`;

        if (priorFailuresFromIp.length > 0 && isExternalIp) {
          suspicionLevel = 'Critical';
          hasCritical = true;
          killChainPhase = this.PHASE_INITIAL_ACCESS;
          detectedPhases.add(this.PHASE_INITIAL_ACCESS);
          correlationReason =
            `CRITICAL BREACH INDICATOR: Account '${user}' successfully logged on from ${srcIp} ` +
            `immediately following ${priorFailuresFromIp.length} prior failed login attempts from the exact same IP. ` +
            'Strong evidence of password guessing or credential compromise.';
          investigationGuidance =
            `1. IMMEDIATELY isolate host '${host}' from network segment.\n` +
            `2. Force password reset and revoke active Kerberos/NTLM ticket grants for '${user}'.\n` +
            `3. Inspect process creation events (Sysmon Event 1) spawned within 10 minutes of ${timestamp}.`;
        } else if (createdAccounts.has(user)) {
          // Rogue backdoor account logging in
          suspicionLevel = 'Critical';
          hasCritical = true;
          killChainPhase = this.PHASE_PERSISTENCE;
          detectedPhases.add(this.PHASE_PERSISTENCE);
          correlationReason =
            `HIGH RISK SECONDARY INGRESS: Logon by rogue account '${user}', which was recently created ` +
            '(Event 4720) during this intrusion. Attacker is validating persistent backdoor access.';
          investigationGuidance =
            `1. Terminate active sessions for rogue account '${user}'.\n` +
            `2. Delete or disable account '${user}' immediately using 'net user ${user} /active:no'.\n` +
            `3. Audit all files modified by '${user}' in C:\\Users\\${user} and Temp directories.`;
        } else if (logonCode === '10') {
          // Remote Desktop (RDP)
          if (priorFailuresFromIp.length > 0 || isExternalIp) {
            suspicionLevel = 'High';
            hasHigh = true;
            killChainPhase = this.PHASE_LATERAL_MOVE;
            detectedPhases.add(this.PHASE_LATERAL_MOVE);
            correlationReason =
              `Remote Desktop (RDP) interactive session established by '${user}' from external source ${srcIp}. ` +
              'Indicates interactive GUI control over the target machine.';
            investigationGuidance =
              "1. Review RDP session logs in 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'.\n" +
              '2. Inspect clipboard transfer and drive redirection activity during RDP session.';
          } else {
            suspicionLevel = 'Medium';
            killChainPhase = this.PHASE_BASELINE;
            correlationReason = `Internal Remote Desktop session from internal IP ${srcIp}.`;
            investigationGuidance = `Verify whether internal IP ${srcIp} belongs to authorized IT administration workstation.`;
          }
        } else {
          // Baseline logon
          suspicionLevel = 'Informational / Baseline';
          killChainPhase = this.PHASE_BASELINE;
          detectedPhases.add(this.PHASE_BASELINE);
          correlationReason = 'Standard baseline authentication without prior anomalous indicators.';
          investigationGuidance = `No immediate remediation required unless user '${user}' was scheduled for off-hours.`;
        }
      } else if (eid === '4672') {
        // Special Privileges Assigned
        confirmedFacts =
          `Special administrative privileges (e.g. SeDebugPrivilege, SeSecurityPrivilege) assigned ` +
          `to logon session for user '${user}' on '${host}'.`;

        if (isExternalIp || createdAccounts.has(user)) {
          suspicionLevel = 'High';
          hasHigh = true;
          killChainPhase = this.PHASE_PRIV_ESC;
          detectedPhases.add(this.PHASE_PRIV_ESC);
          correlationReason =
            `High-risk administrative privileges granted to session originating from external address ${srcIp} ` +
            `or belonging to rogue persistence user '${user}'.`;
          investigationGuidance =
            '1. Check if SeDebugPrivilege was utilized to dump LSASS process memory (e.g., Mimikatz).\n' +
            '2. Review Security Event ID 4673 (Privileged Service Called) for unauthorized token impersonation.';
        } else {
          suspicionLevel = 'Informational / Baseline';
          killChainPhase = this.PHASE_BASELINE;
          correlationReason = `Routine administrative elevation for internal admin session on ${host}.`;
          investigationGuidance = 'Verify that this elevation corresponds to scheduled internal maintenance.';
        }
      } else if (eid === '4720') {
        // User Account Created
        confirmedFacts =
          `A new local Windows user account named '${user}' was created on '${host}'. ` +
          'Target creator session was active on machine.';
        suspicionLevel = 'Critical';
        hasCritical = true;
        killChainPhase = this.PHASE_PERSISTENCE;
        detectedPhases.add(this.PHASE_PERSISTENCE);
        correlationReason =
          `CRITICAL PERSISTENCE ACTION: New user account '${user}' created on domain/host. ` +
          'In forensic analysis, creation of unmanaged local accounts during off-hours or following a breach ' +
          'strongly indicates attacker establishing persistence.';
        investigationGuidance =
          `1. Check Windows Event 4728 / 4732 to see if '${user}' was added to Administrators or Remote Desktop Users group.\n` +
          `2. Check creation timestamp against employee onboarding records to verify legitimacy.\n` +
          `3. Disable account '${user}' immediately if unauthorized.`;
      }

      timelineItems.push({
        step: stepNum,
        timestamp,
        event_id: eid,
        event_name: evName,
        actor: srcIp !== '-' ? srcIp : 'Local Machine Session',
        target_user: user,
        target_host: host,
        logon_type: logonType,
        kill_chain_phase: killChainPhase,
        suspicion_level: suspicionLevel,
        confirmed_facts: confirmedFacts,
        correlation_reason: correlationReason,
        investigation_guidance: investigationGuidance,
        raw_snippet: rawSnippet,
        is_real_data: ev.is_real_data,
      });
    });

    // 5. Extract Correlation Chains
    const correlationChains: CorrelationChain[] = [];

    for (const [ip, idxs] of Object.entries(failedAttemptsByIp)) {
      if (idxs.length >= 2) {
        const succs = successfulLogonsByIp[ip] || [];
        correlationChains.push({
          chain_id: `CHAIN-BRUTE-${ip.replace(/\./g, '_')}`,
          title: 'Credential Access Campaign',
          primary_actor: ip,
          events_involved: idxs.length + succs.length,
          tactic: 'Credential Access / Initial Access',
          verdict: succs.length > 0 ? 'Compromised Access' : 'Unsuccessful Brute Force',
          description:
            `Detected ${idxs.length} authentication failures from ${ip}.` +
            (succs.length > 0 ? ` Followed by successful logon (${succs.length} events).` : ''),
        });
      }
    }

    if (accountsCreatedIndices.length > 0) {
      correlationChains.push({
        chain_id: 'CHAIN-PERSISTENCE-01',
        title: 'Account Manipulation & Persistence',
        primary_actor: 'Elevated Session',
        events_involved: accountsCreatedIndices.length,
        tactic: 'Persistence (T1136)',
        verdict: 'High-Risk Persistence',
        description: `Created ${accountsCreatedIndices.length} rogue user account(s): ${Array.from(createdAccounts).join(', ')}.`,
      });
    }

    let threatLevel = 'None';
    if (hasCritical) {
      threatLevel = 'Critical Threat (Active Multi-Stage Compromise)';
    } else if (hasHigh) {
      threatLevel = 'High Suspicion (Targeted Attacks Detected)';
    } else if (timelineItems.length > 0) {
      threatLevel = 'Low / Baseline (Routine Security Telemetry)';
    }

    const earliest = sortedEvents[0]?.timestamp || null;
    const latest = sortedEvents[sortedEvents.length - 1]?.timestamp || null;

    if (reverse) {
      timelineItems.reverse();
    }

    timelineItems.forEach((item, idx) => {
      item.display_index = idx + 1;
    });

    const summary: TimelineSummary = {
      total_events: timelineItems.length,
      threat_level: threatLevel,
      unique_actors: Array.from(allActors).sort(),
      targeted_accounts: Array.from(allTargets).sort(),
      created_accounts: Array.from(createdAccounts).sort(),
      detected_attack_phases: Array.from(detectedPhases).sort(),
      earliest_event: earliest,
      latest_event: latest,
    };

    return {
      success: true,
      count: timelineItems.length,
      timeline: timelineItems,
      summary,
      correlation_chains: correlationChains,
      message: `Successfully reconstructed attack timeline with ${timelineItems.length} correlated steps.`,
    };
  }
}
