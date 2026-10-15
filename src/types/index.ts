export interface WindowsEvent {
  timestamp: string;
  event_id: string;
  event_name: string;
  category: string;
  severity: string;
  mitre_tactic: string;
  mitre_technique: string;
  username: string;
  source_ip: string;
  computer_name: string;
  logon_type: string;
  logon_type_code: string;
  message: string;
  raw_snippet: string;
  is_real_data: boolean;
  cloud_provider?: 'AWS' | 'Azure' | 'GCP' | 'On-Premises Windows' | string;
}

export interface TimelineStep {
  step: number;
  display_index?: number;
  timestamp: string;
  event_id: string;
  event_name: string;
  actor: string;
  target_user: string;
  target_host: string;
  logon_type: string;
  kill_chain_phase: string;
  suspicion_level: 'Critical' | 'High' | 'Suspicious' | 'Informational / Baseline' | string;
  confirmed_facts: string;
  correlation_reason: string;
  investigation_guidance: string;
  raw_snippet: string;
  is_real_data: boolean;
  cloud_provider?: string;
}

export interface TimelineSummary {
  total_events: number;
  threat_level: string;
  unique_actors: string[];
  targeted_accounts: string[];
  created_accounts: string[];
  detected_attack_phases: string[];
  earliest_event: string | null;
  latest_event: string | null;
}

export interface CorrelationChain {
  chain_id: string;
  title: string;
  primary_actor: string;
  events_involved: number;
  tactic: string;
  verdict: string;
  description: string;
}

export interface TimelineResult {
  success: boolean;
  count: number;
  timeline: TimelineStep[];
  summary: TimelineSummary;
  correlation_chains: CorrelationChain[];
  message: string;
}

export interface KeyFinding {
  step: number;
  timestamp: string;
  event_id: string;
  event_name: string;
  actor: string;
  target: string;
  phase: string;
  suspicion: string;
  description: string;
}

export interface ConfirmedFact {
  timestamp: string;
  event_id: string;
  fact: string;
}

export interface ThreatHypothesis {
  timestamp: string;
  event_id: string;
  suspicion: string;
  hypothesis: string;
}

export interface Recommendation {
  priority: string;
  action: string;
  details: string;
}

export interface InvestigationSummary {
  methodology: string;
  data_provenance: string;
  is_demo: boolean;
  generated_at: string;
  threat_verdict: string;
  executive_summary: string;
  time_scope: {
    earliest_event: string;
    latest_event: string;
    total_events_analyzed: number;
  };
  entities: {
    actors: string[];
    targeted_accounts: string[];
    created_accounts: string[];
    detected_phases: string[];
  };
  key_findings: KeyFinding[];
  confirmed_facts: ConfirmedFact[];
  threat_hypotheses: ThreatHypothesis[];
  correlation_chains: CorrelationChain[];
  recommendations: Recommendation[];
  forensic_limitations: string;
}

export interface SystemConfig {
  offline_demo_only: boolean;
  default_time_range: string;
  default_record_limit: number;
  engine_name: string;
  analysis_algorithm: string;
  alert_recipient: string;
  data_origin: string;
}

export type CloudLogSource =
  | 'windows_dc'
  | 'aws_cloudtrail'
  | 'azure_entra'
  | 'gcp_audit'
  | 'hybrid_cloud'
  | 'custom_upload';

export interface EmailAlertConfig {
  recipient: string;
  senderName: string;
  smtpServer: string;
  severityThreshold: 'Critical' | 'High' | 'All';
  includePdfSummary: boolean;
  alertRules: {
    bruteForce: boolean;
    initialAccess: boolean;
    privilegeEscalation: boolean;
    persistenceRogue: boolean;
    cloudPolicyAbuse: boolean;
  };
}

export interface DispatchedAlert {
  id: string;
  timestamp: string;
  recipient: string;
  subject: string;
  threatLevel: string;
  actor: string;
  affectedAccounts: string[];
  htmlPreview: string;
  status: 'Sent / Delivered' | 'Simulated Dispatch';
}

export interface PipelineTestStep {
  id: string;
  title: string;
  status: 'pending' | 'running' | 'passed' | 'failed';
  details: string;
  latencyMs?: number;
}
