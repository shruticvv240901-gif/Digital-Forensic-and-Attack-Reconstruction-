import { WindowsEvent, SystemConfig } from '../types';
import { generateDemoEvents, filterDemoEvents } from './demoData';

const DEFAULT_CONFIG: SystemConfig = {
  offline_demo_only: true,
  default_time_range: '-24h',
  default_record_limit: 50,
  engine_name: 'Deterministic Heuristic Causal Correlation Engine',
  analysis_algorithm: 'Temporal Causality & Multi-Entity Linkage',
  alert_recipient: 'shruti.cvv240901@cvv.ac.in',
  data_origin: 'High-Fidelity Simulated Forensics & Cloud Telemetry (Zero License Required)',
};

export class TelemetryService {
  private static STORAGE_KEY = 'forensic_system_config';

  static getConfig(): SystemConfig {
    try {
      const stored = localStorage.getItem(this.STORAGE_KEY);
      if (stored) {
        return { ...DEFAULT_CONFIG, ...JSON.parse(stored) };
      }
    } catch {
      // Fallback
    }
    return { ...DEFAULT_CONFIG };
  }

  static saveConfig(cfg: Partial<SystemConfig>): SystemConfig {
    const current = this.getConfig();
    const updated = { ...current, ...cfg };
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(updated));
    } catch {
      // Ignore
    }
    return updated;
  }

  static querySecurityEvents(
    eventId: string = 'all',
    timeRange: string = '-24h',
    limit: number = 50
  ): {
    success: boolean;
    mode: 'DEMO';
    events: WindowsEvent[];
    count: number;
    execution_time_ms: number;
    query_syntax: string;
    message: string;
  } {
    const allEvents = generateDemoEvents();
    const filtered = filterDemoEvents(allEvents, eventId, timeRange, limit);

    const targetDesc =
      eventId && eventId.toLowerCase() !== 'all'
        ? `EventCode=${eventId}`
        : 'EventCode IN (4624, 4625, 4672, 4720)';
    const querySyntax = `[LOCAL FORENSIC SEARCH]: search EventLog:Security (${targetDesc}) earliest=${timeRange} | sort - _time | head ${limit}`;

    return {
      success: true,
      mode: 'DEMO',
      events: filtered,
      count: filtered.length,
      execution_time_ms: 1.5,
      query_syntax: querySyntax,
      message: `[DEMO DATASET ACTIVE] Ingested ${filtered.length} security log events for timeline reconstruction. No external license or connection required.`,
    };
  }
}

// Keep SplunkService export alias for backwards-compatibility
export const SplunkService = TelemetryService;
