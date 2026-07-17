import type { Severity } from './severity';

export interface DetectionResult {
  is_suspicious: boolean;
  severity: Severity;
  reason: string | null;
}

export interface LogResponse {
  id: number;
  source: string;
  host: string | null;
  event_type: string;
  message: string;
  severity: Severity;
  timestamp: string;
  source_ip: string | null;
  user: string | null;
  metadata: Record<string, any>;
  record_number: number | null;
  ingested_at: string;
  detection: DetectionResult | null;
}
