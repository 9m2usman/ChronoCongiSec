export interface DriftObservation {
  id: string;
  tenant_id: string;
  record_id: string;
  record_name: string;
  cosine_divergence: number;
  anomaly_confidence: string;
  status: 'HIGH_DRIFT' | 'MODERATE_DRIFT' | 'NORMAL';
  baseline_doc: string;
  observed_at: string;
}
