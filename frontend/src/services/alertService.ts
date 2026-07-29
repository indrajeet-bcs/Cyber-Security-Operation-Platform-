import { apiClient } from '../api/client';
import type { AlertsResponse, AlertRecord } from '../types';

export interface GetAlertsParams {
  severity?: string;
  status?: string;
  source_ip?: string;
  source?: string;
  search?: string;
  sort_by?: string;
  sort_order?: string;
  skip?: number;
  limit?: number;
}

export const alertService = {
  async getAlerts(params: GetAlertsParams = {}): Promise<AlertsResponse> {
    const response = await apiClient.get<AlertsResponse>('/alerts', { params });
    return response.data;
  },

  async getAlert(alertId: string): Promise<AlertRecord> {
    const response = await apiClient.get<AlertRecord>(`/alerts/${alertId}`);
    return response.data;
  },
};
