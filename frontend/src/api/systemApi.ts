import { apiClient } from './client';
import type { SystemMetricsResponse } from '../types/systemMetrics';

export const getSystemMetrics = async (): Promise<SystemMetricsResponse> => {
  const response = await apiClient.get<SystemMetricsResponse>('/system/metrics');
  return response.data;
};
