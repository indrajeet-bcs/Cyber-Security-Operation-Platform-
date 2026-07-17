import { apiClient } from '../api/client';
import type { LogResponse } from '../types';

export const logService = {
  async getLogs(skip = 0, limit = 100): Promise<LogResponse[]> {
    const response = await apiClient.get<LogResponse[]>('/logs', {
      params: { skip, limit },
    });
    return response.data;
  },

  async getLog(logId: number): Promise<LogResponse> {
    const response = await apiClient.get<LogResponse>(`/logs/${logId}`);
    return response.data;
  },
};
