import { apiClient } from './client';
import type { PortTrafficReportResponse, LivePortStatusResponse } from '../types/portTraffic';

export const getMonitoredPorts = async (): Promise<number[]> => {
  const response = await apiClient.get<number[]>('/port-traffic/monitored-ports');
  return response.data;
};

export const getPortTrafficReport = async (
  port: number,
  startTime?: string,
  endTime?: string,
  bucketMinutes: number = 5
): Promise<PortTrafficReportResponse> => {
  const params: Record<string, any> = {
    port,
    bucket_minutes: bucketMinutes,
  };
  if (startTime) params.start_time = startTime;
  if (endTime) params.end_time = endTime;

  const response = await apiClient.get<PortTrafficReportResponse>('/port-traffic/report', {
    params,
  });
  return response.data;
};

export const getLivePortStatus = async (hours: number = 6): Promise<LivePortStatusResponse> => {
  const response = await apiClient.get<LivePortStatusResponse>('/port-traffic/live-status', {
    params: { hours },
  });
  return response.data;
};
