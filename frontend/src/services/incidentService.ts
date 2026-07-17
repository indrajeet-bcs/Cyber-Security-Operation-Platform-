import { apiClient } from '../api/client';
import type { Incident, IncidentStatus, Severity } from '../types';

export const incidentService = {
  async getIncidents(
    status?: IncidentStatus | '',
    severity?: Severity | '',
    skip = 0,
    limit = 100
  ): Promise<Incident[]> {
    const params: Record<string, any> = { skip, limit };
    if (status) params.status = status;
    if (severity) params.severity = severity;
    const response = await apiClient.get<Incident[]>('/incidents', { params });
    return response.data;
  },

  async getIncident(incidentId: string): Promise<Incident> {
    const response = await apiClient.get<Incident>(`/incident/${incidentId}`);
    return response.data;
  },

  async assignIncident(
    incidentId: string,
    assigned_to: string,
    assigned_role: string
  ): Promise<Incident> {
    const response = await apiClient.post<Incident>(`/incident/${incidentId}/assign`, {
      assigned_to,
      assigned_role,
    });
    return response.data;
  },

  async addNote(incidentId: string, note: string): Promise<Incident> {
    const response = await apiClient.post<Incident>(`/incident/${incidentId}/notes`, { note });
    return response.data;
  },

  async closeIncident(incidentId: string): Promise<Incident> {
    const response = await apiClient.post<Incident>(`/incident/${incidentId}/close`);
    return response.data;
  },
};
