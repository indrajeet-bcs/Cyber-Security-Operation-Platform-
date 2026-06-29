import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import type { Incident, DashboardSummary, IncidentStatus, Severity } from '../types';

// Fetch Dashboard Summary
export function useDashboardSummary() {
  return useQuery<DashboardSummary>({
    queryKey: ['dashboardSummary'],
    queryFn: async () => {
      const response = await apiClient.get('/dashboard/summary');
      return response.data;
    },
    refetchInterval: 30000, // auto-refresh every 30 seconds
  });
}

// Fetch Incidents
export function useIncidents(status?: IncidentStatus | '', severity?: Severity | '') {
  return useQuery<Incident[]>({
    queryKey: ['incidents', status, severity],
    queryFn: async () => {
      const params: Record<string, string> = {};
      if (status) params.status = status;
      if (severity) params.severity = severity;
      const response = await apiClient.get('/incidents', { params });
      return response.data;
    },
  });
}

// Fetch Incident Detail
export function useIncident(incidentId: string) {
  return useQuery<Incident>({
    queryKey: ['incident', incidentId],
    queryFn: async () => {
      const response = await apiClient.get(`/incident/${incidentId}`);
      return response.data;
    },
  });
}

// Assign Incident Mutation
export function useAssignIncident() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      incidentId,
      assigned_to,
      assigned_role,
    }: {
      incidentId: string;
      assigned_to: string;
      assigned_role: string;
    }) => {
      const response = await apiClient.post(`/incident/${incidentId}/assign`, {
        assigned_to,
        assigned_role,
      });
      return response.data;
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['incident', variables.incidentId] });
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      queryClient.invalidateQueries({ queryKey: ['dashboardSummary'] });
    },
  });
}

// Add Note Mutation
export function useAddNote() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ incidentId, note }: { incidentId: string; note: string }) => {
      const response = await apiClient.post(`/incident/${incidentId}/notes`, { note });
      return response.data;
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['incident', variables.incidentId] });
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
    },
  });
}

// Close Incident Mutation
export function useCloseIncident() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (incidentId: string) => {
      const response = await apiClient.post(`/incident/${incidentId}/close`);
      return response.data;
    },
    onSuccess: (_data, incidentId) => {
      queryClient.invalidateQueries({ queryKey: ['incident', incidentId] });
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      queryClient.invalidateQueries({ queryKey: ['dashboardSummary'] });
    },
  });
}
