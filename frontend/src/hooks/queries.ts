import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { dashboardService } from '../services/dashboardService';
import { logService } from '../services/logService';
import { incidentService } from '../services/incidentService';
import type { Incident, DashboardSummary, IncidentStatus, Severity, LogResponse } from '../types';

// Fetch Dashboard Summary
export function useDashboardSummary(refreshInterval: number | false = 30000) {
  return useQuery<DashboardSummary>({
    queryKey: ['dashboardSummary'],
    queryFn: () => dashboardService.getSummary(),
    refetchInterval: refreshInterval,
  });
}

// Fetch Logs
export function useLogs(skip = 0, limit = 100, refreshInterval: number | false = false) {
  return useQuery<LogResponse[]>({
    queryKey: ['logs', skip, limit],
    queryFn: () => logService.getLogs(skip, limit),
    refetchInterval: refreshInterval,
  });
}

// Fetch Incidents
export function useIncidents(
  status?: IncidentStatus | '',
  severity?: Severity | '',
  skip = 0,
  limit = 100,
  refreshInterval: number | false = false
) {
  return useQuery<Incident[]>({
    queryKey: ['incidents', status, severity, skip, limit],
    queryFn: () => incidentService.getIncidents(status, severity, skip, limit),
    refetchInterval: refreshInterval,
  });
}

// Fetch Incident Detail
export function useIncident(incidentId: string) {
  return useQuery<Incident>({
    queryKey: ['incident', incidentId],
    queryFn: () => incidentService.getIncident(incidentId),
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
      return incidentService.assignIncident(incidentId, assigned_to, assigned_role);
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
      return incidentService.addNote(incidentId, note);
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
      return incidentService.closeIncident(incidentId);
    },
    onSuccess: (_data, incidentId) => {
      queryClient.invalidateQueries({ queryKey: ['incident', incidentId] });
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      queryClient.invalidateQueries({ queryKey: ['dashboardSummary'] });
    },
  });
}
