import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Card,
  CardContent,
  Typography,
  Box,
  TextField,
  MenuItem,
  FormControl,
  Select,
  InputLabel,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  TablePagination,
  Paper,
  Button,
  IconButton,
  Tooltip,
  Snackbar,
  Alert,
} from '@mui/material';
import {
  Search as SearchIcon,
  Visibility as ViewIcon,
  AssignmentInd as TakeIcon,
  Clear as ClearIcon,
  Autorenew as AutoRenewIcon,
} from '@mui/icons-material';

import { useIncidents, useAssignIncident } from '../../hooks/queries';
import type { Incident, IncidentStatus, Severity } from '../../types';
import SeverityBadge from '../../components/SeverityBadge';
import StatusChip from '../../components/StatusChip';
import LoadingState from '../../components/LoadingState';
import ErrorState from '../../components/ErrorState';
import EmptyState from '../../components/EmptyState';

export default function Incidents() {
  const navigate = useNavigate();

  // Filters & State
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | ''>('');
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('');
  
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  
  const [orderBy, setOrderBy] = useState<keyof Incident>('created_at');
  const [order, setOrder] = useState<'asc' | 'desc'>('desc');

  // Auto-refresh state (10s default or false)
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number | undefined>(10000);

  // Snackbar Notification State
  const [toast, setToast] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // Queries & Mutations
  const { data: incidents, isLoading, isError, error, refetch, isRefetching } = useIncidents(statusFilter, severityFilter, autoRefreshInterval);
  const assignMutation = useAssignIncident();

  // ----------------------------------------------------
  // Event Handlers
  // ----------------------------------------------------
  const handleRequestSort = (property: keyof Incident) => {
    const isAsc = orderBy === property && order === 'asc';
    setOrder(isAsc ? 'desc' : 'asc');
    setOrderBy(property);
  };

  const handleTakeIncident = async (e: React.MouseEvent, incidentId: string) => {
    e.stopPropagation(); // prevent navigating to detail page on button click
    try {
      await assignMutation.mutateAsync({
        incidentId,
        assigned_to: 'shubham',
        assigned_role: 'SOC_L1',
      });
      setToast({
        open: true,
        message: `Incident ${incidentId} successfully assigned to you!`,
        severity: 'success',
      });
    } catch (err: any) {
      setToast({
        open: true,
        message: `Failed to take incident: ${err?.response?.data?.detail || err.message}`,
        severity: 'error',
      });
    }
  };

  const handleClearFilters = () => {
    setSearch('');
    setStatusFilter('');
    setSeverityFilter('');
    setPage(0);
  };

  // ----------------------------------------------------
  // Data Filtering, Sorting & Pagination
  // ----------------------------------------------------
  const filteredIncidents = incidents
    ? incidents.filter((inc) => {
        const matchesSearch = inc.incident_id.toLowerCase().includes(search.toLowerCase()) || 
                             inc.title.toLowerCase().includes(search.toLowerCase());
        return matchesSearch;
      })
    : [];

  const sortedIncidents = filteredIncidents.sort((a, b) => {
    const valA = a[orderBy];
    const valB = b[orderBy];

    if (valA === null || valA === undefined) return order === 'asc' ? -1 : 1;
    if (valB === null || valB === undefined) return order === 'asc' ? 1 : -1;

    if (typeof valA === 'string' && typeof valB === 'string') {
      return order === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
    }
    
    return order === 'asc' 
      ? (valA as any) - (valB as any) 
      : (valB as any) - (valA as any);
  });

  const paginatedIncidents = sortedIncidents.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3.5 }}>
      {/* Page Title & Controls */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 800, color: '#F3F4F6', mb: 0.5 }}>
            Incident Investigation Queue
          </Typography>
          <Typography variant="body2" sx={{ color: '#9CA3AF' }}>
            Assign owner, sort, filter, and escalate active cybersecurity threats.
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Button
            variant={autoRefreshInterval ? "contained" : "outlined"}
            color={autoRefreshInterval ? "primary" : "inherit"}
            startIcon={<AutoRenewIcon className={isRefetching ? 'spin' : ''} />}
            onClick={() => setAutoRefreshInterval(prev => prev ? undefined : 10000)}
            sx={{ 
              borderRadius: 2, 
              textTransform: 'none',
              ...(autoRefreshInterval ? {} : { color: '#9CA3AF', borderColor: '#4B5563' })
            }}
          >
            {autoRefreshInterval ? 'Auto-Refresh: ON (10s)' : 'Auto-Refresh: OFF'}
          </Button>
          <Button
            variant="outlined"
            onClick={() => refetch()}
            disabled={isRefetching}
            sx={{ borderRadius: 2, textTransform: 'none', color: '#F3F4F6', borderColor: '#4B5563' }}
          >
            Manual Refresh
          </Button>
        </Box>
      </Box>

      {/* Filters Card */}
      <Card>
        <CardContent sx={{ p: 2.5 }}>
          <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
            {/* Search Input */}
            <Box sx={{ flex: 1.5, minWidth: { xs: '100%', sm: '250px' } }}>
              <TextField
                fullWidth
                size="small"
                variant="outlined"
                label="Search Incident ID / Title"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(0);
                }}
                slotProps={{
                  input: {
                    startAdornment: <SearchIcon sx={{ color: '#9CA3AF', mr: 1 }} />,
                    endAdornment: search && (
                      <IconButton size="small" onClick={() => setSearch('')}>
                        <ClearIcon fontSize="small" />
                      </IconButton>
                    ),
                  }
                }}
              />
            </Box>

            {/* Status Filter */}
            <Box sx={{ width: { xs: '100%', sm: '180px' } }}>
              <FormControl fullWidth size="small">
                <InputLabel id="status-filter-label">Status</InputLabel>
                <Select
                  labelId="status-filter-label"
                  value={statusFilter}
                  label="Status"
                  onChange={(e) => {
                    setStatusFilter(e.target.value as IncidentStatus | '');
                    setPage(0);
                  }}
                >
                  <MenuItem value=""><em>All Statuses</em></MenuItem>
                  <MenuItem value="open">Open</MenuItem>
                  <MenuItem value="acknowledged">Acknowledged</MenuItem>
                  <MenuItem value="investigating">Investigating</MenuItem>
                  <MenuItem value="closed">Closed</MenuItem>
                </Select>
              </FormControl>
            </Box>

            {/* Severity Filter */}
            <Box sx={{ width: { xs: '100%', sm: '180px' } }}>
              <FormControl fullWidth size="small">
                <InputLabel id="severity-filter-label">Severity</InputLabel>
                <Select
                  labelId="severity-filter-label"
                  value={severityFilter}
                  label="Severity"
                  onChange={(e) => {
                    setSeverityFilter(e.target.value as Severity | '');
                    setPage(0);
                  }}
                >
                  <MenuItem value=""><em>All Severities</em></MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="low">Low</MenuItem>
                </Select>
              </FormControl>
            </Box>

            {/* Clear Filters Button */}
            <Box sx={{ width: { xs: '100%', sm: '150px' } }}>
              {(search || statusFilter || severityFilter) ? (
                <Button
                  fullWidth
                  variant="outlined"
                  onClick={handleClearFilters}
                  startIcon={<ClearIcon />}
                >
                  Clear
                </Button>
              ) : null}
            </Box>
          </Box>
        </CardContent>
      </Card>

      {/* Incidents Table */}
      <Card sx={{ border: '1px solid #1F2937' }}>
        {isError ? (
          <ErrorState message="Failed to fetch incidents." error={error} onRetry={() => refetch()} />
        ) : (
          <TableContainer component={Paper} sx={{ backgroundColor: 'transparent', boxShadow: 'none' }}>
            <Table>
              <TableHead>
                <TableRow>
                  {/* ID */}
                  <TableCell>
                    <TableSortLabel
                      active={orderBy === 'incident_id'}
                      direction={orderBy === 'incident_id' ? order : 'asc'}
                      onClick={() => handleRequestSort('incident_id')}
                    >
                      Incident ID
                    </TableSortLabel>
                  </TableCell>
                  {/* Severity */}
                  <TableCell>
                    <TableSortLabel
                      active={orderBy === 'severity'}
                      direction={orderBy === 'severity' ? order : 'asc'}
                      onClick={() => handleRequestSort('severity')}
                    >
                      Severity
                    </TableSortLabel>
                  </TableCell>
                  {/* Status */}
                  <TableCell>
                    <TableSortLabel
                      active={orderBy === 'status'}
                      direction={orderBy === 'status' ? order : 'asc'}
                      onClick={() => handleRequestSort('status')}
                    >
                      Status
                    </TableSortLabel>
                  </TableCell>
                  {/* Detection Reason */}
                  <TableCell>Detection Reason</TableCell>
                  {/* Source */}
                  <TableCell>Source</TableCell>
                  {/* Created Time */}
                  <TableCell>
                    <TableSortLabel
                      active={orderBy === 'created_at'}
                      direction={orderBy === 'created_at' ? order : 'asc'}
                      onClick={() => handleRequestSort('created_at')}
                    >
                      Created Time
                    </TableSortLabel>
                  </TableCell>
                  {/* Actions */}
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={7} sx={{ p: 0 }}>
                      <LoadingState message="Loading incidents..." />
                    </TableCell>
                  </TableRow>
                ) : paginatedIncidents.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} sx={{ p: 0 }}>
                      <EmptyState message="No incidents matching criteria." />
                    </TableCell>
                  </TableRow>
                ) : (
                  paginatedIncidents.map((incident: Incident) => (
                    <TableRow
                      key={incident.id}
                      hover
                      onClick={() => navigate(`/incident/${incident.incident_id}`)}
                      sx={{ cursor: 'pointer' }}
                    >
                      {/* ID */}
                      <TableCell sx={{ fontFamily: 'monospace', fontWeight: 700, color: '#3B82F6' }}>
                        {incident.incident_id}
                      </TableCell>
                      {/* Severity */}
                      <TableCell>
                        <SeverityBadge severity={incident.severity} />
                      </TableCell>
                      {/* Status */}
                      <TableCell>
                        <StatusChip status={incident.status} />
                      </TableCell>
                      {/* Detection Reason */}
                      <TableCell sx={{ fontWeight: 500 }}>
                        {incident.title}
                      </TableCell>
                      {/* Source */}
                      <TableCell sx={{ color: '#D1D5DB' }}>
                        {incident.alert?.source || 'System'}
                      </TableCell>
                      {/* Created Time */}
                      <TableCell sx={{ color: '#9CA3AF' }}>
                        {new Date(incident.created_at).toLocaleString()}
                      </TableCell>
                      {/* Actions */}
                      <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                        <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                          {incident.status === 'open' && (
                            <Tooltip title="Assign to Myself">
                              <IconButton
                                color="primary"
                                onClick={(e) => handleTakeIncident(e, incident.incident_id)}
                                disabled={assignMutation.isPending}
                                sx={{ backgroundColor: '#3B82F610', '&:hover': { backgroundColor: '#3B82F625' } }}
                              >
                                <TakeIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          )}
                          <Tooltip title="View Details">
                            <IconButton
                              onClick={() => navigate(`/incident/${incident.incident_id}`)}
                              sx={{ backgroundColor: '#9CA3AF10', '&:hover': { backgroundColor: '#9CA3AF20' } }}
                            >
                              <ViewIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {/* Pagination */}
        <TablePagination
          rowsPerPageOptions={[5, 10, 25, 50]}
          component="div"
          count={filteredIncidents.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={(_, newPage) => setPage(newPage)}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
          sx={{ borderTop: '1px solid #1F2937' }}
        />
      </Card>

      {/* Snackbar notification feedback */}
      <Snackbar
        open={toast.open}
        autoHideDuration={4000}
        onClose={() => setToast((prev) => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert 
          onClose={() => setToast((prev) => ({ ...prev, open: false }))} 
          severity={toast.severity} 
          sx={{ width: '100%' }}
        >
          {toast.message}
        </Alert>
      </Snackbar>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .spin {
          animation: spin 1s linear infinite;
        }
      `}</style>
    </Box>
  );
}
