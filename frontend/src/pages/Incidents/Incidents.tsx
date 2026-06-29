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
  Chip,
  Button,
  IconButton,
  Tooltip,
  Skeleton,
  Alert,
  Snackbar,
} from '@mui/material';
import {
  Search as SearchIcon,
  Visibility as ViewIcon,
  AssignmentInd as TakeIcon,
  Clear as ClearIcon,
} from '@mui/icons-material';

import { useIncidents, useAssignIncident } from '../../hooks/queries';
import { theme } from '../../theme';
import type { Incident, IncidentStatus, Severity } from '../../types';

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

  // Snackbar Notification State
  const [toast, setToast] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // Queries & Mutations
  const { data: incidents, isLoading, isError } = useIncidents(statusFilter, severityFilter);
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

  // ----------------------------------------------------
  // Color Styling Helpers
  // ----------------------------------------------------
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return theme.palette.severity.critical;
      case 'high': return theme.palette.severity.high;
      case 'medium': return theme.palette.severity.medium;
      case 'low': return theme.palette.severity.low;
      default: return theme.palette.text.secondary;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open': return theme.palette.status.open;
      case 'acknowledged': return theme.palette.status.acknowledged;
      case 'investigating': return theme.palette.status.investigating;
      case 'closed': return theme.palette.status.closed;
      default: return theme.palette.text.secondary;
    }
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3.5 }}>
      {/* Page Title */}
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 800, color: '#F3F4F6', mb: 0.5 }}>
          Incident Investigation Queue
        </Typography>
        <Typography variant="body2" sx={{ color: '#9CA3AF' }}>
          Assign owner, sort, filter, and escalate active cybersecurity threats.
        </Typography>
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
          <Box sx={{ p: 4 }}>
            <Alert severity="error">Failed to fetch incidents. Make sure backend is running.</Alert>
          </Box>
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
                  {/* Title */}
                  <TableCell>Title</TableCell>
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
                  {/* Assigned To */}
                  <TableCell>Assigned Analyst</TableCell>
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
                  Array.from({ length: rowsPerPage }).map((_, i) => (
                    <TableRow key={i}>
                      {Array.from({ length: 7 }).map((_, j) => (
                        <TableCell key={j}><Skeleton height={20} /></TableCell>
                      ))}
                    </TableRow>
                  ))
                ) : paginatedIncidents.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} align="center" sx={{ py: 8, color: '#9CA3AF' }}>
                      No active incidents matching the current search parameters.
                    </TableCell>
                  </TableRow>
                ) : (
                  paginatedIncidents.map((incident: Incident) => (
                    <TableRow
                      key={incident.id}
                      onClick={() => navigate(`/incident/${incident.incident_id}`)}
                      sx={{ cursor: 'pointer' }}
                    >
                      {/* ID */}
                      <TableCell sx={{ fontFamily: 'monospace', fontWeight: 700, color: '#3B82F6' }}>
                        {incident.incident_id}
                      </TableCell>
                      {/* Title */}
                      <TableCell sx={{ fontWeight: 500 }}>
                        {incident.title}
                      </TableCell>
                      {/* Severity */}
                      <TableCell>
                        <Chip
                          label={incident.severity}
                          size="small"
                          sx={{
                            backgroundColor: `${getSeverityColor(incident.severity)}18`,
                            color: getSeverityColor(incident.severity),
                            border: `1px solid ${getSeverityColor(incident.severity)}40`,
                            fontWeight: 700,
                            textTransform: 'uppercase',
                          }}
                        />
                      </TableCell>
                      {/* Status */}
                      <TableCell>
                        <Chip
                          label={incident.status}
                          size="small"
                          sx={{
                            backgroundColor: `${getStatusColor(incident.status)}18`,
                            color: getStatusColor(incident.status),
                            border: `1px solid ${getStatusColor(incident.status)}40`,
                            fontWeight: 600,
                            textTransform: 'uppercase',
                          }}
                        />
                      </TableCell>
                      {/* Assigned Analyst */}
                      <TableCell>
                        {incident.assigned_to ? (
                          <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                            <Typography variant="body2">{incident.assigned_to}</Typography>
                            <Typography variant="caption" sx={{ color: '#9CA3AF', backgroundColor: '#1E293B', px: 0.5, borderRadius: '4px' }}>
                              {incident.assigned_role}
                            </Typography>
                          </Box>
                        ) : (
                          <Typography variant="body2" sx={{ color: '#6B7280', fontStyle: 'italic' }}>
                            Unassigned
                          </Typography>
                        )}
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
    </Box>
  );
}
