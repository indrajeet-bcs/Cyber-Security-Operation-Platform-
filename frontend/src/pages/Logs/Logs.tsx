import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
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
  Switch,
  FormControlLabel,
  Drawer,
  Divider,
  Grid,
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  Close as CloseIcon,
  Storage as StorageIcon,
  Security as SecurityIcon,
  Code as CodeIcon,
} from '@mui/icons-material';

import { useLogs } from '../../hooks/queries';
import SeverityBadge from '../../components/SeverityBadge';
import LoadingState from '../../components/LoadingState';
import ErrorState from '../../components/ErrorState';
import EmptyState from '../../components/EmptyState';
import type { LogResponse, Severity } from '../../types';

type Order = 'asc' | 'desc';

export default function Logs() {
  // Query options & state
  const [limit, setLimit] = useState(250); // Fetch latest 250 logs
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number | false>(10000); // 10s default
  
  // Table filters
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [suspiciousFilter, setSuspiciousFilter] = useState<'all' | 'suspicious' | 'normal'>('all');
  
  // Table sorting
  const [orderBy, setOrderBy] = useState<keyof LogResponse>('timestamp');
  const [order, setOrder] = useState<Order>('desc');
  
  // Table pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  
  // Detail Drawer state
  const [selectedLog, setSelectedLog] = useState<LogResponse | null>(null);

  // TanStack Query to fetch logs
  const {
    data: logs,
    isLoading,
    isError,
    refetch,
  } = useLogs(0, limit, autoRefreshInterval);

  // Reset page when filters change
  useEffect(() => {
    setPage(0);
  }, [search, severityFilter, suspiciousFilter]);

  // Handle Sort Toggle
  const handleRequestSort = (property: keyof LogResponse) => {
    const isAsc = orderBy === property && order === 'asc';
    setOrder(isAsc ? 'desc' : 'asc');
    setOrderBy(property);
  };

  // Helper: Sort and filter logs
  const getProcessedLogs = (): LogResponse[] => {
    if (!logs) return [];

    let result = [...logs];

    // 1. Text Search Filter
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (log) =>
          log.message?.toLowerCase().includes(q) ||
          log.source?.toLowerCase().includes(q) ||
          log.event_type?.toLowerCase().includes(q) ||
          log.host?.toLowerCase().includes(q) ||
          log.source_ip?.toLowerCase().includes(q) ||
          log.user?.toLowerCase().includes(q)
      );
    }

    // 2. Severity Filter
    if (severityFilter !== 'all') {
      result = result.filter((log) => log.severity === severityFilter);
    }

    // 3. Suspicious Detection Filter
    if (suspiciousFilter !== 'all') {
      const isSuspicious = suspiciousFilter === 'suspicious';
      result = result.filter((log) => (log.detection?.is_suspicious ?? false) === isSuspicious);
    }

    // 4. Sorting
    result.sort((a, b) => {
      let valA = a[orderBy];
      let valB = b[orderBy];

      // Handle nulls
      if (valA === null || valA === undefined) return order === 'asc' ? 1 : -1;
      if (valB === null || valB === undefined) return order === 'asc' ? -1 : 1;

      // Handle custom fields
      if (orderBy === 'timestamp') {
        const timeA = new Date(valA as string).getTime();
        const timeB = new Date(valB as string).getTime();
        return order === 'asc' ? timeA - timeB : timeB - timeA;
      }

      if (typeof valA === 'string' && typeof valB === 'string') {
        return order === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
      }

      return order === 'asc' ? (valA as any) - (valB as any) : (valB as any) - (valA as any);
    });

    return result;
  };

  const processedLogs = getProcessedLogs();
  
  // Paginated chunk
  const paginatedLogs = processedLogs.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  const handlePageChange = (_: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleRowsPerPageChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleRefreshClick = () => {
    refetch();
  };

  // Metrics helper
  const suspiciousCount = logs ? logs.filter(l => l.detection?.is_suspicious).length : 0;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3.5 }}>
      {/* Title block */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 800, color: '#F3F4F6', mb: 0.5 }}>
            SIEM Security Activity Logs
          </Typography>
          <Typography variant="body2" sx={{ color: '#9CA3AF' }}>
            Real-time ingestion and threat intelligence correlation on incoming SOC events.
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <FormControlLabel
            control={
              <Switch
                checked={autoRefreshInterval !== false}
                onChange={(e) => setAutoRefreshInterval(e.target.checked ? 10000 : false)}
                color="primary"
              />
            }
            label={
              <Typography variant="body2" sx={{ color: '#9CA3AF' }}>
                Auto Refresh (10s)
              </Typography>
            }
          />
          <Button
            variant="contained"
            startIcon={<RefreshIcon />}
            onClick={handleRefreshClick}
          >
            Manual Refresh
          </Button>
        </Box>
      </Box>

      {/* KPI Cards Row */}
      <Grid container spacing={2.5}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Box>
                <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', fontWeight: 600 }}>
                  Fetched Logs Count
                </Typography>
                <Typography variant="h4" sx={{ fontWeight: 800, mt: 0.5, color: '#F3F4F6' }}>
                  {logs?.length ?? 0}
                </Typography>
              </Box>
              <Box sx={{ p: 1.5, borderRadius: '8px', backgroundColor: 'rgba(59, 130, 246, 0.1)', color: '#3B82F6' }}>
                <StorageIcon />
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Box>
                <Typography variant="caption" sx={{ color: '#EF4444', textTransform: 'uppercase', fontWeight: 600 }}>
                  Suspicious Events
                </Typography>
                <Typography variant="h4" sx={{ fontWeight: 800, mt: 0.5, color: '#EF4444' }}>
                  {suspiciousCount}
                </Typography>
              </Box>
              <Box sx={{ p: 1.5, borderRadius: '8px', backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#EF4444' }}>
                <SecurityIcon />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Filters bar */}
      <Card sx={{ p: 2 }}>
        <Grid container spacing={2} sx={{ alignItems: 'center' }}>
          <Grid size={{ xs: 12, md: 4 }}>
            <TextField
              fullWidth
              variant="outlined"
              size="small"
              placeholder="Search by source, event type, message..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              slotProps={{
                input: {
                  startAdornment: <SearchIcon sx={{ color: '#6B7280', mr: 1, fontSize: 20 }} />,
                }
              }}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2.5 }}>
            <FormControl fullWidth size="small">
              <InputLabel>Severity</InputLabel>
              <Select
                value={severityFilter}
                label="Severity"
                onChange={(e) => setSeverityFilter(e.target.value as Severity | 'all')}
              >
                <MenuItem value="all">All Severities</MenuItem>
                <MenuItem value="low">Low</MenuItem>
                <MenuItem value="medium">Medium</MenuItem>
                <MenuItem value="high">High</MenuItem>
                <MenuItem value="critical">Critical</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 2.5 }}>
            <FormControl fullWidth size="small">
              <InputLabel>Detection Status</InputLabel>
              <Select
                value={suspiciousFilter}
                label="Detection Status"
                onChange={(e) => setSuspiciousFilter(e.target.value as 'all' | 'suspicious' | 'normal')}
              >
                <MenuItem value="all">All Traffic</MenuItem>
                <MenuItem value="suspicious">Suspicious</MenuItem>
                <MenuItem value="normal">Normal</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <FormControl fullWidth size="small">
              <InputLabel>Fetch Volume</InputLabel>
              <Select
                value={limit}
                label="Fetch Volume"
                onChange={(e) => {
                  setLimit(Number(e.target.value));
                  setPage(0);
                }}
              >
                <MenuItem value={100}>Latest 100 logs</MenuItem>
                <MenuItem value={250}>Latest 250 logs</MenuItem>
                <MenuItem value={500}>Latest 500 logs</MenuItem>
              </Select>
            </FormControl>
          </Grid>
        </Grid>
      </Card>

      {/* Main logs display area */}
      {isLoading ? (
        <LoadingState cols={6} rows={10} />
      ) : isError ? (
        <ErrorState onRetry={refetch} />
      ) : processedLogs.length === 0 ? (
        <EmptyState message="No Logs Found" subMessage="Check that logs are being pushed to `/api/logs` or loosen search filters." />
      ) : (
        <Paper sx={{ border: '1px solid #1F2937' }}>
          <TableContainer>
            <Table size="medium">
              <TableHead>
                <TableRow>
                  <TableCell width={110}>
                    <TableSortLabel
                      active={orderBy === 'severity'}
                      direction={orderBy === 'severity' ? order : 'desc'}
                      onClick={() => handleRequestSort('severity')}
                    >
                      Severity
                    </TableSortLabel>
                  </TableCell>
                  <TableCell width={190}>
                    <TableSortLabel
                      active={orderBy === 'timestamp'}
                      direction={orderBy === 'timestamp' ? order : 'desc'}
                      onClick={() => handleRequestSort('timestamp')}
                    >
                      Timestamp
                    </TableSortLabel>
                  </TableCell>
                  <TableCell width={130}>
                    <TableSortLabel
                      active={orderBy === 'source'}
                      direction={orderBy === 'source' ? order : 'asc'}
                      onClick={() => handleRequestSort('source')}
                    >
                      Source
                    </TableSortLabel>
                  </TableCell>
                  <TableCell width={160}>
                    <TableSortLabel
                      active={orderBy === 'event_type'}
                      direction={orderBy === 'event_type' ? order : 'asc'}
                      onClick={() => handleRequestSort('event_type')}
                    >
                      Event Type
                    </TableSortLabel>
                  </TableCell>
                  <TableCell>
                    <TableSortLabel
                      active={orderBy === 'message'}
                      direction={orderBy === 'message' ? order : 'asc'}
                      onClick={() => handleRequestSort('message')}
                    >
                      Log Message
                    </TableSortLabel>
                  </TableCell>
                  <TableCell width={150}>Threat Scan</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {paginatedLogs.map((log) => {
                  const isSuspicious = log.detection?.is_suspicious ?? false;
                  return (
                    <TableRow
                      key={log.id}
                      hover
                      onClick={() => setSelectedLog(log)}
                      sx={{ cursor: 'pointer' }}
                    >
                      <TableCell>
                        <SeverityBadge severity={log.severity} />
                      </TableCell>
                      <TableCell sx={{ color: '#E5E7EB', fontSize: '0.8rem', fontFamily: 'monospace' }}>
                        {new Date(log.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell sx={{ fontWeight: 600, color: '#F3F4F6' }}>
                        {log.source}
                      </TableCell>
                      <TableCell sx={{ fontFamily: 'monospace', color: '#60A5FA', fontSize: '0.8rem' }}>
                        {log.event_type}
                      </TableCell>
                      <TableCell sx={{ color: '#D1D5DB', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden', maxWidth: '35vw' }}>
                        {log.message}
                      </TableCell>
                      <TableCell>
                        {isSuspicious ? (
                          <Typography variant="body2" sx={{ color: '#EF4444', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            ⚠️ SUSPICIOUS
                          </Typography>
                        ) : (
                          <Typography variant="body2" sx={{ color: '#10B981', fontWeight: 600 }}>
                            ✓ Secure
                          </Typography>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
          <TablePagination
            rowsPerPageOptions={[10, 25, 50]}
            component="div"
            count={processedLogs.length}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handlePageChange}
            onRowsPerPageChange={handleRowsPerPageChange}
            sx={{ borderTop: '1px solid #1F2937' }}
          />
        </Paper>
      )}

      {/* Log Details Sliding Drawer */}
      <Drawer
        anchor="right"
        open={selectedLog !== null}
        onClose={() => setSelectedLog(null)}
        sx={{
          '& .MuiDrawer-paper': {
            width: { xs: '100%', sm: 500, md: 650 },
            backgroundColor: '#0F172A',
            borderLeft: '1px solid #1E293B',
            p: 3,
            boxSizing: 'border-box',
          }
        }}
      >
        {selectedLog && (
          <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
            {/* Header info */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                <StorageIcon color="primary" />
                <Typography variant="h5" sx={{ fontWeight: 800, color: '#F3F4F6' }}>
                  Log Record Details
                </Typography>
              </Box>
              <IconButton onClick={() => setSelectedLog(null)} sx={{ color: '#9CA3AF' }}>
                <CloseIcon />
              </IconButton>
            </Box>

            <Divider sx={{ mb: 3 }} />

            <Box sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column', gap: 2.5, overflowY: 'auto', pr: 1 }}>
              {/* Basic Fields */}
              <Box>
                <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', fontWeight: 600 }}>
                  Log Record ID
                </Typography>
                <Typography variant="body1" sx={{ fontWeight: 600, color: '#E5E7EB', fontFamily: 'monospace' }}>
                  #{selectedLog.id}
                </Typography>
              </Box>

              <Grid container spacing={2}>
                <Grid size={{ xs: 6 }}>
                  <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', fontWeight: 600 }}>
                    Severity
                  </Typography>
                  <Box sx={{ mt: 0.5 }}>
                    <SeverityBadge severity={selectedLog.severity} size="medium" />
                  </Box>
                </Grid>
                <Grid size={{ xs: 6 }}>
                  <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', fontWeight: 600 }}>
                    Source
                  </Typography>
                  <Typography variant="body1" sx={{ mt: 0.5, fontWeight: 700, color: '#F3F4F6' }}>
                    {selectedLog.source}
                  </Typography>
                </Grid>
              </Grid>

              <Grid container spacing={2}>
                <Grid size={{ xs: 6 }}>
                  <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', fontWeight: 600 }}>
                    Event Type
                  </Typography>
                  <Typography variant="body1" sx={{ mt: 0.5, fontFamily: 'monospace', color: '#60A5FA', fontWeight: 600 }}>
                    {selectedLog.event_type}
                  </Typography>
                </Grid>
                <Grid size={{ xs: 6 }}>
                  <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', fontWeight: 600 }}>
                    Source IP
                  </Typography>
                  <Typography variant="body1" sx={{ mt: 0.5, fontFamily: 'monospace', color: '#E5E7EB' }}>
                    {selectedLog.source_ip || 'N/A'}
                  </Typography>
                </Grid>
              </Grid>

              <Grid container spacing={2}>
                <Grid size={{ xs: 6 }}>
                  <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', fontWeight: 600 }}>
                    Host
                  </Typography>
                  <Typography variant="body1" sx={{ mt: 0.5, color: '#E5E7EB' }}>
                    {selectedLog.host || 'N/A'}
                  </Typography>
                </Grid>
                <Grid size={{ xs: 6 }}>
                  <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', fontWeight: 600 }}>
                    User / Account
                  </Typography>
                  <Typography variant="body1" sx={{ mt: 0.5, color: '#E5E7EB' }}>
                    {selectedLog.user || 'N/A'}
                  </Typography>
                </Grid>
              </Grid>

              <Box>
                <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', fontWeight: 600 }}>
                  Event Timestamp
                </Typography>
                <Typography variant="body1" sx={{ color: '#E5E7EB', mt: 0.5, fontFamily: 'monospace' }}>
                  {new Date(selectedLog.timestamp).toUTCString()} ({new Date(selectedLog.timestamp).toLocaleString()})
                </Typography>
              </Box>

              <Box>
                <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', fontWeight: 600 }}>
                  Log Message
                </Typography>
                <Paper sx={{ p: 2, mt: 0.5, bgcolor: '#070A13', border: '1px solid #1E293B', color: '#F3F4F6', wordBreak: 'break-all' }}>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {selectedLog.message}
                  </Typography>
                </Paper>
              </Box>

              {/* Threat Scan Analysis */}
              <Box>
                <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', fontWeight: 600 }}>
                  Threat Detection Scan Result
                </Typography>
                <Paper
                  sx={{
                    p: 2.5,
                    mt: 0.5,
                    border: '1px solid',
                    borderColor: selectedLog.detection?.is_suspicious ? '#EF444440' : '#10B98140',
                    backgroundColor: selectedLog.detection?.is_suspicious ? 'rgba(239, 68, 68, 0.04)' : 'rgba(16, 185, 129, 0.04)',
                  }}
                >
                  <Typography
                    variant="h6"
                    sx={{
                      fontSize: '1rem',
                      fontWeight: 700,
                      color: selectedLog.detection?.is_suspicious ? '#EF4444' : '#10B981',
                      mb: selectedLog.detection?.is_suspicious ? 1 : 0,
                    }}
                  >
                    {selectedLog.detection?.is_suspicious ? '⚠️ Suspicious Traffic Flagged' : '✓ Legitimate Activity Verified'}
                  </Typography>
                  {selectedLog.detection?.is_suspicious && (
                    <>
                      <Typography variant="body2" sx={{ color: '#F3F4F6', fontWeight: 500, mb: 1 }}>
                        <span style={{ color: '#9CA3AF' }}>Reason:</span> {selectedLog.detection.reason}
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                        <Typography variant="caption" sx={{ color: '#9CA3AF' }}>
                          Detection Severity:
                        </Typography>
                        <SeverityBadge severity={selectedLog.detection.severity} />
                      </Box>
                    </>
                  )}
                </Paper>
              </Box>

              {/* Collapsible raw metadata inspector */}
              <Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                  <CodeIcon fontSize="small" sx={{ color: '#3B82F6' }} />
                  <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', fontWeight: 600 }}>
                    Log Metadata (JSON)
                  </Typography>
                </Box>
                <Paper
                  component="pre"
                  sx={{
                    p: 2,
                    m: 0,
                    backgroundColor: '#070A13',
                    border: '1px solid #1E293B',
                    borderRadius: '6px',
                    color: '#34D399',
                    fontSize: '0.775rem',
                    fontFamily: 'monospace',
                    overflowX: 'auto',
                    maxHeight: 250,
                  }}
                >
                  {JSON.stringify(
                    {
                      fingerprint: selectedLog.metadata?.event_fingerprint || 'N/A',
                      record_number: selectedLog.record_number,
                      ingested_at: selectedLog.ingested_at,
                      ...selectedLog.metadata,
                    },
                    null,
                    2
                  )}
                </Paper>
              </Box>
            </Box>
          </Box>
        )}
      </Drawer>
    </Box>
  );
}
