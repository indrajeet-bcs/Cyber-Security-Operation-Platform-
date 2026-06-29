import { useNavigate } from 'react-router-dom';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Skeleton,
  Alert,
  Button,
} from '@mui/material';
import {
  Warning as CriticalIcon,
  Error as HighIcon,
  Help as MedIcon,
  Info as LowIcon,
  FolderOpen as OpenIcon,
  CheckCircle as ClosedIcon,
  AssignmentTurnedIn as AckIcon,
  HourglassEmpty as InvIcon,
  ArrowForward as ArrowForwardIcon,
  Storage as DatabaseIcon,
  Shield as ShieldIcon,
} from '@mui/icons-material';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
  Tooltip as ChartTooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';

import { useDashboardSummary, useIncidents } from '../../hooks/queries';
import { theme } from '../../theme';
import type { Incident } from '../../types';

export default function Dashboard() {
  const navigate = useNavigate();

  // Queries
  const { 
    data: summary, 
    isLoading: summaryLoading, 
    isError: summaryError, 
    error: summaryErrObj 
  } = useDashboardSummary();

  const { 
    data: incidents, 
    isLoading: incidentsLoading, 
    isError: incidentsError 
  } = useIncidents('', ''); // Fetch all without filters

  // Get only latest 5 incidents for dashboard
  const recentIncidents = incidents ? incidents.slice(0, 5) : [];

  // ----------------------------------------------------
  // Render Helpers
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

  // ----------------------------------------------------
  // Chart Data Preparation
  // ----------------------------------------------------
  const severityChartData = summary ? [
    { name: 'Critical', value: summary.critical_incidents, color: theme.palette.severity.critical },
    { name: 'High', value: summary.high_incidents, color: theme.palette.severity.high },
    { name: 'Medium', value: summary.medium_incidents, color: theme.palette.severity.medium },
    { name: 'Low', value: summary.low_incidents, color: theme.palette.severity.low },
  ].filter(d => d.value > 0) : [];

  const statusChartData = summary ? [
    { name: 'Open', value: summary.open_incidents, color: theme.palette.status.open },
    { name: 'Acknowledged', value: summary.acknowledged_incidents, color: theme.palette.status.acknowledged },
    { name: 'Investigating', value: summary.investigating_incidents, color: theme.palette.status.investigating },
    { name: 'Closed', value: summary.closed_incidents, color: theme.palette.status.closed },
  ].filter(d => d.value > 0) : [];

  if (summaryError || incidentsError) {
    return (
      <Box sx={{ mt: 4 }}>
        <Alert severity="error" sx={{ backgroundColor: '#1F1015', border: '1px solid #F87171' }}>
          Failed to load dashboard metrics. Ensure the backend FastAPI server is running.
          {summaryErrObj ? ` Error details: ${(summaryErrObj as any).message}` : ''}
        </Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3.5 }}>
      {/* Title Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 800, color: '#F3F4F6', mb: 0.5 }}>
            Security Monitoring Dashboard
          </Typography>
          <Typography variant="body2" sx={{ color: '#9CA3AF' }}>
            Real-time SIEM activity, metrics, and recent alert escalation queues.
          </Typography>
        </Box>
        <Button 
          variant="contained" 
          onClick={() => navigate('/incidents')}
          endIcon={<ArrowForwardIcon />}
        >
          View Full Queue
        </Button>
      </Box>

      {/* 1. KPI Cards Grid — 5 per row (10 total) */}
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)', md: 'repeat(3, 1fr)', lg: 'repeat(5, 1fr)' }, gap: 2.5 }}>
        {[
          // Row 1
          { title: 'Total Logs',      value: summary?.total_logs,              icon: <DatabaseIcon />,  color: '#3B82F6',                          type: 'raw' },
          { title: 'Total Incidents', value: summary?.total_incidents,          icon: <ShieldIcon />,    color: '#8B5CF6',                          type: 'raw' },
          { title: 'Open',            value: summary?.open_incidents,           icon: <OpenIcon />,      color: theme.palette.status.open,          type: 'status' },
          { title: 'Acknowledged',    value: summary?.acknowledged_incidents,   icon: <AckIcon />,       color: theme.palette.status.acknowledged,   type: 'status' },
          { title: 'Investigating',   value: summary?.investigating_incidents,  icon: <InvIcon />,       color: theme.palette.status.investigating,  type: 'status' },
          // Row 2
          { title: 'Closed',          value: summary?.closed_incidents,         icon: <ClosedIcon />,    color: theme.palette.status.closed,        type: 'status' },
          { title: 'Critical',        value: summary?.critical_incidents,       icon: <CriticalIcon />,  color: theme.palette.severity.critical,    type: 'severity' },
          { title: 'High',            value: summary?.high_incidents,           icon: <HighIcon />,      color: theme.palette.severity.high,        type: 'severity' },
          { title: 'Medium',          value: summary?.medium_incidents,         icon: <MedIcon />,       color: theme.palette.severity.medium,      type: 'severity' },
          { title: 'Low',             value: summary?.low_incidents,            icon: <LowIcon />,       color: theme.palette.severity.low,         type: 'severity' },
        ].map((kpi, idx) => (
          <Card
            key={idx}
            sx={{
              position: 'relative',
              overflow: 'hidden',
              transition: 'all 0.3s ease',
              '&:hover': {
                transform: 'translateY(-4px)',
                boxShadow: `0 8px 24px rgba(0,0,0,0.5)`,
                borderColor: kpi.color,
              },
            }}
          >
            {/* Colour accent bar at top */}
            <Box sx={{ position: 'absolute', top: 0, left: 0, right: 0, height: 4, backgroundColor: kpi.color }} />

            <CardContent sx={{ p: 2.5 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Box>
                  <Typography variant="caption" sx={{ color: '#9CA3AF', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                    {kpi.type === 'raw' ? kpi.title : `${kpi.title} Incidents`}
                  </Typography>
                  {summaryLoading ? (
                    <Skeleton width={80} height={40} sx={{ mt: 1 }} />
                  ) : (
                    <Typography variant="h4" sx={{ fontWeight: 800, mt: 0.5, color: '#F3F4F6' }}>
                      {typeof kpi.value === 'number' ? kpi.value.toLocaleString() : (kpi.value ?? 0)}
                    </Typography>
                  )}
                </Box>
                <Box
                  sx={{
                    p: 1.5,
                    borderRadius: '8px',
                    backgroundColor: `${kpi.color}18`,
                    color: kpi.color,
                    display: 'flex',
                    alignItems: 'center',
                  }}
                >
                  {kpi.icon}
                </Box>
              </Box>
            </CardContent>
          </Card>
        ))}
      </Box>

      {/* 2. Visual Charts Container */}
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' }, gap: 3 }}>
        {/* Severity chart */}
        <Card sx={{ height: 380, display: 'flex', flexDirection: 'column' }}>
          <CardContent sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: '#F3F4F6' }}>
              Severity Distribution
            </Typography>
            {summaryLoading ? (
              <Skeleton variant="rectangular" height="100%" />
            ) : severityChartData.length === 0 ? (
              <Box sx={{ flexGrow: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Typography variant="body2" sx={{ color: '#6B7280' }}>
                  No active severity logs found.
                </Typography>
              </Box>
            ) : (
              <Box sx={{ flexGrow: 1, minHeight: 250 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={90}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {severityChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <ChartTooltip
                      contentStyle={{ backgroundColor: '#111827', border: '1px solid #1F2937', color: '#F3F4F6' }}
                    />
                    <Legend verticalAlign="bottom" height={36} />
                  </PieChart>
                </ResponsiveContainer>
              </Box>
            )}
          </CardContent>
        </Card>

        {/* Status chart */}
        <Card sx={{ height: 380, display: 'flex', flexDirection: 'column' }}>
          <CardContent sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: '#F3F4F6' }}>
              Incident Status Distribution
            </Typography>
            {summaryLoading ? (
              <Skeleton variant="rectangular" height="100%" />
            ) : statusChartData.length === 0 ? (
              <Box sx={{ flexGrow: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Typography variant="body2" sx={{ color: '#6B7280' }}>
                  No active incident states found.
                </Typography>
              </Box>
            ) : (
              <Box sx={{ flexGrow: 1, minHeight: 250 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={statusChartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" />
                    <XAxis dataKey="name" stroke="#9CA3AF" />
                    <YAxis stroke="#9CA3AF" allowDecimals={false} />
                    <ChartTooltip
                      contentStyle={{ backgroundColor: '#111827', border: '1px solid #1F2937', color: '#F3F4F6' }}
                    />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {statusChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </Box>
            )}
          </CardContent>
        </Card>
      </Box>

      {/* 3. Recent Incidents Table */}
      <Card sx={{ border: '1px solid #1F2937' }}>
        <Box sx={{ p: 2.5, borderBottom: '1px solid #1F2937', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6" sx={{ fontWeight: 700, color: '#F3F4F6' }}>
            Recent Incidents
          </Typography>
          <Chip label="Live Feed" color="success" size="small" variant="outlined" />
        </Box>
        <TableContainer component={Paper} sx={{ backgroundColor: 'transparent', boxShadow: 'none', border: 'none' }}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Incident ID</TableCell>
                <TableCell>Title</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Assigned To</TableCell>
                <TableCell>Created Time</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {incidentsLoading ? (
                Array.from({ length: 3 }).map((_, i) => (
                  <TableRow key={i}>
                    {Array.from({ length: 7 }).map((_, j) => (
                      <TableCell key={j}><Skeleton height={20} /></TableCell>
                    ))}
                  </TableRow>
                ))
              ) : recentIncidents.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center" sx={{ py: 6, color: '#9CA3AF' }}>
                    No recent incidents found. Ensure logs and alerts are being processed.
                  </TableCell>
                </TableRow>
              ) : (
                recentIncidents.map((incident: Incident) => (
                  <TableRow 
                    key={incident.id}
                    onClick={() => navigate(`/incident/${incident.incident_id}`)}
                    sx={{ cursor: 'pointer' }}
                  >
                    {/* ID */}
                    <TableCell sx={{ fontFamily: 'monospace', fontWeight: 700, color: '#60A5FA' }}>
                      {incident.incident_id}
                    </TableCell>
                    {/* Title */}
                    <TableCell sx={{ fontWeight: 500, color: '#E5E7EB' }}>
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
                    <TableCell sx={{ color: '#E5E7EB' }}>
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
                    {/* Action button */}
                    <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                      <Button
                        variant="outlined"
                        size="small"
                        onClick={() => navigate(`/incident/${incident.incident_id}`)}
                      >
                        Investigate
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Card>
    </Box>
  );
}
