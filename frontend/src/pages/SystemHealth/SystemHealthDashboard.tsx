import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Paper,
  CircularProgress,
  Alert,
  LinearProgress,
  Chip,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  FiberManualRecord as DotIcon,
  Speed as CpuIcon,
  Memory as MemoryIcon,
  Storage as DiskIcon,
  Warning as OfflineIcon,
  CheckCircle as OnlineIcon,
  MonitorHeart as HealthIcon,
  TrendingUp as TrendIcon,
} from '@mui/icons-material';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip as ChartTooltip,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts';
import { getSystemMetrics } from '../../api/systemApi';
import type { SystemMetricsResponse, ServiceProcessInfo } from '../../types/systemMetrics';

// ── helpers ──────────────────────────────────────────────────────────────────

function formatGB(gb: number): string {
  return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(gb * 1024).toFixed(0)} MB`;
}

// ── sub-components ────────────────────────────────────────────────────────────

interface MetricCardProps {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  icon: React.ReactNode;
  accentColor: string;
  progress?: number;  // 0-100
}

const MetricCard: React.FC<MetricCardProps> = ({ label, value, sub, icon, accentColor, progress }) => (
  <Card
    elevation={0}
    sx={{
      border: '1px solid #e2e8f0',
      borderRadius: 2,
      backgroundColor: '#ffffff',
      '&:hover': { boxShadow: '0 4px 16px rgba(0,0,0,0.08)', borderColor: accentColor },
      transition: 'box-shadow 0.2s, border-color 0.2s',
    }}
  >
    <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
        <Typography variant="caption" sx={{ color: '#64748b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          {label}
        </Typography>
        <Box sx={{ color: accentColor }}>{icon}</Box>
      </Box>
      <Typography variant="h5" sx={{ color: '#0f172a', fontWeight: 800, lineHeight: 1.2, mb: sub ? 0.25 : 0 }}>
        {value}
      </Typography>
      {sub && (
        <Typography variant="caption" sx={{ color: '#94a3b8' }}>{sub}</Typography>
      )}
      {progress !== undefined && (
        <LinearProgress
          variant="determinate"
          value={Math.min(progress, 100)}
          sx={{
            mt: 1.5, height: 5, borderRadius: 3,
            backgroundColor: '#f1f5f9',
            '& .MuiLinearProgress-bar': {
              backgroundColor:
                progress >= 85 ? '#ef4444' : progress >= 60 ? '#f59e0b' : accentColor,
            },
          }}
        />
      )}
    </CardContent>
  </Card>
);

interface WidgetPaperProps {
  label: string;
  children: React.ReactNode;
  accentColor: string;
}

const WidgetPaper: React.FC<WidgetPaperProps> = ({ label, children, accentColor }) => (
  <Paper
    elevation={0}
    sx={{
      p: 2.5, backgroundColor: '#ffffff',
      border: '1px solid #e2e8f0',
      borderLeft: `4px solid ${accentColor}`,
      borderRadius: 2,
    }}
  >
    <Typography variant="caption" sx={{ color: '#64748b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', mb: 0.75 }}>
      {label}
    </Typography>
    {children}
  </Paper>
);

// ── main component ────────────────────────────────────────────────────────────

export const SystemHealthDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<SystemMetricsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getSystemMetrics();
      setMetrics(data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load system metrics');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMetrics();
    // Auto-refresh every 15 seconds
    const timer = setInterval(fetchMetrics, 15000);
    return () => clearInterval(timer);
  }, [fetchMetrics]);

  // ── derived values ──────────────────────────────────────────────────────────

  const onlineServices: ServiceProcessInfo[] = metrics?.services.filter(s => s.status === 'ONLINE') ?? [];

  // Highest CPU — only from ONLINE services; only pick a winner if at least one has cpu > 0
  const topCpuSvc = (() => {
    if (onlineServices.length === 0) return null;
    const best = onlineServices.reduce((a, b) => (b.cpu_percent > a.cpu_percent ? b : a));
    return best.cpu_percent > 0 ? best : null;   // null means all are 0%
  })();

  const topRamSvc = onlineServices.length > 0
    ? onlineServices.reduce((a, b) => (b.memory_mb > a.memory_mb ? b : a))
    : null;

  // System health score
  const computeHealth = (): { label: string; color: string; bg: string } => {
    if (!metrics) return { label: 'Unknown', color: '#94a3b8', bg: '#f8fafc' };
    const cpu = metrics.cpu_percent;
    const ram = metrics.memory_percent;
    const disk = metrics.disk_percent;
    const offPct = metrics.total_services > 0
      ? (metrics.offline_services / metrics.total_services) * 100 : 0;
    if (cpu > 85 || ram > 90 || disk > 90 || offPct > 30) {
      return { label: 'Critical', color: '#ef4444', bg: '#fef2f2' };
    }
    if (cpu > 65 || ram > 75 || disk > 75 || offPct > 0) {
      return { label: 'Warning', color: '#f59e0b', bg: '#fffbeb' };
    }
    return { label: 'Healthy', color: '#10b981', bg: '#f0fdf4' };
  };

  const health = computeHealth();

  // CPU chart — ONLINE services only; filter out all-zero case for "no activity" message
  const cpuChartData = onlineServices.map(s => ({ name: s.service_name, cpu: s.cpu_percent }));
  const allCpuZero = cpuChartData.every(d => d.cpu === 0);

  // RAM chart — ONLINE services only
  const ramChartData = onlineServices.map(s => ({ name: s.service_name, ram: Math.round(s.memory_mb) }));

  const statusPieData = [
    { name: 'Online', value: metrics?.online_services ?? 0, color: '#10b981' },
    { name: 'Offline', value: metrics?.offline_services ?? 0, color: '#ef4444' },
  ].filter(d => d.value > 0);

  // ── render ──────────────────────────────────────────────────────────────────

  return (
    <Box sx={{ p: 3, maxWidth: 1440, margin: '0 auto', backgroundColor: '#f8fafc', minHeight: '100vh' }}>

      {/* ── Header ── */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 3 }}>
        <Box>
          <Typography variant="h4" sx={{ color: '#0f172a', fontWeight: 800, letterSpacing: '-0.025em', mb: 0.5 }}>
            System &amp; Service Health
          </Typography>
          <Typography variant="body2" sx={{ color: '#64748b' }}>
            Real-time infrastructure monitoring — CPU, memory, disk, and services
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          {metrics && (
            <Typography variant="caption" sx={{ color: '#94a3b8' }}>
              Updated: {new Date(metrics.generated_at).toLocaleTimeString()} · auto-refresh 15s
            </Typography>
          )}
          <Button
            variant="contained"
            startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <RefreshIcon />}
            onClick={fetchMetrics}
            disabled={loading}
            sx={{
              backgroundColor: '#2563eb',
              '&:hover': { backgroundColor: '#1d4ed8' },
              borderRadius: 1.5,
              textTransform: 'none',
              fontWeight: 600,
              px: 2.5,
            }}
          >
            Refresh
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>
      )}

      {loading && !metrics && (
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', py: 16 }}>
          <CircularProgress />
        </Box>
      )}

      {metrics && (
        <>
          {/* ── System Health banner ── */}
          <Paper
            elevation={0}
            sx={{
              p: 2, mb: 3, borderRadius: 2,
              backgroundColor: health.bg,
              border: `1px solid ${health.color}30`,
              display: 'flex', alignItems: 'center', gap: 2,
            }}
          >
            <HealthIcon sx={{ color: health.color, fontSize: 28 }} />
            <Box>
              <Typography variant="subtitle1" sx={{ color: '#0f172a', fontWeight: 700 }}>
                System Status:{' '}
                <span style={{ color: health.color }}>{health.label}</span>
              </Typography>
              <Typography variant="caption" sx={{ color: '#64748b' }}>
                CPU {metrics.cpu_percent}% · RAM {metrics.memory_percent}% · Disk {metrics.disk_percent}% · {metrics.online_services}/{metrics.total_services} services online
              </Typography>
            </Box>
          </Paper>

          {/* ── Summary Cards (5 cards, no Free Memory) ── */}
          <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 2, mb: 3 }}>

            <MetricCard
              label="System Health"
              value={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <DotIcon sx={{ color: health.color, fontSize: 18 }} />
                  <span style={{ color: health.color, fontSize: '1.1rem' }}>{health.label}</span>
                </Box>
              }
              icon={<HealthIcon sx={{ fontSize: 22 }} />}
              accentColor={health.color}
            />

            <MetricCard
              label="Total Services"
              value={metrics.total_services}
              sub={`${metrics.online_services} online · ${metrics.offline_services} offline`}
              icon={<TrendIcon sx={{ fontSize: 22 }} />}
              accentColor="#3b82f6"
            />

            <MetricCard
              label="CPU Usage"
              value={`${metrics.cpu_percent}%`}
              sub={`${metrics.cpu_count_physical} cores (${metrics.cpu_count_logical} logical)`}
              icon={<CpuIcon sx={{ fontSize: 22 }} />}
              accentColor="#f59e0b"
              progress={metrics.cpu_percent}
            />

            <MetricCard
              label="Memory Usage"
              value={`${metrics.memory_percent}%`}
              sub={`${formatGB(metrics.memory_used_gb)} of ${formatGB(metrics.memory_total_gb)}`}
              icon={<MemoryIcon sx={{ fontSize: 22 }} />}
              accentColor="#8b5cf6"
              progress={metrics.memory_percent}
            />

            {/* Disk Usage card — values come directly from the OS via psutil */}
            <MetricCard
              label="Disk Usage"
              value={`${metrics.disk_percent}%`}
              sub={`${formatGB(metrics.disk_used_gb)} used · ${formatGB(metrics.disk_free_gb)} free · Total ${formatGB(metrics.disk_total_gb)}`}
              icon={<DiskIcon sx={{ fontSize: 22 }} />}
              accentColor="#ec4899"
              progress={metrics.disk_percent}
            />
          </Box>

          {/* ── Widgets row (no System Uptime, no Active Connections, no Avg Service Uptime) ── */}
          <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 2, mb: 4 }}>

            <WidgetPaper label="Offline Services" accentColor={metrics.offline_services > 0 ? '#ef4444' : '#10b981'}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {metrics.offline_services > 0
                  ? <OfflineIcon sx={{ color: '#ef4444', fontSize: 20 }} />
                  : <OnlineIcon sx={{ color: '#10b981', fontSize: 20 }} />}
                <Typography variant="h5" sx={{ color: metrics.offline_services > 0 ? '#ef4444' : '#10b981', fontWeight: 800 }}>
                  {metrics.offline_services}
                </Typography>
              </Box>
              <Typography variant="caption" sx={{ color: '#94a3b8' }}>
                {metrics.offline_services === 0 ? 'All services responding' : 'Require attention'}
              </Typography>
            </WidgetPaper>

            {/* Highest CPU Service — shows "No Active CPU Usage" when all are 0% */}
            <WidgetPaper label="Highest CPU Service" accentColor="#f59e0b">
              {topCpuSvc ? (
                <>
                  <Typography variant="h6" sx={{ color: '#0f172a', fontWeight: 700, lineHeight: 1.3 }}>
                    {topCpuSvc.service_name}
                  </Typography>
                  <Typography variant="body2" sx={{ color: '#f59e0b', fontWeight: 600 }}>
                    {topCpuSvc.cpu_percent}% CPU
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#94a3b8' }}>Port {topCpuSvc.port}</Typography>
                </>
              ) : (
                <Typography variant="body2" sx={{ color: '#94a3b8', fontStyle: 'italic' }}>
                  No Active CPU Usage
                </Typography>
              )}
            </WidgetPaper>

            <WidgetPaper label="Highest Memory Service" accentColor="#8b5cf6">
              {topRamSvc ? (
                <>
                  <Typography variant="h6" sx={{ color: '#0f172a', fontWeight: 700, lineHeight: 1.3 }}>
                    {topRamSvc.service_name}
                  </Typography>
                  <Typography variant="body2" sx={{ color: '#8b5cf6', fontWeight: 600 }}>
                    {Math.round(topRamSvc.memory_mb)} MB
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#94a3b8' }}>Port {topRamSvc.port}</Typography>
                </>
              ) : (
                <Typography variant="body2" sx={{ color: '#94a3b8' }}>No online services with memory data</Typography>
              )}
            </WidgetPaper>
          </Box>

          {/* ── Service status list ── */}
          <Paper elevation={0} sx={{ p: 2.5, mb: 3, border: '1px solid #e2e8f0', borderRadius: 2, backgroundColor: '#fff' }}>
            <Typography variant="subtitle1" sx={{ color: '#0f172a', fontWeight: 700, mb: 1.5 }}>
              Services Overview ({metrics.total_services} monitored)
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {metrics.services.map(s => (
                <Chip
                  key={s.port}
                  icon={
                    s.status === 'ONLINE'
                      ? <OnlineIcon sx={{ color: '#10b981 !important', fontSize: '14px !important' }} />
                      : <OfflineIcon sx={{ color: '#ef4444 !important', fontSize: '14px !important' }} />
                  }
                  label={`${s.service_name} :${s.port}`}
                  size="small"
                  sx={{
                    backgroundColor: s.status === 'ONLINE' ? '#f0fdf4' : '#fef2f2',
                    border: `1px solid ${s.status === 'ONLINE' ? '#86efac' : '#fca5a5'}`,
                    color: s.status === 'ONLINE' ? '#166534' : '#991b1b',
                    fontWeight: 600,
                    fontSize: '0.75rem',
                  }}
                />
              ))}
            </Box>
          </Paper>

          {/* ── Charts ── */}
          <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: 3 }}>

            {/* CPU Usage by Service — live values; "No CPU activity" when all are 0% */}
            {cpuChartData.length > 0 && (
              <Paper elevation={0} sx={{ p: 3, border: '1px solid #e2e8f0', borderRadius: 2, backgroundColor: '#fff' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <CpuIcon sx={{ color: '#f59e0b', fontSize: 20 }} />
                  <Typography variant="subtitle1" sx={{ color: '#0f172a', fontWeight: 700 }}>
                    CPU Usage by Service (%) — Online Only
                  </Typography>
                </Box>
                {allCpuZero ? (
                  <Box sx={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Typography variant="body2" sx={{ color: '#94a3b8', fontStyle: 'italic' }}>
                      No CPU activity detected
                    </Typography>
                  </Box>
                ) : (
                  <Box sx={{ height: 240 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={cpuChartData} margin={{ top: 4, right: 8, left: -20, bottom: 30 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                        <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 11 }} interval={0} angle={-15} textAnchor="end" />
                        <YAxis stroke="#94a3b8" unit="%" domain={[0, 100]} />
                        <ChartTooltip contentStyle={{ borderRadius: 8, border: '1px solid #e2e8f0', boxShadow: '0 4px 12px rgba(0,0,0,0.08)' }} />
                        <Bar dataKey="cpu" name="CPU %" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </Box>
                )}
              </Paper>
            )}

            {/* Memory Usage by Service */}
            {ramChartData.length > 0 && (
              <Paper elevation={0} sx={{ p: 3, border: '1px solid #e2e8f0', borderRadius: 2, backgroundColor: '#fff' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <MemoryIcon sx={{ color: '#8b5cf6', fontSize: 20 }} />
                  <Typography variant="subtitle1" sx={{ color: '#0f172a', fontWeight: 700 }}>
                    Memory by Service (MB) — Online Only
                  </Typography>
                </Box>
                <Box sx={{ height: 240 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={ramChartData} margin={{ top: 4, right: 8, left: -10, bottom: 30 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                      <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 11 }} interval={0} angle={-15} textAnchor="end" />
                      <YAxis stroke="#94a3b8" unit=" MB" />
                      <ChartTooltip contentStyle={{ borderRadius: 8, border: '1px solid #e2e8f0', boxShadow: '0 4px 12px rgba(0,0,0,0.08)' }} />
                      <Bar dataKey="ram" name="Memory (MB)" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </Box>
              </Paper>
            )}

            {/* Service Status Distribution */}
            {statusPieData.length > 0 && (
              <Paper elevation={0} sx={{ p: 3, border: '1px solid #e2e8f0', borderRadius: 2, backgroundColor: '#fff' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <OnlineIcon sx={{ color: '#10b981', fontSize: 20 }} />
                  <Typography variant="subtitle1" sx={{ color: '#0f172a', fontWeight: 700 }}>
                    Service Availability
                  </Typography>
                </Box>
                <Box sx={{ height: 240 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={statusPieData} cx="50%" cy="50%" innerRadius={55} outerRadius={85} paddingAngle={4} dataKey="value">
                        {statusPieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                      </Pie>
                      <ChartTooltip contentStyle={{ borderRadius: 8, border: '1px solid #e2e8f0' }} />
                      <Legend verticalAlign="bottom" height={36} />
                    </PieChart>
                  </ResponsiveContainer>
                </Box>
              </Paper>
            )}

            {/* Disk Usage — stacked bar per partition */}
            {metrics.disks.length > 0 && (
              <Paper elevation={0} sx={{ p: 3, border: '1px solid #e2e8f0', borderRadius: 2, backgroundColor: '#fff' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <DiskIcon sx={{ color: '#ec4899', fontSize: 20 }} />
                  <Typography variant="subtitle1" sx={{ color: '#0f172a', fontWeight: 700 }}>
                    Disk Usage
                  </Typography>
                </Box>
                <Box sx={{ height: 240 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={metrics.disks.map(d => ({ name: d.mount_point, used: d.used_gb, free: d.free_gb }))}
                      margin={{ top: 4, right: 8, left: -10, bottom: 10 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                      <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 11 }} />
                      <YAxis stroke="#94a3b8" unit=" GB" />
                      <ChartTooltip
                        contentStyle={{ borderRadius: 8, border: '1px solid #e2e8f0' }}
                        formatter={(value: any, name: any) => [`${Number(value).toFixed(1)} GB`, name === 'used' ? 'Used' : 'Free']}
                      />
                      <Legend />
                      <Bar dataKey="used" name="Used" fill="#ec4899" radius={[4, 4, 0, 0]} stackId="disk" />
                      <Bar dataKey="free" name="Free" fill="#d1d5db" radius={[4, 4, 0, 0]} stackId="disk" />
                    </BarChart>
                  </ResponsiveContainer>
                </Box>
              </Paper>
            )}
          </Box>
        </>
      )}
    </Box>
  );
};
