import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  TextField,
  InputAdornment,
  Button,
  Grid,
  CircularProgress,
  Alert,
  Divider,
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  Circle as CircleIcon,
  Speed as CpuIcon,
  Memory as MemoryIcon,
  TrendingUp as ConnectionIcon,
  AccessTime as UptimeIcon,
} from '@mui/icons-material';
import { getLivePortStatus } from '../../api/portTrafficApi';
import type { LivePortStatusResponse, LivePortInfo } from '../../types/portTraffic';

export const ServiceInformationPage: React.FC = () => {
  const [liveStatus, setLiveStatus] = useState<LivePortStatusResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ONLINE' | 'WARNING' | 'OFFLINE'>('ALL');

  const fetchServices = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getLivePortStatus(6);
      setLiveStatus(data);
    } catch (err: any) {
      console.error('Failed to load service information:', err);
      setError(err.message || 'Failed to load service information');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchServices();
  }, []);

  const formatUptime = (seconds?: number): string => {
    if (!seconds || seconds <= 0) return 'Offline / Idle';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  const formatRelativeTime = (iso?: string | null): string => {
    if (!iso) return 'Not available';
    const date = new Date(iso);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffSec = Math.round(diffMs / 1000);
    const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    if (diffSec < 60) return `Just now (${timeStr})`;
    if (diffSec < 3600) {
      const m = Math.floor(diffSec / 60);
      return `${m}m ago (${timeStr})`;
    }
    if (diffSec < 86400) {
      const h = Math.floor(diffSec / 3600);
      return `${h}h ago (${timeStr})`;
    }
    return `${date.toLocaleDateString([], { month: 'short', day: 'numeric' })} at ${timeStr}`;
  };

  const getServiceStatusDetails = (service: LivePortInfo) => {
    if (service.current_status === 'OPEN_AND_ACTIVE') {
      return { label: 'Online', bg: '#F0FDF4', color: '#15803D', border: '#BBF7D0', dot: '#16A34A', badge: 'Online' };
    }
    if (service.current_status === 'OPEN_IDLE') {
      return { label: 'Online (Idle)', bg: '#F0FDF4', color: '#15803D', border: '#BBF7D0', dot: '#16A34A', badge: 'Online' };
    }
    return { label: 'Offline', bg: '#FEF2F2', color: '#B91C1C', border: '#FECACA', dot: '#DC2626', badge: 'Offline' };
  };

  const ports = liveStatus?.ports || [];

  const filteredPorts = ports.filter((port) => {
    const matchesSearch =
      port.service_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      port.port.toString().includes(searchQuery);

    const isOnline = port.current_status === 'OPEN_AND_ACTIVE' || port.current_status === 'OPEN_IDLE';
    const isOffline = port.current_status === 'CLOSED';

    if (statusFilter === 'ONLINE') return matchesSearch && isOnline;
    if (statusFilter === 'OFFLINE') return matchesSearch && isOffline;
    return matchesSearch;
  });

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h5" sx={{ color: '#0F172A', fontWeight: 800 }}>
            Monitored Services Directory
          </Typography>
          <Typography variant="body2" sx={{ color: '#64748B', mt: 0.5 }}>
            Directory of all monitored system services, binding ports, socket metrics, uptime & memory usage.
          </Typography>
        </Box>

        <Button
          variant="outlined"
          startIcon={<RefreshIcon className={loading ? 'spin' : ''} />}
          onClick={fetchServices}
          disabled={loading}
          size="small"
          sx={{
            borderColor: '#CBD5E1',
            color: '#334155',
            '&:hover': { borderColor: '#2563EB', backgroundColor: '#EFF6FF' },
          }}
        >
          Refresh Directory
        </Button>
      </Box>

      {/* Filter and Search Bar */}
      <Card>
        <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, alignItems: 'center', justifyContent: 'space-between' }}>
            <TextField
              placeholder="Search service name or port number..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              size="small"
              sx={{ minWidth: 320 }}
              slotProps={{
                input: {
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon sx={{ color: '#94A3B8' }} />
                    </InputAdornment>
                  ),
                },
              }}
            />

            <Box sx={{ display: 'flex', gap: 1 }}>
              <Chip
                label="All Services"
                clickable
                onClick={() => setStatusFilter('ALL')}
                sx={{
                  fontWeight: 700,
                  backgroundColor: statusFilter === 'ALL' ? '#2563EB' : '#F1F5F9',
                  color: statusFilter === 'ALL' ? '#FFFFFF' : '#475569',
                  '&:hover': { backgroundColor: statusFilter === 'ALL' ? '#1D4ED8' : '#E2E8F0' },
                }}
              />
              <Chip
                icon={<CircleIcon sx={{ fontSize: '8px !important', color: statusFilter === 'ONLINE' ? '#FFFFFF' : '#16A34A' }} />}
                label="Online Services"
                clickable
                onClick={() => setStatusFilter('ONLINE')}
                sx={{
                  fontWeight: 700,
                  backgroundColor: statusFilter === 'ONLINE' ? '#16A34A' : '#F0FDF4',
                  color: statusFilter === 'ONLINE' ? '#FFFFFF' : '#15803D',
                  border: statusFilter === 'ONLINE' ? 'none' : '1px solid #BBF7D0',
                  '&:hover': { backgroundColor: statusFilter === 'ONLINE' ? '#15803D' : '#DCFCE7' },
                }}
              />
              <Chip
                icon={<CircleIcon sx={{ fontSize: '8px !important', color: statusFilter === 'OFFLINE' ? '#FFFFFF' : '#DC2626' }} />}
                label="Offline Services"
                clickable
                onClick={() => setStatusFilter('OFFLINE')}
                sx={{
                  fontWeight: 700,
                  backgroundColor: statusFilter === 'OFFLINE' ? '#DC2626' : '#FEF2F2',
                  color: statusFilter === 'OFFLINE' ? '#FFFFFF' : '#B91C1C',
                  border: statusFilter === 'OFFLINE' ? 'none' : '1px solid #FECACA',
                  '&:hover': { backgroundColor: statusFilter === 'OFFLINE' ? '#B91C1C' : '#FEE2E2' },
                }}
              />
            </Box>
          </Box>
        </CardContent>
      </Card>

      {error && (
        <Alert severity="error" sx={{ borderRadius: '10px' }}>
          {error}
        </Alert>
      )}

      {loading && !liveStatus && (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 12 }}>
          <CircularProgress color="primary" />
        </Box>
      )}

      {/* Services Grid */}
      {liveStatus && (
        <Grid container spacing={2.5}>
          {filteredPorts.map((service) => {
            const statusInfo = getServiceStatusDetails(service);
            const isOffline = service.current_status === 'CLOSED';

            return (
              <Grid size={{ xs: 12, sm: 6, md: 4 }} key={service.port}>
                <Card
                  sx={{
                    backgroundColor: '#FFFFFF',
                    border: `1px solid ${isOffline ? '#FECACA' : '#E2E8F0'}`,
                    borderTop: `4px solid ${statusInfo.dot}`,
                    borderRadius: '10px',
                    boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.04)',
                    transition: 'transform 0.15s ease-in-out, box-shadow 0.15s ease-in-out',
                    '&:hover': {
                      transform: 'translateY(-2px)',
                      boxShadow: '0 4px 12px 0 rgba(0, 0, 0, 0.08)',
                    },
                  }}
                >
                  <CardContent sx={{ p: 2.5 }}>
                    {/* Header: Service Name, Port & Status */}
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                      <Box>
                        <Typography variant="h6" sx={{ color: '#0F172A', fontWeight: 800, fontSize: '1rem', lineHeight: 1.3 }}>
                          {service.service_name}
                        </Typography>
                        <Typography variant="caption" sx={{ color: '#2563EB', fontWeight: 700, fontFamily: 'monospace', display: 'block', mt: 0.5 }}>
                          Port: {service.port} ({service.protocol})
                        </Typography>
                      </Box>

                      <Chip
                        label={
                          <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                            <span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: statusInfo.dot }} />
                            {statusInfo.badge}
                          </span>
                        }
                        size="small"
                        sx={{
                          backgroundColor: statusInfo.bg,
                          color: statusInfo.color,
                          border: `1px solid ${statusInfo.border}`,
                          fontWeight: 700,
                          fontSize: '0.7rem',
                        }}
                      />
                    </Box>

                    <Divider sx={{ borderColor: '#E2E8F0', mb: 2 }} />

                    {/* Metrics Grid */}
                    <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1.5, mb: 2 }}>
                      <Box sx={{ backgroundColor: '#F8FAFC', border: '1px solid #F1F5F9', p: 1.5, borderRadius: '8px' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                          <CpuIcon sx={{ color: '#D97706', fontSize: 16 }} />
                          <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 600 }}>
                            CPU Usage
                          </Typography>
                        </Box>
                        <Typography variant="body1" sx={{ color: '#0F172A', fontWeight: 800 }}>
                          {isOffline ? '0%' : `${service.cpu_percent ?? 0}%`}
                        </Typography>
                      </Box>

                      <Box sx={{ backgroundColor: '#F8FAFC', border: '1px solid #F1F5F9', p: 1.5, borderRadius: '8px' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                          <MemoryIcon sx={{ color: '#7C3AED', fontSize: 16 }} />
                          <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 600 }}>
                            RAM
                          </Typography>
                        </Box>
                        <Typography variant="body1" sx={{ color: '#0F172A', fontWeight: 800 }}>
                          {isOffline ? '0 MB' : `${Math.round(service.memory_mb ?? 0)} MB`}
                        </Typography>
                      </Box>

                      <Box sx={{ backgroundColor: '#F8FAFC', border: '1px solid #F1F5F9', p: 1.5, borderRadius: '8px' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                          <ConnectionIcon sx={{ color: '#2563EB', fontSize: 16 }} />
                          <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 600 }}>
                            Connections
                          </Typography>
                        </Box>
                        <Typography variant="body1" sx={{ color: '#0F172A', fontWeight: 800 }}>
                          {service.current_active_connections}
                        </Typography>
                      </Box>

                      <Box sx={{ backgroundColor: '#F8FAFC', border: '1px solid #F1F5F9', p: 1.5, borderRadius: '8px' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                          <UptimeIcon sx={{ color: '#16A34A', fontSize: 16 }} />
                          <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 600 }}>
                            Uptime
                          </Typography>
                        </Box>
                        <Typography variant="body2" sx={{ color: '#0F172A', fontWeight: 800 }}>
                          {isOffline ? 'N/A' : formatUptime(service.uptime_seconds)}
                        </Typography>
                      </Box>
                    </Box>

                    {/* Timeline & Metadata */}
                    <Box sx={{ backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', p: 1.5, borderRadius: '8px' }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                        <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 500 }}>
                          Process Name:
                        </Typography>
                        <Typography variant="caption" sx={{ color: '#0F172A', fontFamily: 'monospace', fontWeight: 700 }}>
                          {service.process_name || 'System / Unbound'}
                        </Typography>
                      </Box>

                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                        <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 500 }}>
                          First Seen:
                        </Typography>
                        <Typography variant="caption" sx={{ color: '#334155', fontWeight: 600 }}>
                          {formatRelativeTime(service.first_activity)}
                        </Typography>
                      </Box>

                      <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                        <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 500 }}>
                          Last Seen:
                        </Typography>
                        <Typography variant="caption" sx={{ color: '#334155', fontWeight: 600 }}>
                          {formatRelativeTime(service.last_activity)}
                        </Typography>
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}
    </Box>
  );
};
