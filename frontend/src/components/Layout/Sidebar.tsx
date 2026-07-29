import { NavLink } from 'react-router-dom';
import {
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Typography,
  Box,
  Divider,
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Warning as WarningIcon,
  Notifications as NotificationsIcon,
  Search as SearchIcon,
  Security as SecurityIcon,
  Settings as SettingsIcon,
  Shield as ShieldIcon,
  Storage as DatabaseIcon,
  MonitorHeart as MonitorIcon,
  Dns as DnsIcon,
} from '@mui/icons-material';

const DRAWER_WIDTH = 260;

export default function Sidebar() {
  const navItems = [
    { text: 'Dashboard', icon: <DashboardIcon />, path: '/', active: true },
    { text: 'System Health', icon: <MonitorIcon />, path: '/system-health', active: true },
    { text: 'Service Information', icon: <DnsIcon />, path: '/service-information', active: true },
    { text: 'Logs', icon: <DatabaseIcon />, path: '/logs', active: true },
    { text: 'Incident Queue', icon: <WarningIcon />, path: '/incidents', active: true },
    { text: 'Alerts', icon: <NotificationsIcon />, path: '/alerts', active: true },
    { text: 'Investigations', icon: <SearchIcon />, path: '/investigations', active: true },
    { text: 'Threat Intel', icon: <SecurityIcon />, path: '/intel', active: false },
    { text: 'Settings', icon: <SettingsIcon />, path: '/settings', active: false },
  ];

  return (
    <Drawer
      variant="permanent"
      sx={{
        width: DRAWER_WIDTH,
        flexShrink: 0,
        [`& .MuiDrawer-paper`]: {
          width: DRAWER_WIDTH,
          boxSizing: 'border-box',
          backgroundColor: '#FFFFFF',
          borderRight: '1px solid #E2E8F0',
          boxShadow: '1px 0 4px 0 rgba(0,0,0,0.03)',
        },
      }}
    >
      {/* Brand Header */}
      <Box sx={{ p: 2.5, display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Box
          sx={{
            width: 36,
            height: 36,
            borderRadius: '8px',
            background: 'linear-gradient(135deg, #2563EB 0%, #1D4ED8 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <ShieldIcon sx={{ fontSize: 22, color: '#FFFFFF' }} />
        </Box>
        <Typography variant="h6" sx={{ fontWeight: 800, letterSpacing: '0.03em', color: '#0F172A', fontSize: '1.05rem' }}>
          Bestowal <span style={{ color: '#2563EB' }}>SOC</span>
        </Typography>
      </Box>

      <Divider sx={{ borderColor: '#E2E8F0' }} />

      <List sx={{ mt: 1.5, px: 1.5 }}>
        {navItems.map((item) => {
          if (item.active) {
            return (
              <ListItem key={item.text} disablePadding sx={{ mb: 0.4 }}>
                <ListItemButton
                  component={NavLink}
                  to={item.path}
                  sx={{
                    borderRadius: '8px',
                    color: '#475569',
                    py: 0.9,
                    transition: 'all 0.15s ease',
                    '&:hover': {
                      backgroundColor: '#F1F5F9',
                      color: '#1E293B',
                    },
                    '&.active': {
                      color: '#2563EB',
                      backgroundColor: '#EFF6FF',
                      fontWeight: 700,
                      boxShadow: 'inset 3px 0 0 0 #2563EB',
                      '& .MuiListItemIcon-root': {
                        color: '#2563EB',
                      },
                      '& .MuiListItemText-primary': {
                        fontWeight: 700,
                      },
                    },
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 38, color: 'inherit' }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.text}
                    slotProps={{ primary: { sx: { fontSize: '0.85rem', fontWeight: 600 } } }}
                  />
                </ListItemButton>
              </ListItem>
            );
          } else {
            return (
              <ListItem key={item.text} disablePadding sx={{ mb: 0.4, opacity: 0.4 }}>
                <ListItemButton sx={{ borderRadius: '8px', cursor: 'not-allowed', py: 0.9 }}>
                  <ListItemIcon sx={{ minWidth: 38, color: '#94A3B8' }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.text}
                    secondary="Coming Soon"
                    slotProps={{
                      primary: { sx: { fontSize: '0.85rem', fontWeight: 500, color: '#64748B' } },
                      secondary: { sx: { fontSize: '0.65rem', color: '#94A3B8' } },
                    }}
                  />
                </ListItemButton>
              </ListItem>
            );
          }
        })}
      </List>

      {/* Sidebar footer */}
      <Box sx={{ mt: 'auto', p: 2, borderTop: '1px solid #E2E8F0' }}>
        <Typography variant="caption" sx={{ color: '#94A3B8', fontSize: '0.68rem', display: 'block', textAlign: 'center' }}>
          Bestowal SOC Platform v1.0
        </Typography>
      </Box>
    </Drawer>
  );
}
