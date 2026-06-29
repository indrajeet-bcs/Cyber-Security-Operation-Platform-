
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
} from '@mui/icons-material';

const DRAWER_WIDTH = 260;

export default function Sidebar() {
  const navItems = [
    { text: 'Dashboard', icon: <DashboardIcon />, path: '/', active: true },
    { text: 'Incident Queue', icon: <WarningIcon />, path: '/incidents', active: true },
    { text: 'Alerts', icon: <NotificationsIcon />, path: '/alerts', active: false },
    { text: 'Investigations', icon: <SearchIcon />, path: '/investigations', active: false },
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
          backgroundColor: '#111827',
          borderRight: '1px solid #1F2937',
        },
      }}
    >
      {/* Brand Header */}
      <Box sx={{ p: 2.5, display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <ShieldIcon color="primary" sx={{ fontSize: 32 }} />
        <Typography variant="h6" sx={{ fontWeight: 800, letterSpacing: '0.05em', color: '#F3F4F6' }}>
          Bestowal <span style={{ color: '#3B82F6' }}>SOC</span>
        </Typography>
      </Box>

      <Divider />

      <List sx={{ mt: 2, px: 1 }}>
        {navItems.map((item) => {
          if (item.active) {
            return (
              <ListItem key={item.text} disablePadding sx={{ mb: 0.5 }}>
                <ListItemButton
                  component={NavLink}
                  to={item.path}
                  sx={{
                    borderRadius: '6px',
                    '&:hover': {
                      backgroundColor: '#1F2937',
                    },
                    '&.active': {
                      color: '#3B82F6',
                      backgroundColor: '#1E293B',
                      borderRight: '3px solid #3B82F6',
                    },
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 40, color: 'inherit' }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.text}
                    slotProps={{ primary: { sx: { fontSize: '0.875rem', fontWeight: 500 } } }}
                  />
                </ListItemButton>
              </ListItem>
            );
          } else {
            return (
              <ListItem key={item.text} disablePadding sx={{ mb: 0.5, opacity: 0.4 }}>
                <ListItemButton sx={{ borderRadius: '6px', cursor: 'not-allowed' }}>
                  <ListItemIcon sx={{ minWidth: 40, color: 'inherit' }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.text}
                    secondary="Placeholder"
                    slotProps={{
                      primary: { sx: { fontSize: '0.875rem', fontWeight: 500 } },
                      secondary: { sx: { fontSize: '0.7rem' } },
                    }}
                  />
                </ListItemButton>
              </ListItem>
            );
          }
        })}
      </List>
    </Drawer>
  );
}
