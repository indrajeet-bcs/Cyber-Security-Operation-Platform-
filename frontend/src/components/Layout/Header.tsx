import { useEffect, useState } from 'react';
import { AppBar, Toolbar, Typography, Box, IconButton, Tooltip, Chip } from '@mui/material';
import { Refresh as RefreshIcon, AccountCircle as AccountIcon, AccessTime as TimeIcon } from '@mui/icons-material';

interface HeaderProps {
  onRefresh?: () => void;
  isFetching?: boolean;
}

export default function Header({ onRefresh, isFetching }: HeaderProps) {
  const [time, setTime] = useState(new Date().toLocaleTimeString());

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date().toLocaleTimeString());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const lastUpdated = new Date().toLocaleTimeString();

  return (
    <AppBar
      position="sticky"
      elevation={0}
      sx={{
        backgroundColor: '#FFFFFF',
        borderBottom: '1px solid #E2E8F0',
        color: '#0F172A',
        width: '100%',
        boxShadow: '0 1px 3px 0 rgba(0,0,0,0.03)',
      }}
    >
      <Toolbar sx={{ justifyContent: 'space-between', minHeight: '56px !important' }}>
        {/* Left Side: System status indicator */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Box
            sx={{
              width: 9,
              height: 9,
              borderRadius: '50%',
              backgroundColor: '#22C55E',
              boxShadow: '0 0 6px rgba(34,197,94,0.6)',
              animation: 'pulse 2s infinite',
              '@keyframes pulse': {
                '0%': { opacity: 0.6 },
                '50%': { opacity: 1 },
                '100%': { opacity: 0.6 },
              },
            }}
          />
          <Typography variant="body2" sx={{ fontWeight: 700, color: '#16A34A', letterSpacing: '0.04em', fontSize: '0.75rem' }}>
            ALL PIPELINES ACTIVE
          </Typography>
        </Box>

        {/* Right Side: Clock, Analyst info, Refresh action */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2.5 }}>
          {/* Real-time Clock */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.6, color: '#64748B' }}>
            <TimeIcon sx={{ fontSize: 16 }} />
            <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace', fontWeight: 600, color: '#334155', fontSize: '0.8rem' }}>
              {time}
            </Typography>
          </Box>

          {/* Refresh Action */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.8 }}>
            {onRefresh && (
              <Tooltip title="Force Refresh Data">
                <IconButton 
                  color="inherit" 
                  onClick={onRefresh} 
                  disabled={isFetching}
                  size="small"
                  sx={{ 
                    color: '#64748B',
                    '&:hover': { color: '#2563EB', backgroundColor: '#EFF6FF' },
                    animation: isFetching ? 'spin 1s linear infinite' : 'none',
                    '@keyframes spin': {
                      '0%': { transform: 'rotate(0deg)' },
                      '100%': { transform: 'rotate(360deg)' },
                    }
                  }}
                >
                  <RefreshIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            )}
            <Typography variant="caption" sx={{ color: '#94A3B8', display: { xs: 'none', sm: 'block' }, fontSize: '0.7rem' }}>
              {lastUpdated}
            </Typography>
          </Box>

          {/* Analyst Session Chip */}
          <Chip
            icon={<AccountIcon style={{ color: '#2563EB', fontSize: 20 }} />}
            label={
              <Box sx={{ display: 'flex', gap: 0.8, alignItems: 'center' }}>
                <Typography variant="body2" sx={{ fontWeight: 700, color: '#0F172A', fontSize: '0.8rem' }}>
                  shubham
                </Typography>
                <Typography
                  variant="caption"
                  sx={{
                    color: '#2563EB',
                    backgroundColor: '#EFF6FF',
                    px: 0.8,
                    py: 0.15,
                    borderRadius: '4px',
                    fontWeight: 700,
                    fontSize: '0.65rem',
                    border: '1px solid #BFDBFE',
                  }}
                >
                  SOC_L1
                </Typography>
              </Box>
            }
            sx={{
              backgroundColor: '#F8FAFC',
              color: '#0F172A',
              border: '1px solid #E2E8F0',
              py: 2,
              px: 0.5,
              borderRadius: '8px',
            }}
          />
        </Box>
      </Toolbar>
    </AppBar>
  );
}
