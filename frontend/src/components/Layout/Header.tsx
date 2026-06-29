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
        backgroundColor: '#111827',
        borderBottom: '1px solid #1F2937',
        color: '#F3F4F6',
        width: '100%',
      }}
    >
      <Toolbar sx={{ justifyContent: 'space-between' }}>
        {/* Left Side: System status indicator */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Box
            sx={{
              width: 10,
              height: 10,
              borderRadius: '50%',
              backgroundColor: '#10B981',
              boxShadow: '0 0 8px #10B981',
              animation: 'pulse 2s infinite',
              '@keyframes pulse': {
                '0%': { opacity: 0.6 },
                '50%': { opacity: 1 },
                '100%': { opacity: 0.6 },
              },
            }}
          />
          <Typography variant="body2" sx={{ fontWeight: 600, color: '#10B981', letterSpacing: '0.05em' }}>
            ALL PIPELINES ACTIVE
          </Typography>
        </Box>

        {/* Right Side: Clock, Analyst info, Refresh action */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 3 }}>
          {/* Real-time Clock */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.8, color: '#9CA3AF' }}>
            <TimeIcon sx={{ fontSize: 18 }} />
            <Typography variant="body2" sx={{ fontFamily: 'monospace', fontWeight: 600 }}>
              {time}
            </Typography>
          </Box>

          {/* Refresh Action */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {onRefresh && (
              <Tooltip title="Force Refresh Data">
                <IconButton 
                  color="inherit" 
                  onClick={onRefresh} 
                  disabled={isFetching}
                  sx={{ 
                    color: '#9CA3AF',
                    '&:hover': { color: '#3B82F6' },
                    animation: isFetching ? 'spin 1s linear infinite' : 'none',
                    '@keyframes spin': {
                      '0%': { transform: 'rotate(0deg)' },
                      '100%': { transform: 'rotate(360deg)' },
                    }
                  }}
                >
                  <RefreshIcon />
                </IconButton>
              </Tooltip>
            )}
            <Typography variant="caption" sx={{ color: '#6B7280', display: { xs: 'none', sm: 'block' } }}>
              Updated: {lastUpdated}
            </Typography>
          </Box>

          {/* Analyst Session Chip */}
          <Chip
            icon={<AccountIcon style={{ color: '#60A5FA' }} />}
            label={
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                <Typography variant="body2" sx={{ fontWeight: 700 }}>
                  shubham
                </Typography>
                <Typography variant="caption" sx={{ color: '#9CA3AF', backgroundColor: '#1E293B', px: 0.8, py: 0.2, borderRadius: '4px' }}>
                  SOC_L1
                </Typography>
              </Box>
            }
            sx={{
              backgroundColor: '#1F2937',
              color: '#F3F4F6',
              border: '1px solid #374151',
              py: 2,
              px: 0.5,
            }}
          />
        </Box>
      </Toolbar>
    </AppBar>
  );
}
