import { Box, Typography, Button, Alert } from '@mui/material';
import { Refresh as RefreshIcon } from '@mui/icons-material';

interface ErrorStateProps {
  message?: string;
  error?: any;
  onRetry?: () => void;
}

export default function ErrorState({
  message = 'Unable to connect to backend server. Please verify your connection or check that the service is active.',
  error,
  onRetry,
}: ErrorStateProps) {
  return (
    <Box sx={{ my: 3, display: 'flex', flexDirection: 'column', gap: 2 }}>
      <Alert
        severity="error"
        sx={{
          backgroundColor: '#1F1015',
          border: '1px solid #F87171',
          color: '#F87171',
          '& .MuiAlert-icon': {
            color: '#F87171',
          },
        }}
      >
        <Typography variant="body1" sx={{ fontWeight: 500 }}>
          {message}
        </Typography>
        {error && (
          <Typography variant="caption" sx={{ display: 'block', mt: 1, opacity: 0.8 }}>
            Details: {error.message || String(error)}
          </Typography>
        )}
      </Alert>
      {onRetry && (
        <Box sx={{ display: 'flex' }}>
          <Button
            variant="outlined"
            color="error"
            startIcon={<RefreshIcon />}
            onClick={onRetry}
            sx={{
              borderColor: '#F87171',
              color: '#F87171',
              '&:hover': {
                borderColor: '#EF4444',
                backgroundColor: 'rgba(248, 113, 113, 0.08)',
              },
            }}
          >
            Retry Connection
          </Button>
        </Box>
      )}
    </Box>
  );
}
