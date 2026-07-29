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
          backgroundColor: '#FEF2F2',
          border: '1px solid #FCA5A5',
          color: '#991B1B',
          '& .MuiAlert-icon': {
            color: '#EF4444',
          },
        }}
      >
        <Typography variant="body1" sx={{ fontWeight: 600 }}>
          {message}
        </Typography>
        {error && (
          <Typography variant="caption" sx={{ display: 'block', mt: 1, color: '#7F1D1D' }}>
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
              borderColor: '#FCA5A5',
              color: '#DC2626',
              backgroundColor: '#FFFFFF',
              '&:hover': {
                borderColor: '#EF4444',
                backgroundColor: '#FEF2F2',
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
