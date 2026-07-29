import { Paper, Typography } from '@mui/material';
import { InfoOutlined as InfoIcon } from '@mui/icons-material';

interface EmptyStateProps {
  message: string;
  subMessage?: string;
}

export default function EmptyState({
  message,
  subMessage = 'No records matching your search queries or active filters were found.',
}: EmptyStateProps) {
  return (
    <Paper
      elevation={0}
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        p: 6,
        textAlign: 'center',
        backgroundColor: '#FFFFFF',
        border: '1px solid #E5E7EB',
        borderRadius: '8px',
        mt: 2,
      }}
    >
      <InfoIcon sx={{ fontSize: 48, color: '#2563EB', mb: 2, opacity: 0.8 }} />
      <Typography variant="h6" sx={{ fontWeight: 600, color: '#111827', mb: 1 }}>
        {message}
      </Typography>
      <Typography variant="body2" sx={{ color: '#6B7280', maxWidth: 400 }}>
        {subMessage}
      </Typography>
    </Paper>
  );
}
