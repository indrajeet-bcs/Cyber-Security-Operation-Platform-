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
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        p: 6,
        textAlign: 'center',
        backgroundColor: '#111827',
        border: '1px solid #1F2937',
        borderRadius: '8px',
        mt: 2,
      }}
    >
      <InfoIcon sx={{ fontSize: 48, color: '#3B82F6', mb: 2, opacity: 0.8 }} />
      <Typography variant="h6" sx={{ fontWeight: 600, color: '#F3F4F6', mb: 1 }}>
        {message}
      </Typography>
      <Typography variant="body2" sx={{ color: '#9CA3AF', maxWidth: 400 }}>
        {subMessage}
      </Typography>
    </Paper>
  );
}
