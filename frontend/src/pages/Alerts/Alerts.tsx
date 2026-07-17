import { Box, Card, CardContent, Typography } from '@mui/material';
import { NotificationsOff as AlertsOffIcon } from '@mui/icons-material';

export default function Alerts() {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3.5, height: '70vh', justifyContent: 'center', alignItems: 'center' }}>
      <Card sx={{ maxWidth: 500, p: 4, textAlign: 'center', border: '1px solid #1F2937' }}>
        <CardContent sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
          <AlertsOffIcon sx={{ fontSize: 64, color: '#F59E0B', opacity: 0.8 }} />
          <Typography variant="h5" sx={{ fontWeight: 800, color: '#F3F4F6' }}>
            Alerts Dispatch Queue
          </Typography>
          <Typography variant="body1" sx={{ color: '#9CA3AF' }}>
            Alerts backend endpoint is not yet available.
          </Typography>
          <Typography variant="body2" sx={{ color: '#6B7280', mt: 1 }}>
            The notification and event classification pipeline operates in the background, but the alerts listing API has not been exposed.
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
}
