import { Skeleton, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, Typography, Box } from '@mui/material';

interface LoadingStateProps {
  rows?: number;
  cols?: number;
  message?: string;
}

export default function LoadingState({ rows = 5, cols = 6, message }: LoadingStateProps) {
  return (
    <Box>
      {message && (
        <Typography variant="body2" sx={{ mb: 1, color: '#6B7280' }}>
          {message}
        </Typography>
      )}
      <TableContainer component={Paper} elevation={0} sx={{ border: '1px solid #E5E7EB', borderRadius: '8px', mt: 2, backgroundColor: '#FFFFFF' }}>
        <Table>
          <TableHead>
            <TableRow sx={{ backgroundColor: '#F8FAFC' }}>
              {Array.from({ length: cols }).map((_, idx) => (
                <TableCell key={idx}>
                  <Skeleton variant="text" width={85} height={24} sx={{ bgcolor: '#E2E8F0' }} />
                </TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {Array.from({ length: rows }).map((_, rowIdx) => (
              <TableRow key={rowIdx}>
                {Array.from({ length: cols }).map((_, colIdx) => (
                  <TableCell key={colIdx}>
                    <Skeleton variant="rectangular" height={22} sx={{ bgcolor: '#F1F5F9', borderRadius: '4px' }} />
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}
