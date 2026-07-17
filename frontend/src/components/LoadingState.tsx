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
        <Typography variant="body2" sx={{ mb: 1, color: '#9CA3AF' }}>
          {message}
        </Typography>
      )}
      <TableContainer component={Paper} sx={{ border: '1px solid #1F2937', mt: 2 }}>
        <Table>
        <TableHead>
          <TableRow>
            {Array.from({ length: cols }).map((_, idx) => (
              <TableCell key={idx}>
                <Skeleton variant="text" width={85} height={24} sx={{ bgcolor: 'rgba(255, 255, 255, 0.08)' }} />
              </TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {Array.from({ length: rows }).map((_, rowIdx) => (
            <TableRow key={rowIdx}>
              {Array.from({ length: cols }).map((_, colIdx) => (
                <TableCell key={colIdx}>
                  <Skeleton variant="rectangular" height={22} sx={{ bgcolor: 'rgba(255, 255, 255, 0.05)', borderRadius: '4px' }} />
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
