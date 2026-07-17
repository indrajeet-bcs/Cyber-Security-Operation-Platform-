import { Chip, useTheme } from '@mui/material';

interface StatusChipProps {
  status: string;
  size?: 'small' | 'medium';
}

export default function StatusChip({ status, size = 'small' }: StatusChipProps) {
  const theme = useTheme();

  const getStatusColor = (stat: string) => {
    switch (stat.toLowerCase()) {
      case 'open':
        return theme.palette.status?.open || '#3B82F6';
      case 'acknowledged':
        return theme.palette.status?.acknowledged || '#F97316';
      case 'investigating':
        return theme.palette.status?.investigating || '#EAB308';
      case 'closed':
        return theme.palette.status?.closed || '#10B981';
      default:
        return theme.palette.text.secondary;
    }
  };

  const color = getStatusColor(status);

  return (
    <Chip
      size={size}
      label={status.toUpperCase()}
      sx={{
        backgroundColor: `${color}18`,
        color: color,
        border: `1px solid ${color}40`,
        fontWeight: 700,
        borderRadius: '4px',
      }}
    />
  );
}
