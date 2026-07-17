import { Chip, useTheme } from '@mui/material';

interface SeverityBadgeProps {
  severity: string;
  size?: 'small' | 'medium';
}

export default function SeverityBadge({ severity, size = 'small' }: SeverityBadgeProps) {
  const theme = useTheme();

  const getSeverityColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return theme.palette.severity?.critical || '#EF4444';
      case 'high':
        return theme.palette.severity?.high || '#F97316';
      case 'medium':
        return theme.palette.severity?.medium || '#F59E0B';
      case 'low':
        return theme.palette.severity?.low || '#10B981';
      default:
        return theme.palette.text.secondary;
    }
  };

  const color = getSeverityColor(severity);

  return (
    <Chip
      size={size}
      label={severity.toUpperCase()}
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
