import { Chip } from '@mui/material';

interface SeverityBadgeProps {
  severity: string;
  size?: 'small' | 'medium';
}

const SEVERITY_CONFIG: Record<string, { bg: string; color: string; border: string; dot: string }> = {
  critical: { bg: '#FEF2F2', color: '#B91C1C', border: '#FECACA', dot: '#DC2626' },
  high:     { bg: '#FFF7ED', color: '#C2410C', border: '#FED7AA', dot: '#EA580C' },
  medium:   { bg: '#FFFBEB', color: '#B45309', border: '#FDE68A', dot: '#D97706' },
  low:      { bg: '#F0FDF4', color: '#15803D', border: '#BBF7D0', dot: '#16A34A' },
  safe:     { bg: '#F0FDF4', color: '#15803D', border: '#BBF7D0', dot: '#16A34A' },
  info:     { bg: '#EFF6FF', color: '#1D4ED8', border: '#BFDBFE', dot: '#2563EB' },
};

const DEFAULT_CONFIG = { bg: '#F8FAFC', color: '#475569', border: '#E2E8F0', dot: '#64748B' };

export default function SeverityBadge({ severity, size = 'small' }: SeverityBadgeProps) {
  const config = SEVERITY_CONFIG[severity.toLowerCase()] || DEFAULT_CONFIG;

  return (
    <Chip
      size={size}
      label={
        <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: '50%',
              backgroundColor: config.dot,
              display: 'inline-block',
              flexShrink: 0,
            }}
          />
          {severity.toUpperCase()}
        </span>
      }
      sx={{
        backgroundColor: config.bg,
        color: config.color,
        border: `1px solid ${config.border}`,
        fontWeight: 700,
        borderRadius: '6px',
        fontSize: '0.7rem',
        letterSpacing: '0.03em',
        height: size === 'small' ? 24 : 28,
      }}
    />
  );
}
