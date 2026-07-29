import { Chip } from '@mui/material';

interface StatusChipProps {
  status: string;
  size?: 'small' | 'medium';
}

const STATUS_CONFIG: Record<string, { bg: string; color: string; border: string; dot: string }> = {
  open:          { bg: '#EFF6FF', color: '#1D4ED8', border: '#BFDBFE', dot: '#2563EB' },
  new:           { bg: '#EFF6FF', color: '#1D4ED8', border: '#BFDBFE', dot: '#2563EB' },
  acknowledged:  { bg: '#FFF7ED', color: '#C2410C', border: '#FED7AA', dot: '#EA580C' },
  investigating: { bg: '#FFFBEB', color: '#B45309', border: '#FDE68A', dot: '#D97706' },
  resolved:      { bg: '#F0FDF4', color: '#15803D', border: '#BBF7D0', dot: '#16A34A' },
  closed:        { bg: '#F0FDF4', color: '#15803D', border: '#BBF7D0', dot: '#16A34A' },
  suspicious:    { bg: '#FFFBEB', color: '#B45309', border: '#FDE68A', dot: '#D97706' },
  safe:          { bg: '#F0FDF4', color: '#15803D', border: '#BBF7D0', dot: '#16A34A' },
  malicious:     { bg: '#FEF2F2', color: '#B91C1C', border: '#FECACA', dot: '#DC2626' },
};

const DEFAULT_CONFIG = { bg: '#F8FAFC', color: '#475569', border: '#E2E8F0', dot: '#64748B' };

export default function StatusChip({ status, size = 'small' }: StatusChipProps) {
  const config = STATUS_CONFIG[status.toLowerCase()] || DEFAULT_CONFIG;

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
          {status.toUpperCase()}
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
