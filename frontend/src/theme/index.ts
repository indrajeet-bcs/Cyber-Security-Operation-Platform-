import { createTheme } from '@mui/material/styles';

declare module '@mui/material/styles' {
  interface Palette {
    severity: {
      critical: string;
      high: string;
      medium: string;
      low: string;
    };
    status: {
      open: string;
      acknowledged: string;
      investigating: string;
      closed: string;
    };
  }
  interface PaletteOptions {
    severity?: {
      critical?: string;
      high?: string;
      medium?: string;
      low?: string;
    };
    status?: {
      open?: string;
      acknowledged?: string;
      investigating?: string;
      closed?: string;
    };
  }
}

export const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#3B82F6', // Cyber Blue
      light: '#60A5FA',
      dark: '#1D4ED8',
    },
    secondary: {
      main: '#10B981', // Emerald Green
      light: '#34D399',
      dark: '#047857',
    },
    background: {
      default: '#0B0F19', // Deep Space Black
      paper: '#111827',   // Dark Slate Card
    },
    text: {
      primary: '#F3F4F6',   // Off-white
      secondary: '#9CA3AF', // Muted Grey
    },
    divider: '#1F2937',     // Border lines
    severity: {
      critical: '#EF4444',
      high: '#F97316',
      medium: '#F59E0B',
      low: '#10B981',
    },
    status: {
      open: '#3B82F6',
      acknowledged: '#F97316',
      investigating: '#EAB308',
      closed: '#10B981',
    },
  },
  typography: {
    fontFamily: [
      'Inter',
      'Outfit',
      'Roboto',
      '-apple-system',
      'BlinkMacSystemFont',
      '"Segoe UI"',
      'sans-serif',
    ].join(','),
    h4: {
      fontWeight: 700,
      letterSpacing: '-0.02em',
    },
    h5: {
      fontWeight: 700,
      letterSpacing: '-0.01em',
    },
    h6: {
      fontWeight: 600,
      letterSpacing: '0.01em',
    },
    subtitle1: {
      fontWeight: 500,
    },
    body1: {
      fontSize: '0.925rem',
      lineHeight: 1.6,
    },
    body2: {
      fontSize: '0.8125rem',
      lineHeight: 1.5,
    },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundColor: '#0B0F19',
          color: '#F3F4F6',
          scrollbarColor: '#1F2937 #0B0F19',
          '&::-webkit-scrollbar': {
            width: '8px',
            height: '8px',
          },
          '&::-webkit-scrollbar-track': {
            backgroundColor: '#0B0F19',
          },
          '&::-webkit-scrollbar-thumb': {
            backgroundColor: '#1F2937',
            borderRadius: '4px',
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 600,
          borderRadius: '6px',
          padding: '6px 16px',
        },
        contained: {
          background: 'linear-gradient(135deg, #3B82F6 0%, #1D4ED8 100%)',
          boxShadow: '0 4px 12px rgba(59, 130, 246, 0.25)',
          '&:hover': {
            background: 'linear-gradient(135deg, #60A5FA 0%, #3B82F6 100%)',
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: '#111827',
          borderRadius: '8px',
          border: '1px solid #1F2937',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.4)',
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderBottom: '1px solid #1F2937',
          padding: '14px 16px',
        },
        head: {
          backgroundColor: '#182235',
          fontWeight: 600,
          color: '#F3F4F6',
        },
      },
    },
    MuiTableRow: {
      styleOverrides: {
        root: {
          '&:hover': {
            backgroundColor: '#1C2535 !important',
          },
        },
      },
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          backgroundColor: '#111827',
          border: '1px solid #1F2937',
          borderRadius: '10px',
        },
      },
    },
  },
});
