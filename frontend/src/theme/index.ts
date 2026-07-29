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
    mode: 'light',
    primary: {
      main: '#2563EB',
      light: '#60A5FA',
      dark: '#1D4ED8',
    },
    secondary: {
      main: '#22C55E',
      light: '#4ADE80',
      dark: '#15803D',
    },
    background: {
      default: '#F5F7FA',
      paper: '#FFFFFF',
    },
    text: {
      primary: '#0F172A',
      secondary: '#64748B',
    },
    divider: '#E2E8F0',
    severity: {
      critical: '#DC2626',
      high: '#EA580C',
      medium: '#D97706',
      low: '#16A34A',
    },
    status: {
      open: '#2563EB',
      acknowledged: '#EA580C',
      investigating: '#D97706',
      closed: '#16A34A',
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
      fontWeight: 800,
      letterSpacing: '-0.025em',
      color: '#0F172A',
    },
    h5: {
      fontWeight: 700,
      letterSpacing: '-0.01em',
      color: '#0F172A',
    },
    h6: {
      fontWeight: 700,
      letterSpacing: '0.005em',
      color: '#0F172A',
    },
    subtitle1: {
      fontWeight: 600,
      color: '#1E293B',
    },
    body1: {
      fontSize: '0.925rem',
      lineHeight: 1.6,
      color: '#1E293B',
    },
    body2: {
      fontSize: '0.8125rem',
      lineHeight: 1.5,
      color: '#64748B',
    },
    caption: {
      color: '#64748B',
      fontWeight: 500,
    },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundColor: '#F5F7FA',
          color: '#0F172A',
          scrollbarColor: '#CBD5E1 #F5F7FA',
          '&::-webkit-scrollbar': {
            width: '7px',
            height: '7px',
          },
          '&::-webkit-scrollbar-track': {
            backgroundColor: '#F1F5F9',
          },
          '&::-webkit-scrollbar-thumb': {
            backgroundColor: '#CBD5E1',
            borderRadius: '8px',
            '&:hover': {
              backgroundColor: '#94A3B8',
            },
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 600,
          borderRadius: '8px',
          padding: '7px 18px',
          fontSize: '0.8125rem',
        },
        contained: {
          backgroundColor: '#2563EB',
          color: '#FFFFFF',
          boxShadow: '0 1px 3px 0 rgba(37, 99, 235, 0.2), 0 1px 2px 0 rgba(37, 99, 235, 0.1)',
          '&:hover': {
            backgroundColor: '#1D4ED8',
            boxShadow: '0 4px 8px -2px rgba(37, 99, 235, 0.3)',
          },
        },
        outlined: {
          borderColor: '#D1D5DB',
          color: '#374151',
          backgroundColor: '#FFFFFF',
          '&:hover': {
            borderColor: '#2563EB',
            color: '#2563EB',
            backgroundColor: '#EFF6FF',
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: '#FFFFFF',
          borderRadius: '10px',
          border: '1px solid #E2E8F0',
          boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.04), 0 1px 2px -1px rgba(0, 0, 0, 0.03)',
          transition: 'box-shadow 0.2s ease, border-color 0.2s ease',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: '#FFFFFF',
          borderRadius: '10px',
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderBottom: '1px solid #F1F5F9',
          padding: '13px 16px',
          color: '#1E293B',
          fontSize: '0.8125rem',
        },
        head: {
          backgroundColor: '#F8FAFC',
          fontWeight: 700,
          color: '#0F172A',
          borderBottom: '2px solid #E2E8F0',
          fontSize: '0.75rem',
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
        },
      },
    },
    MuiTableRow: {
      styleOverrides: {
        root: {
          '&:nth-of-type(even)': {
            backgroundColor: '#FAFBFD',
          },
          '&:hover': {
            backgroundColor: '#EFF6FF !important',
          },
          transition: 'background-color 0.15s ease',
        },
      },
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          backgroundColor: '#FFFFFF',
          border: '1px solid #E2E8F0',
          borderRadius: '12px',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.15)',
        },
      },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          backgroundColor: '#FFFFFF',
          borderRadius: '8px',
          fontSize: '0.875rem',
          '& fieldset': {
            borderColor: '#D1D5DB',
            borderWidth: '1.5px',
          },
          '&:hover fieldset': {
            borderColor: '#94A3B8 !important',
          },
          '&.Mui-focused fieldset': {
            borderColor: '#2563EB !important',
            borderWidth: '2px !important',
          },
        },
      },
    },
    MuiInputLabel: {
      styleOverrides: {
        root: {
          color: '#64748B',
          fontWeight: 500,
          fontSize: '0.875rem',
          '&.Mui-focused': {
            color: '#2563EB',
          },
        },
      },
    },
    MuiSelect: {
      styleOverrides: {
        root: {
          borderRadius: '8px',
          fontSize: '0.875rem',
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          fontWeight: 600,
          borderRadius: '6px',
          fontSize: '0.7rem',
          letterSpacing: '0.03em',
        },
      },
    },
    MuiTablePagination: {
      styleOverrides: {
        root: {
          borderTop: '1px solid #E2E8F0',
          color: '#64748B',
        },
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          backgroundColor: '#1E293B',
          color: '#F8FAFC',
          fontSize: '0.75rem',
          borderRadius: '6px',
          padding: '6px 12px',
        },
      },
    },
    MuiAccordion: {
      styleOverrides: {
        root: {
          backgroundColor: '#FFFFFF',
          border: '1px solid #E2E8F0',
          borderRadius: '10px !important',
          boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.04)',
          '&:before': { display: 'none' },
        },
      },
    },
    MuiTabs: {
      styleOverrides: {
        indicator: {
          backgroundColor: '#2563EB',
          height: '3px',
          borderRadius: '3px 3px 0 0',
        },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 600,
          fontSize: '0.875rem',
          color: '#64748B',
          '&.Mui-selected': {
            color: '#2563EB',
          },
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          border: 'none',
        },
      },
    },
    MuiSnackbar: {
      styleOverrides: {
        root: {
          '& .MuiAlert-root': {
            borderRadius: '10px',
            fontSize: '0.8125rem',
            fontWeight: 500,
          },
        },
      },
    },
  },
});
