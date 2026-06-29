
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider, CssBaseline } from '@mui/material';

import { theme } from './theme';
import Layout from './components/Layout/Layout';
import Dashboard from './pages/Dashboard/Dashboard';
import Incidents from './pages/Incidents/Incidents';
import IncidentDetails from './pages/IncidentDetails/IncidentDetails';

// Create a client for React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false, // Avoid refetching when user switches tab
      retry: 1,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Layout />}>
              {/* Dashboard page */}
              <Route index element={<Dashboard />} />
              {/* Incident queue table */}
              <Route path="incidents" element={<Incidents />} />
              {/* Incident Details and actions */}
              <Route path="incident/:incidentId" element={<IncidentDetails />} />
              {/* Fallback redirect */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
