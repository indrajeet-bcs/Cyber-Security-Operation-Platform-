
import { Outlet } from 'react-router-dom';
import { Box, CssBaseline } from '@mui/material';
import Sidebar from './Sidebar';
import Header from './Header';
import { useIsFetching, useQueryClient } from '@tanstack/react-query';

export default function Layout() {
  const queryClient = useQueryClient();
  const isFetchingCount = useIsFetching();

  const handleRefresh = () => {
    queryClient.invalidateQueries();
  };

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', backgroundColor: '#0B0F19' }}>
      <CssBaseline />
      
      {/* Persistent Left Sidebar */}
      <Sidebar />

      {/* Main Content Area */}
      <Box sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Top Navbar */}
        <Header onRefresh={handleRefresh} isFetching={isFetchingCount > 0} />

        {/* Page Render Body */}
        <Box component="main" sx={{ flexGrow: 1, p: 3, overflowY: 'auto' }}>
          <Outlet />
        </Box>
      </Box>
    </Box>
  );
}
