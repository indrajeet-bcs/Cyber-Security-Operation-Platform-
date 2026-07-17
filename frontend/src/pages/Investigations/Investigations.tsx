import { Box, Card, Typography, TextField, Button, Grid, Paper, Tabs, Tab } from '@mui/material';
import { Search as SearchIcon, Hub as HubIcon, Timeline as TimelineIcon } from '@mui/icons-material';
import { useState } from 'react';

export default function Investigations() {
  const [tabValue, setTabValue] = useState(0);
  const [query, setQuery] = useState('source="nginx" AND status>=400');

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3.5 }}>
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 800, color: '#F3F4F6', mb: 0.5 }}>
          Threat Hunting & Investigations
        </Typography>
        <Typography variant="body2" sx={{ color: '#9CA3AF' }}>
          Interactive correlation log search and forensics timeline workspace.
        </Typography>
      </Box>

      {/* Query Bar */}
      <Card sx={{ p: 2 }}>
        <Grid container spacing={2} sx={{ alignItems: 'center' }}>
          <Grid size={{ xs: 10 }}>
            <TextField
              fullWidth
              size="small"
              variant="outlined"
              label="Splunk / Kibana-style Query Language"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              slotProps={{
                input: {
                  startAdornment: <SearchIcon sx={{ color: '#6B7280', mr: 1 }} />,
                  style: { fontFamily: 'monospace' }
                }
              }}
            />
          </Grid>
          <Grid size={{ xs: 2 }}>
            <Button variant="contained" fullWidth startIcon={<SearchIcon />}>
              Execute Hunt
            </Button>
          </Grid>
        </Grid>
      </Card>

      {/* Workspace Tabs */}
      <Paper sx={{ border: '1px solid #1F2937', bgcolor: '#111827' }}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={tabValue} onChange={(_, val) => setTabValue(val)} textColor="primary" indicatorColor="primary">
            <Tab label="Forensics Graph" icon={<HubIcon />} iconPosition="start" />
            <Tab label="Timeline Analysis" icon={<TimelineIcon />} iconPosition="start" />
          </Tabs>
        </Box>
        <Box sx={{ p: 4, minHeight: 300, display: 'flex', alignItems: 'center', justifyContent: 'center', textAlign: 'center' }}>
          {tabValue === 0 ? (
            <Box>
              <HubIcon sx={{ fontSize: 60, color: '#3B82F6', mb: 2, opacity: 0.8 }} />
              <Typography variant="h6" sx={{ color: '#F3F4F6', fontWeight: 600, mb: 1 }}>
                Graph Visualizer Simulation
              </Typography>
              <Typography variant="body2" sx={{ color: '#9CA3AF', maxWidth: 500 }}>
                Interactive visual node graph showing relationship flows between sources, targets, IPs, and rules will render here.
              </Typography>
            </Box>
          ) : (
            <Box>
              <TimelineIcon sx={{ fontSize: 60, color: '#10B981', mb: 2, opacity: 0.8 }} />
              <Typography variant="h6" sx={{ color: '#F3F4F6', fontWeight: 600, mb: 1 }}>
                Correlation Event Timeline
              </Typography>
              <Typography variant="body2" sx={{ color: '#9CA3AF', maxWidth: 500 }}>
                A chronologically ordered timeline list of parsed network logs and authentication trails will render here.
              </Typography>
            </Box>
          )}
        </Box>
      </Paper>
    </Box>
  );
}
