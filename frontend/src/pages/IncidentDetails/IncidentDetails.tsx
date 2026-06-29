import { useState } from 'react';
import type { FormEvent } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Chip,
  Divider,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  List,
  ListItem,
  ListItemText,
  Paper,
  Skeleton,
  Alert,
  Snackbar,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  AssignmentInd as TakeIcon,
  CheckCircle as CloseIcon,
  NoteAdd as NoteIcon,
  ArrowBack as ArrowBackIcon,
  AccessTime as AccessTimeIcon,
  Person as PersonIcon,
  Code as CodeIcon,
  Comment as CommentIcon,
} from '@mui/icons-material';

import { useIncident, useAssignIncident, useAddNote, useCloseIncident } from '../../hooks/queries';
import { theme } from '../../theme';

export default function IncidentDetails() {
  const { incidentId } = useParams<{ incidentId: string }>();
  const navigate = useNavigate();

  // Dialog & Notification state
  const [confirmCloseOpen, setConfirmCloseOpen] = useState(false);
  const [newNote, setNewNote] = useState('');
  const [jsonExpanded, setJsonExpanded] = useState(false);
  
  const [toast, setToast] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // Queries & Mutations
  const { data: incident, isLoading, isError, error } = useIncident(incidentId || '');
  const assignMutation = useAssignIncident();
  const noteMutation = useAddNote();
  const closeMutation = useCloseIncident();

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <Skeleton height={50} width="40%" />
        <Box sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, gap: 3 }}>
          <Box sx={{ flex: 2, display: 'flex', flexDirection: 'column', gap: 3 }}>
            <Skeleton variant="rectangular" height={200} />
            <Skeleton variant="rectangular" height={300} />
          </Box>
          <Box sx={{ flex: 1 }}>
            <Skeleton variant="rectangular" height={400} />
          </Box>
        </Box>
      </Box>
    );
  }

  if (isError || !incident) {
    return (
      <Box sx={{ mt: 4 }}>
        <Alert severity="error" sx={{ backgroundColor: '#1F1015', border: '1px solid #F87171' }}>
          Failed to load incident. Ensure the backend FastAPI server is running.
          {error ? ` Details: ${(error as any).message}` : ''}
        </Alert>
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/incidents')} sx={{ mt: 2 }}>
          Back to Incidents Queue
        </Button>
      </Box>
    );
  }

  // ----------------------------------------------------
  // Color Styling Helpers
  // ----------------------------------------------------
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return theme.palette.severity.critical;
      case 'high': return theme.palette.severity.high;
      case 'medium': return theme.palette.severity.medium;
      case 'low': return theme.palette.severity.low;
      default: return theme.palette.text.secondary;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open': return theme.palette.status.open;
      case 'acknowledged': return theme.palette.status.acknowledged;
      case 'investigating': return theme.palette.status.investigating;
      case 'closed': return theme.palette.status.closed;
      default: return theme.palette.text.secondary;
    }
  };

  // Split newline appended notes for history listing
  const notesList = incident.notes ? incident.notes.split('\n').filter(n => n.trim() !== '') : [];

  // Construct a mocked alert JSON object for the collapsible viewer to display standard alerts columns
  const mockAlertJSON = {
    alert_id: incident.alert_id ? `ALT-20260619-${String(incident.alert_id).padStart(4, '0')}` : 'ALT-EXTERNAL',
    alert_title: incident.title,
    severity: incident.severity,
    status: incident.status === 'closed' ? 'closed' : 'open',
    source_ip: '192.168.10.45',
    host: 'soc-agent-node-01',
    user_name: incident.assigned_to || 'system',
    risk_score: incident.severity === 'critical' ? 95 : incident.severity === 'high' ? 80 : 50,
    confidence: 85,
    event_type: 'suspicious_activity',
    rule_matches: [
      {
        rule_code: 'SIG_0042',
        rule_name: incident.title,
        severity: incident.severity,
        risk_score: incident.severity === 'critical' ? 95 : 50,
      }
    ],
    correlation_matches: [],
    created_at: incident.created_at,
  };

  // ----------------------------------------------------
  // Handler Submissions
  // ----------------------------------------------------
  const handleTakeIncident = async () => {
    try {
      await assignMutation.mutateAsync({
        incidentId: incident.incident_id,
        assigned_to: 'shubham',
        assigned_role: 'SOC_L1',
      });
      setToast({
        open: true,
        message: 'Incident successfully assigned to you! State moved to Investigating.',
        severity: 'success',
      });
    } catch (err: any) {
      setToast({
        open: true,
        message: `Failed to assign incident: ${err?.response?.data?.detail || err.message}`,
        severity: 'error',
      });
    }
  };

  const handleAddNote = async (e: FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;

    try {
      await noteMutation.mutateAsync({
        incidentId: incident.incident_id,
        note: newNote.trim(),
      });
      setNewNote('');
      setToast({
        open: true,
        message: 'Note successfully added.',
        severity: 'success',
      });
    } catch (err: any) {
      setToast({
        open: true,
        message: `Failed to add note: ${err?.response?.data?.detail || err.message}`,
        severity: 'error',
      });
    }
  };

  const handleCloseIncident = async () => {
    setConfirmCloseOpen(false);
    try {
      await closeMutation.mutateAsync(incident.incident_id);
      setToast({
        open: true,
        message: 'Incident closed successfully.',
        severity: 'success',
      });
    } catch (err: any) {
      setToast({
        open: true,
        message: `Failed to close incident: ${err?.response?.data?.detail || err.message}`,
        severity: 'error',
      });
    }
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3.5 }}>
      {/* Back Button */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Button 
          startIcon={<ArrowBackIcon />} 
          onClick={() => navigate('/incidents')}
          sx={{ color: '#9CA3AF', '&:hover': { color: '#F3F4F6' } }}
        >
          Back to Incident Queue
        </Button>
      </Box>

      {/* Title & Status Summary Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
            <Typography variant="h4" sx={{ fontWeight: 800, color: '#F3F4F6', fontFamily: 'monospace' }}>
              {incident.incident_id}
            </Typography>
            <Chip
              label={incident.status}
              sx={{
                backgroundColor: `${getStatusColor(incident.status)}18`,
                color: getStatusColor(incident.status),
                border: `1px solid ${getStatusColor(incident.status)}40`,
                fontWeight: 700,
                textTransform: 'uppercase',
              }}
            />
            <Chip
              label={incident.severity}
              sx={{
                backgroundColor: `${getSeverityColor(incident.severity)}18`,
                color: getSeverityColor(incident.severity),
                border: `1px solid ${getSeverityColor(incident.severity)}40`,
                fontWeight: 700,
                textTransform: 'uppercase',
              }}
            />
          </Box>
          <Typography variant="h5" sx={{ fontWeight: 600, color: '#E5E7EB', mb: 0.5 }}>
            {incident.title}
          </Typography>
        </Box>
      </Box>

      <Box sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, gap: 3 }}>
        {/* Left Columns: Core Alert JSON and Notes Feed */}
        <Box sx={{ flex: 2, display: 'flex', flexDirection: 'column', gap: 3 }}>
          {/* Collapsible raw alert viewer */}
          <Accordion 
            expanded={jsonExpanded} 
            onChange={(_, isExpanded) => setJsonExpanded(isExpanded)}
            sx={{ 
              backgroundColor: '#111827', 
              border: '1px solid #1F2937', 
              borderRadius: '8px !important',
              '&:before': { display: 'none' } 
            }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#9CA3AF' }} />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                <CodeIcon sx={{ color: '#3B82F6' }} />
                <Typography sx={{ fontWeight: 700, color: '#F3F4F6' }}>
                  Raw Alert JSON Inspector
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails sx={{ pt: 0, px: 2.5, pb: 2.5 }}>
              <Divider sx={{ mb: 2 }} />
              <Paper 
                component="pre" 
                sx={{ 
                  p: 2, 
                  m: 0, 
                  backgroundColor: '#070A13', 
                  border: '1px solid #1F2937', 
                  borderRadius: '6px', 
                  color: '#10B981', 
                  fontSize: '0.8rem',
                  fontFamily: 'monospace',
                  overflowX: 'auto',
                }}
              >
                {JSON.stringify(mockAlertJSON, null, 2)}
              </Paper>
            </AccordionDetails>
          </Accordion>

          {/* Investigation Notes timelines */}
          <Card>
            <CardContent sx={{ p: 2.5 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
                <CommentIcon sx={{ color: '#3B82F6' }} />
                <Typography variant="h6" sx={{ fontWeight: 700, color: '#F3F4F6' }}>
                  Analyst Log & Notes
                </Typography>
              </Box>
              
              <Divider sx={{ mb: 3 }} />

              {/* Add Note Form */}
              {incident.status !== 'closed' ? (
                <Box component="form" onSubmit={handleAddNote} sx={{ mb: 4 }}>
                  <TextField
                    fullWidth
                    multiline
                    rows={3}
                    placeholder="Enter details (e.g. 'Blocked source IP', 'Checked firewall configuration')"
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    sx={{ mb: 1.5 }}
                    disabled={noteMutation.isPending}
                  />
                  <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <Button
                      type="submit"
                      variant="contained"
                      startIcon={<NoteIcon />}
                      disabled={!newNote.trim() || noteMutation.isPending}
                    >
                      Add Note
                    </Button>
                  </Box>
                </Box>
              ) : (
                <Alert severity="info" sx={{ mb: 4, backgroundColor: '#0C1824', color: '#60A5FA', border: '1px solid #1E3A8A' }}>
                  This incident is closed. Adding additional analyst notes is locked.
                </Alert>
              )}

              {/* Notes List */}
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1.5, color: '#F3F4F6' }}>
                Timeline History ({notesList.length})
              </Typography>
              {notesList.length === 0 ? (
                <Typography variant="body2" sx={{ color: '#6B7280', fontStyle: 'italic', py: 2 }}>
                  No investigation notes recorded for this incident.
                </Typography>
              ) : (
                <List sx={{ display: 'flex', flexDirection: 'column', gap: 2, p: 0 }}>
                  {notesList.map((note, index) => (
                    <Paper 
                      key={index} 
                      sx={{ 
                        p: 2, 
                        backgroundColor: '#1E293B30', 
                        borderColor: '#374151',
                        borderRadius: '6px',
                        borderWidth: '1px',
                        borderStyle: 'solid'
                      }}
                    >
                      <ListItem sx={{ p: 0, alignItems: 'flex-start' }}>
                        <ListItemText
                          primary={
                            <Typography variant="body1" sx={{ color: '#E5E7EB', whiteSpace: 'pre-wrap' }}>
                              {note}
                            </Typography>
                          }
                          secondary={
                            <Typography variant="caption" sx={{ color: '#6B7280', display: 'block', mt: 1 }}>
                              Logged by {incident.assigned_to || 'Analyst'} on {new Date(incident.updated_at).toLocaleString()}
                            </Typography>
                          }
                        />
                      </ListItem>
                    </Paper>
                  ))}
                </List>
              )}
            </CardContent>
          </Card>
        </Box>

        {/* Right Columns: Actions Panel & Timestamps */}
        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 3 }}>
          {/* Action Operations card */}
          <Card>
            <CardContent sx={{ p: 2.5 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: '#F3F4F6' }}>
                Incident Controls
              </Typography>
              
              <Divider sx={{ mb: 2.5 }} />

              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {incident.status === 'open' && (
                  <Button
                    fullWidth
                    variant="contained"
                    startIcon={<TakeIcon />}
                    onClick={handleTakeIncident}
                    disabled={assignMutation.isPending}
                    sx={{ py: 1.2 }}
                  >
                    Take Incident
                  </Button>
                )}

                {incident.status === 'acknowledged' && (
                  <Button
                    fullWidth
                    variant="contained"
                    startIcon={<TakeIcon />}
                    onClick={handleTakeIncident}
                    disabled={assignMutation.isPending}
                    sx={{ py: 1.2 }}
                  >
                    Start Investigation
                  </Button>
                )}

                {incident.status === 'investigating' && (
                  <Button
                    fullWidth
                    variant="contained"
                    color="error"
                    startIcon={<CloseIcon />}
                    onClick={() => setConfirmCloseOpen(true)}
                    disabled={closeMutation.isPending}
                    sx={{ 
                      py: 1.2,
                      background: 'linear-gradient(135deg, #EF4444 0%, #B91C1C 100%)',
                      boxShadow: '0 4px 12px rgba(239, 68, 68, 0.2)',
                    }}
                  >
                    Close Incident
                  </Button>
                )}

                {incident.status === 'closed' && (
                  <Box sx={{ p: 2, borderRadius: '6px', backgroundColor: '#10B98110', border: '1px solid #10B98130', textAlign: 'center' }}>
                    <Typography variant="subtitle1" sx={{ color: '#10B981', fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
                      <CloseIcon /> Incident Closed
                    </Typography>
                  </Box>
                )}
              </Box>
            </CardContent>
          </Card>

          {/* Details & Timestamps card */}
          <Card>
            <CardContent sx={{ p: 2.5 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: '#F3F4F6' }}>
                Incident Details
              </Typography>
              
              <Divider sx={{ mb: 2 }} />

              {/* Analyst ownership */}
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.8 }}>
                <Box>
                  <Typography variant="caption" sx={{ color: '#9CA3AF', display: 'block', fontWeight: 600 }}>
                    Assigned Analyst
                  </Typography>
                  {incident.assigned_to ? (
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                      <PersonIcon sx={{ color: '#3B82F6', fontSize: 18 }} />
                      <Typography variant="body2" sx={{ fontWeight: 700 }}>
                        {incident.assigned_to}
                      </Typography>
                      <Chip label={incident.assigned_role} size="small" sx={{ fontSize: '0.65rem', height: 18 }} />
                    </Box>
                  ) : (
                    <Typography variant="body2" sx={{ color: '#6B7280', fontStyle: 'italic', mt: 0.5 }}>
                      Unassigned (Awaiting SOC Triage)
                    </Typography>
                  )}
                </Box>

                <Divider />

                {/* Timestamps */}
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                  <Box>
                    <Typography variant="caption" sx={{ color: '#9CA3AF', display: 'block', fontWeight: 600 }}>
                      Created Time
                    </Typography>
                    <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mt: 0.5, color: '#E5E7EB' }}>
                      <AccessTimeIcon sx={{ fontSize: 16, color: '#9CA3AF' }} />
                      {new Date(incident.created_at).toLocaleString()}
                    </Typography>
                  </Box>

                  {incident.acknowledged_at && (
                    <Box>
                      <Typography variant="caption" sx={{ color: '#9CA3AF', display: 'block', fontWeight: 600 }}>
                        Acknowledged Time
                      </Typography>
                      <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mt: 0.5, color: '#E5E7EB' }}>
                        <AccessTimeIcon sx={{ fontSize: 16, color: '#9CA3AF' }} />
                        {new Date(incident.acknowledged_at).toLocaleString()}
                      </Typography>
                    </Box>
                  )}

                  {incident.investigating_at && (
                    <Box>
                      <Typography variant="caption" sx={{ color: '#9CA3AF', display: 'block', fontWeight: 600 }}>
                        Investigation Started Time
                      </Typography>
                      <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mt: 0.5, color: '#E5E7EB' }}>
                        <AccessTimeIcon sx={{ fontSize: 16, color: '#9CA3AF' }} />
                        {new Date(incident.investigating_at).toLocaleString()}
                      </Typography>
                    </Box>
                  )}

                  {incident.closed_at && (
                    <Box>
                      <Typography variant="caption" sx={{ color: '#9CA3AF', display: 'block', fontWeight: 600 }}>
                        Closed Time
                      </Typography>
                      <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mt: 0.5, color: '#E5E7EB' }}>
                        <AccessTimeIcon sx={{ fontSize: 16, color: '#9CA3AF' }} />
                        {new Date(incident.closed_at).toLocaleString()}
                      </Typography>
                    </Box>
                  )}
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Box>
      </Box>

      {/* Close Incident Confirmation Dialog */}
      <Dialog
        open={confirmCloseOpen}
        onClose={() => setConfirmCloseOpen(false)}
      >
        <DialogTitle sx={{ fontWeight: 700 }}>
          Confirm Incident Closure
        </DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ color: '#9CA3AF' }}>
            Are you sure you want to close this incident? This action will set the status to CLOSED, record the closed_at timestamp, and lock additional note submissions.
          </DialogContentText>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setConfirmCloseOpen(false)}>
            Cancel
          </Button>
          <Button 
            onClick={handleCloseIncident} 
            color="error" 
            variant="contained"
            sx={{
              background: 'linear-gradient(135deg, #EF4444 0%, #B91C1C 100%)',
            }}
          >
            Confirm Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar notification feedback */}
      <Snackbar
        open={toast.open}
        autoHideDuration={4000}
        onClose={() => setToast((prev) => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert 
          onClose={() => setToast((prev) => ({ ...prev, open: false }))} 
          severity={toast.severity} 
          sx={{ width: '100%' }}
        >
          {toast.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}
