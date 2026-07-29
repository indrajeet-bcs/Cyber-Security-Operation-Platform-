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
import SeverityBadge from '../../components/SeverityBadge';
import StatusChip from '../../components/StatusChip';
import LoadingState from '../../components/LoadingState';
import ErrorState from '../../components/ErrorState';

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

  // Data fetching
  const { data: incident, isLoading, isError, refetch } = useIncident(incidentId || '');

  // Mutations
  const assignMutation = useAssignIncident();
  const noteMutation = useAddNote();
  const closeMutation = useCloseIncident();

  if (isLoading) return <LoadingState message="Loading incident records..." />;
  if (isError || !incident) return <ErrorState message="Failed to load incident details" onRetry={refetch} />;

  // Parse notes list
  const notesList = incident.notes ? incident.notes.split('\n---\n').filter(Boolean) : [];

  // Handlers
  const handleTakeIncident = async () => {
    try {
      await assignMutation.mutateAsync({
        incidentId: incident.incident_id,
        assigned_to: 'shubham',
        assigned_role: 'SOC Analyst L1',
      });
      setToast({ open: true, message: 'Incident assigned to shubham', severity: 'success' });
    } catch {
      setToast({ open: true, message: 'Failed to assign incident', severity: 'error' });
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
      setToast({ open: true, message: 'Note added successfully', severity: 'success' });
    } catch {
      setToast({ open: true, message: 'Failed to add note', severity: 'error' });
    }
  };

  const handleCloseIncident = async () => {
    try {
      await closeMutation.mutateAsync(incident.incident_id);
      setConfirmCloseOpen(false);
      setToast({ open: true, message: 'Incident closed successfully', severity: 'success' });
    } catch {
      setToast({ open: true, message: 'Failed to close incident', severity: 'error' });
    }
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3.5 }}>
      {/* Back Button */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Button 
          startIcon={<ArrowBackIcon />} 
          onClick={() => navigate('/incidents')}
          sx={{ color: '#64748B', '&:hover': { color: '#2563EB' } }}
        >
          Back to Incident Queue
        </Button>
      </Box>

      {/* Title & Status Summary Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
            <Typography variant="h4" sx={{ fontWeight: 800, color: '#2563EB', fontFamily: 'monospace' }}>
              {incident.incident_id}
            </Typography>
            <StatusChip status={incident.status} />
            <SeverityBadge severity={incident.severity} />
          </Box>
          <Typography variant="h5" sx={{ fontWeight: 700, color: '#0F172A', mb: 0.5 }}>
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
              backgroundColor: '#FFFFFF', 
              border: '1px solid #E2E8F0', 
              borderRadius: '10px !important',
              '&:before': { display: 'none' } 
            }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#64748B' }} />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                <CodeIcon sx={{ color: '#2563EB' }} />
                <Typography sx={{ fontWeight: 700, color: '#0F172A' }}>
                  Detection Result & Original Log Inspector
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
                  backgroundColor: '#F8FAFC', 
                  border: '1px solid #E2E8F0', 
                  borderRadius: '6px', 
                  color: '#0F172A', 
                  fontSize: '0.8rem',
                  fontFamily: 'monospace',
                  fontWeight: 600,
                  overflowX: 'auto',
                }}
              >
                {JSON.stringify(incident.alert || { message: "No alert payload associated." }, null, 2)}
              </Paper>
            </AccordionDetails>
          </Accordion>

          {/* Investigation Notes timelines */}
          <Card>
            <CardContent sx={{ p: 2.5 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
                <CommentIcon sx={{ color: '#2563EB' }} />
                <Typography variant="h6" sx={{ fontWeight: 700, color: '#0F172A' }}>
                  Analyst Log & Notes (Timeline & Resolution)
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
                <Alert severity="info" sx={{ mb: 4, backgroundColor: '#EFF6FF', color: '#1D4ED8', border: '1px solid #BFDBFE' }}>
                  This incident is closed. Adding additional analyst notes is locked.
                </Alert>
              )}

              {/* Notes List */}
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1.5, color: '#0F172A' }}>
                Timeline History ({notesList.length})
              </Typography>
              {notesList.length === 0 ? (
                <Typography variant="body2" sx={{ color: '#64748B', fontStyle: 'italic', py: 2 }}>
                  No investigation notes recorded for this incident.
                </Typography>
              ) : (
                <List sx={{ display: 'flex', flexDirection: 'column', gap: 2, p: 0 }}>
                  {notesList.map((note, index) => (
                    <Paper 
                      key={index} 
                      sx={{ 
                        p: 2, 
                        backgroundColor: '#F8FAFC', 
                        borderColor: '#E2E8F0',
                        borderRadius: '8px',
                        borderWidth: '1px',
                        borderStyle: 'solid'
                      }}
                    >
                      <ListItem sx={{ p: 0, alignItems: 'flex-start' }}>
                        <ListItemText
                          primary={
                            <Typography variant="body1" sx={{ color: '#0F172A', whiteSpace: 'pre-wrap', fontWeight: 500 }}>
                              {note}
                            </Typography>
                          }
                          secondary={
                            <Typography variant="caption" sx={{ color: '#64748B', display: 'block', mt: 1, fontWeight: 500 }}>
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
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: '#0F172A' }}>
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
                    onClick={() => setConfirmCloseOpen(false)}
                    disabled={closeMutation.isPending}
                    sx={{ 
                      py: 1.2,
                      backgroundColor: '#DC2626',
                      '&:hover': { backgroundColor: '#B91C1C' },
                    }}
                  >
                    Close Incident
                  </Button>
                )}

                {incident.status === 'closed' && (
                  <Box sx={{ p: 2, borderRadius: '6px', backgroundColor: '#F0FDF4', border: '1px solid #BBF7D0', textAlign: 'center' }}>
                    <Typography variant="subtitle1" sx={{ color: '#16A34A', fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
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
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: '#0F172A' }}>
                Metadata
              </Typography>
              
              <Divider sx={{ mb: 2 }} />

              {/* Analyst ownership */}
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.8 }}>
                <Box>
                  <Typography variant="caption" sx={{ color: '#64748B', display: 'block', fontWeight: 600 }}>
                    Assigned Analyst
                  </Typography>
                  {incident.assigned_to ? (
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                      <PersonIcon sx={{ color: '#2563EB', fontSize: 18 }} />
                      <Typography variant="body2" sx={{ fontWeight: 700, color: '#0F172A' }}>
                        {incident.assigned_to}
                      </Typography>
                      <Chip label={incident.assigned_role} size="small" sx={{ fontSize: '0.65rem', height: 18, backgroundColor: '#EFF6FF', color: '#2563EB', fontWeight: 700 }} />
                    </Box>
                  ) : (
                    <Typography variant="body2" sx={{ color: '#64748B', fontStyle: 'italic', mt: 0.5 }}>
                      Unassigned (Awaiting SOC Triage)
                    </Typography>
                  )}
                </Box>

                <Divider />

                {/* Timestamps */}
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                  <Box>
                    <Typography variant="caption" sx={{ color: '#64748B', display: 'block', fontWeight: 600 }}>
                      Created Time
                    </Typography>
                    <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mt: 0.5, color: '#0F172A', fontWeight: 600 }}>
                      <AccessTimeIcon sx={{ fontSize: 16, color: '#64748B' }} />
                      {new Date(incident.created_at).toLocaleString()}
                    </Typography>
                  </Box>

                  {incident.acknowledged_at && (
                    <Box>
                      <Typography variant="caption" sx={{ color: '#64748B', display: 'block', fontWeight: 600 }}>
                        Acknowledged Time
                      </Typography>
                      <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mt: 0.5, color: '#0F172A', fontWeight: 600 }}>
                        <AccessTimeIcon sx={{ fontSize: 16, color: '#64748B' }} />
                        {new Date(incident.acknowledged_at).toLocaleString()}
                      </Typography>
                    </Box>
                  )}

                  {incident.investigating_at && (
                    <Box>
                      <Typography variant="caption" sx={{ color: '#64748B', display: 'block', fontWeight: 600 }}>
                        Investigation Started Time
                      </Typography>
                      <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mt: 0.5, color: '#0F172A', fontWeight: 600 }}>
                        <AccessTimeIcon sx={{ fontSize: 16, color: '#64748B' }} />
                        {new Date(incident.investigating_at).toLocaleString()}
                      </Typography>
                    </Box>
                  )}

                  {incident.closed_at && (
                    <Box>
                      <Typography variant="caption" sx={{ color: '#64748B', display: 'block', fontWeight: 600 }}>
                        Closed Time
                      </Typography>
                      <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mt: 0.5, color: '#0F172A', fontWeight: 600 }}>
                        <AccessTimeIcon sx={{ fontSize: 16, color: '#64748B' }} />
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
        <DialogTitle sx={{ fontWeight: 700, color: '#0F172A' }}>
          Confirm Incident Closure
        </DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ color: '#64748B' }}>
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
            sx={{ backgroundColor: '#DC2626', '&:hover': { backgroundColor: '#B91C1C' } }}
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
