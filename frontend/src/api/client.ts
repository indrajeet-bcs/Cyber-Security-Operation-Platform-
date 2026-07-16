import axios from 'axios';

// Use VITE_API_BASE_URL env variable if set, otherwise fall back to the deployed backend.
// For local development, the Vite proxy in vite.config.ts handles /api → localhost:8000.
const BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  'https://cyber-security-backend-3o19.onrender.com/api';

export const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});
