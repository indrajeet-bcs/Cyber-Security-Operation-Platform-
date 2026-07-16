import axios from 'axios';

// Automatically use the Vite dev proxy (/api -> localhost:8000) during local development.
// In production, fallback to the deployed Render backend URL.
const BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  (import.meta.env.DEV ? '/api' : 'https://cyber-security-backend-3o19.onrender.com/api');

export const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});
