import * as SecureStore from 'expo-secure-store';
import { API_BASE_URL } from '../constants/config';

// Store the auth token
let authToken = null;

export const setAuthToken = async (token) => {
  authToken = token;
  if (token) {
    await SecureStore.setItemAsync('authToken', token);
  } else {
    await SecureStore.deleteItemAsync('authToken');
  }
};

export const loadAuthToken = async () => {
  authToken = await SecureStore.getItemAsync('authToken');
  return authToken;
};

// Base fetch wrapper with auth
const apiFetch = async (endpoint, options = {}) => {
  const url = `${API_BASE_URL}${endpoint}`;

  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  // Add auth token if available (Cloudflare Access JWT)
  if (authToken) {
    headers['Cf-Access-Jwt-Assertion'] = authToken;
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(error || `HTTP ${response.status}`);
  }

  // Handle empty responses
  const text = await response.text();
  return text ? JSON.parse(text) : null;
};

// Links API
export const linksApi = {
  getAll: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return apiFetch(`/api/links${query ? `?${query}` : ''}`);
  },

  get: (code) => apiFetch(`/api/links/${code}`),

  create: (data) =>
    apiFetch('/api/links', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (code, data) =>
    apiFetch(`/api/links/${code}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  delete: (code) =>
    apiFetch(`/api/links/${code}`, {
      method: 'DELETE',
    }),
};

// Categories API
export const categoriesApi = {
  getAll: () => apiFetch('/api/categories'),

  create: (data) =>
    apiFetch('/api/categories', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id, data) =>
    apiFetch(`/api/categories/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  delete: (id) =>
    apiFetch(`/api/categories/${id}`, {
      method: 'DELETE',
    }),
};

// Tags API
export const tagsApi = {
  getAll: () => apiFetch('/api/tags'),

  create: (data) =>
    apiFetch('/api/tags', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  delete: (id) =>
    apiFetch(`/api/tags/${id}`, {
      method: 'DELETE',
    }),
};

// Stats API
export const statsApi = {
  get: () => apiFetch('/api/stats'),
  getClickEvents: (linkId, params = {}) => {
    const query = new URLSearchParams(params).toString();
    return apiFetch(`/api/links/${linkId}/clicks${query ? `?${query}` : ''}`);
  },
};

export default {
  setAuthToken,
  loadAuthToken,
  links: linksApi,
  categories: categoriesApi,
  tags: tagsApi,
  stats: statsApi,
};
