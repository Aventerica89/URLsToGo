// API Configuration
export const API_BASE_URL = 'https://links.jbcloud.app';

// Auth callback URL for mobile app
export const AUTH_CALLBACK_URL = 'linkshort://auth/callback';

// Cloudflare Access login URL
export const AUTH_LOGIN_URL = `${API_BASE_URL}/cdn-cgi/access/login`;

export default {
  API_BASE_URL,
  AUTH_CALLBACK_URL,
  AUTH_LOGIN_URL,
};
