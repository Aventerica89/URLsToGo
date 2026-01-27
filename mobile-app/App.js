import React, { useState, useEffect } from 'react';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import AppNavigator from './src/navigation/AppNavigator';
import { loadAuthToken, setAuthToken } from './src/services/api';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const token = await loadAuthToken();
      setIsAuthenticated(!!token);
    } catch (error) {
      console.error('Auth check failed:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogin = async (token) => {
    // For development, we'll auto-authenticate
    // In production, this would receive the actual JWT from Cloudflare Access
    await setAuthToken(token || 'dev-token');
    setIsAuthenticated(true);
  };

  const handleLogout = async () => {
    await setAuthToken(null);
    setIsAuthenticated(false);
  };

  if (isLoading) {
    return null; // Or a splash screen
  }

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      <AppNavigator
        isAuthenticated={isAuthenticated}
        onLogin={handleLogin}
        onLogout={handleLogout}
      />
    </SafeAreaProvider>
  );
}
