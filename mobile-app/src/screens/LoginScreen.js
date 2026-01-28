import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ActivityIndicator,
  TextInput,
  Alert,
  Linking,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Feather } from '@expo/vector-icons';
import * as WebBrowser from 'expo-web-browser';
import { colors, spacing, borderRadius, typography, shadows } from '../constants/theme';
import { API_BASE_URL } from '../constants/config';
import { setAuthToken } from '../services/api';

// Ensure web browser redirects are handled
WebBrowser.maybeCompleteAuthSession();

export default function LoginScreen({ onLogin }) {
  const [loading, setLoading] = useState(false);
  const [showTokenInput, setShowTokenInput] = useState(false);
  const [manualToken, setManualToken] = useState('');

  const handleLogin = async () => {
    setLoading(true);
    try {
      // Open Cloudflare Access login in browser
      // User will authenticate and then return to the app
      const result = await WebBrowser.openAuthSessionAsync(
        `${API_BASE_URL}/admin`,
        'linkshort://auth'
      );

      if (result.type === 'success') {
        // Try to verify we're authenticated by making an API call
        try {
          const response = await fetch(`${API_BASE_URL}/api/stats`, {
            credentials: 'include',
          });

          if (response.ok) {
            // We're authenticated via cookies
            await setAuthToken('cookie-auth');
            onLogin();
            return;
          }
        } catch (e) {
          // API call failed, show manual token option
        }

        // Show option to enter token manually
        Alert.alert(
          'Authentication',
          'If you completed login, tap "I\'m logged in". Otherwise, you can enter your access token manually.',
          [
            { text: 'Cancel', style: 'cancel' },
            { text: 'Enter Token', onPress: () => setShowTokenInput(true) },
            { text: "I'm logged in", onPress: () => onLogin() },
          ]
        );
      }
    } catch (error) {
      console.error('Login error:', error);
      Alert.alert('Error', 'Failed to open login page. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleManualToken = async () => {
    if (!manualToken.trim()) {
      Alert.alert('Error', 'Please enter your access token');
      return;
    }

    setLoading(true);
    try {
      // Verify the token works
      const response = await fetch(`${API_BASE_URL}/api/stats`, {
        headers: {
          'Cf-Access-Jwt-Assertion': manualToken.trim(),
        },
      });

      if (response.ok) {
        await setAuthToken(manualToken.trim());
        onLogin();
      } else {
        Alert.alert('Invalid Token', 'The token could not be verified. Please check and try again.');
      }
    } catch (error) {
      Alert.alert('Error', 'Failed to verify token. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const openWebDashboard = () => {
    Linking.openURL(`${API_BASE_URL}/admin`);
  };

  if (showTokenInput) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.content}>
          <TouchableOpacity
            style={styles.backButton}
            onPress={() => setShowTokenInput(false)}
          >
            <Feather name="arrow-left" size={24} color={colors.foreground} />
          </TouchableOpacity>

          <Text style={styles.title}>Enter Token</Text>
          <Text style={styles.subtitle}>
            Get your access token from the web dashboard
          </Text>

          <TextInput
            style={styles.tokenInput}
            placeholder="Paste your access token here..."
            placeholderTextColor={colors.mutedForeground}
            value={manualToken}
            onChangeText={setManualToken}
            multiline
            autoCapitalize="none"
            autoCorrect={false}
          />

          <TouchableOpacity
            style={styles.loginButton}
            onPress={handleManualToken}
            disabled={loading}
          >
            {loading ? (
              <ActivityIndicator color="#fff" />
            ) : (
              <Text style={styles.loginButtonText}>Verify Token</Text>
            )}
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.secondaryButton}
            onPress={openWebDashboard}
          >
            <Feather name="external-link" size={16} color={colors.indigo} />
            <Text style={styles.secondaryButtonText}>Open Web Dashboard</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        {/* Logo */}
        <View style={styles.logoContainer}>
          <View style={styles.logo}>
            <Feather name="link" size={40} color={colors.indigo} />
          </View>
        </View>

        {/* Title */}
        <Text style={styles.title}>LinkShort</Text>
        <Text style={styles.subtitle}>
          Manage your short links on the go
        </Text>

        {/* Features */}
        <View style={styles.features}>
          <View style={styles.feature}>
            <View style={styles.featureIcon}>
              <Feather name="zap" size={18} color={colors.indigo} />
            </View>
            <View style={styles.featureText}>
              <Text style={styles.featureTitle}>Quick Access</Text>
              <Text style={styles.featureDesc}>
                Create and manage links instantly
              </Text>
            </View>
          </View>

          <View style={styles.feature}>
            <View style={styles.featureIcon}>
              <Feather name="bar-chart-2" size={18} color={colors.indigo} />
            </View>
            <View style={styles.featureText}>
              <Text style={styles.featureTitle}>Analytics</Text>
              <Text style={styles.featureDesc}>
                Track clicks and performance
              </Text>
            </View>
          </View>

          <View style={styles.feature}>
            <View style={styles.featureIcon}>
              <Feather name="shield" size={18} color={colors.indigo} />
            </View>
            <View style={styles.featureText}>
              <Text style={styles.featureTitle}>Secure</Text>
              <Text style={styles.featureDesc}>
                Protected by Cloudflare Access
              </Text>
            </View>
          </View>
        </View>

        {/* Login Button */}
        <TouchableOpacity
          style={styles.loginButton}
          onPress={handleLogin}
          disabled={loading}
          activeOpacity={0.8}
        >
          {loading ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <>
              <Feather name="log-in" size={20} color="#fff" />
              <Text style={styles.loginButtonText}>
                Sign in with Cloudflare
              </Text>
            </>
          )}
        </TouchableOpacity>

        {/* Manual Token Option */}
        <TouchableOpacity
          style={styles.secondaryButton}
          onPress={() => setShowTokenInput(true)}
        >
          <Feather name="key" size={16} color={colors.indigo} />
          <Text style={styles.secondaryButtonText}>Enter token manually</Text>
        </TouchableOpacity>

        {/* Info */}
        <Text style={styles.infoText}>
          You'll be redirected to Cloudflare Access to authenticate
        </Text>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background,
  },
  content: {
    flex: 1,
    paddingHorizontal: spacing.xl,
    justifyContent: 'center',
  },
  backButton: {
    position: 'absolute',
    top: spacing.xl,
    left: 0,
    padding: spacing.sm,
  },
  logoContainer: {
    alignItems: 'center',
    marginBottom: spacing.xl,
  },
  logo: {
    width: 80,
    height: 80,
    borderRadius: borderRadius.xl,
    backgroundColor: `${colors.indigo}20`,
    justifyContent: 'center',
    alignItems: 'center',
    ...shadows.lg,
  },
  title: {
    fontSize: 36,
    fontWeight: typography.bold,
    color: colors.foreground,
    textAlign: 'center',
    marginBottom: spacing.sm,
  },
  subtitle: {
    fontSize: typography.lg,
    color: colors.mutedForeground,
    textAlign: 'center',
    marginBottom: spacing.xxxl,
  },
  features: {
    marginBottom: spacing.xxxl,
    gap: spacing.lg,
  },
  feature: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
  },
  featureIcon: {
    width: 40,
    height: 40,
    borderRadius: borderRadius.md,
    backgroundColor: `${colors.indigo}15`,
    justifyContent: 'center',
    alignItems: 'center',
  },
  featureText: {
    flex: 1,
  },
  featureTitle: {
    fontSize: typography.base,
    fontWeight: typography.semibold,
    color: colors.foreground,
  },
  featureDesc: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
    marginTop: 2,
  },
  tokenInput: {
    backgroundColor: colors.card,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: borderRadius.lg,
    padding: spacing.lg,
    color: colors.foreground,
    fontSize: typography.base,
    minHeight: 100,
    textAlignVertical: 'top',
    marginBottom: spacing.lg,
  },
  loginButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: colors.indigo,
    borderRadius: borderRadius.lg,
    height: 56,
    gap: spacing.sm,
    ...shadows.md,
  },
  loginButtonText: {
    fontSize: typography.lg,
    fontWeight: typography.semibold,
    color: '#fff',
  },
  secondaryButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: spacing.lg,
    gap: spacing.sm,
    marginTop: spacing.md,
  },
  secondaryButtonText: {
    fontSize: typography.base,
    color: colors.indigo,
  },
  infoText: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
    textAlign: 'center',
    marginTop: spacing.lg,
  },
});
