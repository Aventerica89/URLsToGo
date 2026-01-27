import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ActivityIndicator,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Feather } from '@expo/vector-icons';
import * as WebBrowser from 'expo-web-browser';
import { colors, spacing, borderRadius, typography, shadows } from '../constants/theme';
import { API_BASE_URL } from '../constants/config';

export default function LoginScreen({ onLogin }) {
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    setLoading(true);
    try {
      // Open Cloudflare Access login in browser
      // After authentication, the user will be redirected back to the app
      // with the JWT token
      const result = await WebBrowser.openAuthSessionAsync(
        `${API_BASE_URL}/admin`,
        'linkshort://'
      );

      if (result.type === 'success' && result.url) {
        // Extract token from URL if available
        // For now, we'll use a simple approach
        onLogin();
      }
    } catch (error) {
      console.error('Login error:', error);
    } finally {
      setLoading(false);
    }
  };

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
  infoText: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
    textAlign: 'center',
    marginTop: spacing.lg,
  },
});
