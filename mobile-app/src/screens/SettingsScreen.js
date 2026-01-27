import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Alert,
  Linking,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Feather } from '@expo/vector-icons';
import { colors, spacing, borderRadius, typography } from '../constants/theme';
import { API_BASE_URL } from '../constants/config';

export default function SettingsScreen({ onLogout, userEmail }) {
  const handleLogout = () => {
    Alert.alert(
      'Log Out',
      'Are you sure you want to log out?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Log Out',
          style: 'destructive',
          onPress: onLogout,
        },
      ]
    );
  };

  const openWebDashboard = () => {
    Linking.openURL(`${API_BASE_URL}/admin`);
  };

  const SettingRow = ({ icon, title, subtitle, onPress, showChevron = true, danger = false }) => (
    <TouchableOpacity
      style={styles.settingRow}
      onPress={onPress}
      activeOpacity={0.7}
    >
      <View style={[styles.settingIcon, danger && styles.settingIconDanger]}>
        <Feather
          name={icon}
          size={20}
          color={danger ? colors.error : colors.indigo}
        />
      </View>
      <View style={styles.settingContent}>
        <Text style={[styles.settingTitle, danger && styles.settingTitleDanger]}>
          {title}
        </Text>
        {subtitle && <Text style={styles.settingSubtitle}>{subtitle}</Text>}
      </View>
      {showChevron && (
        <Feather name="chevron-right" size={20} color={colors.mutedForeground} />
      )}
    </TouchableOpacity>
  );

  return (
    <SafeAreaView style={styles.container} edges={['top']}>
      <View style={styles.titleBar}>
        <Text style={styles.title}>Settings</Text>
      </View>

      <ScrollView style={styles.content} showsVerticalScrollIndicator={false}>
        {/* Account Section */}
        <Text style={styles.sectionTitle}>Account</Text>
        <View style={styles.card}>
          <View style={styles.profileRow}>
            <View style={styles.avatar}>
              <Feather name="user" size={24} color={colors.foreground} />
            </View>
            <View style={styles.profileInfo}>
              <Text style={styles.profileName}>
                {userEmail || 'Not logged in'}
              </Text>
              <Text style={styles.profileMeta}>Cloudflare Access</Text>
            </View>
          </View>
        </View>

        {/* General Section */}
        <Text style={styles.sectionTitle}>General</Text>
        <View style={styles.card}>
          <SettingRow
            icon="globe"
            title="Web Dashboard"
            subtitle="Open full dashboard in browser"
            onPress={openWebDashboard}
          />
          <View style={styles.divider} />
          <SettingRow
            icon="bell"
            title="Notifications"
            subtitle="Coming soon"
            onPress={() => Alert.alert('Coming Soon', 'Push notifications will be available in a future update.')}
          />
        </View>

        {/* About Section */}
        <Text style={styles.sectionTitle}>About</Text>
        <View style={styles.card}>
          <SettingRow
            icon="info"
            title="Version"
            subtitle="1.0.0"
            showChevron={false}
          />
          <View style={styles.divider} />
          <SettingRow
            icon="github"
            title="Source Code"
            subtitle="View on GitHub"
            onPress={() => Linking.openURL('https://github.com')}
          />
        </View>

        {/* Danger Zone */}
        <Text style={styles.sectionTitle}>Account</Text>
        <View style={styles.card}>
          <SettingRow
            icon="log-out"
            title="Log Out"
            onPress={handleLogout}
            showChevron={false}
            danger
          />
        </View>

        <View style={{ height: 100 }} />
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background,
  },
  titleBar: {
    paddingHorizontal: spacing.xl,
    paddingVertical: spacing.md,
  },
  title: {
    fontSize: typography.xxxl,
    fontWeight: typography.bold,
    color: colors.foreground,
  },
  content: {
    flex: 1,
    paddingHorizontal: spacing.xl,
  },
  sectionTitle: {
    fontSize: typography.sm,
    fontWeight: typography.semibold,
    color: colors.mutedForeground,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginTop: spacing.xl,
    marginBottom: spacing.md,
    marginLeft: spacing.xs,
  },
  card: {
    backgroundColor: colors.card,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.border,
    overflow: 'hidden',
  },
  profileRow: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: spacing.lg,
    gap: spacing.md,
  },
  avatar: {
    width: 48,
    height: 48,
    borderRadius: 24,
    backgroundColor: colors.muted,
    justifyContent: 'center',
    alignItems: 'center',
  },
  profileInfo: {
    flex: 1,
  },
  profileName: {
    fontSize: typography.base,
    fontWeight: typography.medium,
    color: colors.foreground,
  },
  profileMeta: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
    marginTop: 2,
  },
  settingRow: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: spacing.lg,
    gap: spacing.md,
  },
  settingIcon: {
    width: 36,
    height: 36,
    borderRadius: borderRadius.md,
    backgroundColor: `${colors.indigo}20`,
    justifyContent: 'center',
    alignItems: 'center',
  },
  settingIconDanger: {
    backgroundColor: `${colors.error}20`,
  },
  settingContent: {
    flex: 1,
  },
  settingTitle: {
    fontSize: typography.base,
    fontWeight: typography.medium,
    color: colors.foreground,
  },
  settingTitleDanger: {
    color: colors.error,
  },
  settingSubtitle: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
    marginTop: 2,
  },
  divider: {
    height: 1,
    backgroundColor: colors.border,
    marginLeft: spacing.lg + 36 + spacing.md,
  },
});
