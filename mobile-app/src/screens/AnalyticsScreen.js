import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Feather } from '@expo/vector-icons';
import { colors, spacing, borderRadius, typography } from '../constants/theme';
import { statsApi } from '../services/api';

export default function AnalyticsScreen() {
  const [stats, setStats] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  const loadStats = useCallback(async () => {
    try {
      const data = await statsApi.get();
      setStats(data);
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  }, []);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await loadStats();
    setRefreshing(false);
  }, [loadStats]);

  const StatBlock = ({ icon, value, label, color = colors.indigo }) => (
    <View style={styles.statBlock}>
      <View style={[styles.statIcon, { backgroundColor: `${color}20` }]}>
        <Feather name={icon} size={20} color={color} />
      </View>
      <Text style={styles.statValue}>{value || 0}</Text>
      <Text style={styles.statLabel}>{label}</Text>
    </View>
  );

  return (
    <SafeAreaView style={styles.container} edges={['top']}>
      <View style={styles.titleBar}>
        <Text style={styles.title}>Analytics</Text>
      </View>

      <ScrollView
        style={styles.content}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={onRefresh}
            tintColor={colors.indigo}
          />
        }
        showsVerticalScrollIndicator={false}
      >
        {/* Overview Stats */}
        <Text style={styles.sectionTitle}>Overview</Text>
        <View style={styles.statsGrid}>
          <StatBlock
            icon="link"
            value={stats?.total_links}
            label="Total Links"
          />
          <StatBlock
            icon="mouse-pointer"
            value={stats?.total_clicks}
            label="Total Clicks"
            color={colors.success}
          />
          <StatBlock
            icon="trending-up"
            value={stats?.clicks_today}
            label="Clicks Today"
            color={colors.warning}
          />
          <StatBlock
            icon="calendar"
            value={stats?.links_this_week}
            label="Links This Week"
            color={colors.categories.personal}
          />
        </View>

        {/* Top Performing Links */}
        <Text style={styles.sectionTitle}>Top Performing</Text>
        <View style={styles.card}>
          {stats?.top_links?.length > 0 ? (
            stats.top_links.map((link, index) => (
              <View
                key={link.code}
                style={[
                  styles.topLinkRow,
                  index < stats.top_links.length - 1 && styles.topLinkBorder,
                ]}
              >
                <View style={styles.topLinkRank}>
                  <Text style={styles.rankText}>{index + 1}</Text>
                </View>
                <View style={styles.topLinkInfo}>
                  <Text style={styles.topLinkCode}>/{link.code}</Text>
                  <Text style={styles.topLinkDest} numberOfLines={1}>
                    {link.destination}
                  </Text>
                </View>
                <View style={styles.topLinkClicks}>
                  <Feather name="mouse-pointer" size={12} color={colors.mutedForeground} />
                  <Text style={styles.topLinkClicksText}>{link.clicks}</Text>
                </View>
              </View>
            ))
          ) : (
            <View style={styles.emptyCard}>
              <Feather name="bar-chart-2" size={32} color={colors.mutedForeground} />
              <Text style={styles.emptyText}>No data yet</Text>
            </View>
          )}
        </View>

        {/* Click Rate Info */}
        <Text style={styles.sectionTitle}>Insights</Text>
        <View style={styles.card}>
          <View style={styles.insightRow}>
            <Feather name="activity" size={18} color={colors.indigo} />
            <View style={styles.insightContent}>
              <Text style={styles.insightTitle}>Average Clicks</Text>
              <Text style={styles.insightValue}>
                {stats?.total_links > 0
                  ? Math.round(stats.total_clicks / stats.total_links)
                  : 0}{' '}
                per link
              </Text>
            </View>
          </View>
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
    fontSize: typography.lg,
    fontWeight: typography.semibold,
    color: colors.foreground,
    marginTop: spacing.xl,
    marginBottom: spacing.md,
  },
  statsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: spacing.md,
  },
  statBlock: {
    width: '48%',
    backgroundColor: colors.card,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
  },
  statIcon: {
    width: 40,
    height: 40,
    borderRadius: borderRadius.md,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: spacing.sm,
  },
  statValue: {
    fontSize: typography.xxl,
    fontWeight: typography.bold,
    color: colors.foreground,
  },
  statLabel: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
    marginTop: spacing.xs,
  },
  card: {
    backgroundColor: colors.card,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
  },
  topLinkRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: spacing.md,
  },
  topLinkBorder: {
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  topLinkRank: {
    width: 28,
    height: 28,
    borderRadius: 14,
    backgroundColor: colors.muted,
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: spacing.md,
  },
  rankText: {
    fontSize: typography.sm,
    fontWeight: typography.semibold,
    color: colors.foreground,
  },
  topLinkInfo: {
    flex: 1,
  },
  topLinkCode: {
    fontSize: typography.base,
    fontWeight: typography.medium,
    color: colors.foreground,
  },
  topLinkDest: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
    marginTop: 2,
  },
  topLinkClicks: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
  },
  topLinkClicksText: {
    fontSize: typography.sm,
    fontWeight: typography.medium,
    color: colors.mutedForeground,
  },
  insightRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
  },
  insightContent: {
    flex: 1,
  },
  insightTitle: {
    fontSize: typography.base,
    fontWeight: typography.medium,
    color: colors.foreground,
  },
  insightValue: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
    marginTop: 2,
  },
  emptyCard: {
    alignItems: 'center',
    paddingVertical: spacing.xl,
  },
  emptyText: {
    fontSize: typography.base,
    color: colors.mutedForeground,
    marginTop: spacing.md,
  },
});
