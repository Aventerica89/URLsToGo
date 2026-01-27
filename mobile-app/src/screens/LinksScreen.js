import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TextInput,
  TouchableOpacity,
  RefreshControl,
  Alert,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Feather } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import * as Haptics from 'expo-haptics';

import { colors, spacing, borderRadius, typography } from '../constants/theme';
import { linksApi, statsApi } from '../services/api';
import LinkCard from '../components/LinkCard';
import StatsCard from '../components/StatsCard';

export default function LinksScreen({ navigation }) {
  const [links, setLinks] = useState([]);
  const [stats, setStats] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      const [linksData, statsData] = await Promise.all([
        linksApi.getAll({ search: searchQuery }),
        statsApi.get(),
      ]);
      setLinks(linksData.links || []);
      setStats(statsData);
    } catch (error) {
      Alert.alert('Error', 'Failed to load data');
      console.error(error);
    } finally {
      setLoading(false);
    }
  }, [searchQuery]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await loadData();
    setRefreshing(false);
  }, [loadData]);

  const handleCopyLink = async (code) => {
    await Clipboard.setStringAsync(`${code}`);
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
  };

  const handleDeleteLink = (code) => {
    Alert.alert(
      'Delete Link',
      'Are you sure you want to delete this link?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            try {
              await linksApi.delete(code);
              Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
              loadData();
            } catch (error) {
              Alert.alert('Error', 'Failed to delete link');
            }
          },
        },
      ]
    );
  };

  const renderHeader = () => (
    <View style={styles.header}>
      {/* Stats Row */}
      <View style={styles.statsRow}>
        <StatsCard
          icon="link"
          value={stats?.total_links || 0}
          label="Total Links"
        />
        <StatsCard
          icon="mouse-pointer"
          value={stats?.total_clicks || 0}
          label="Total Clicks"
        />
      </View>

      {/* Search Bar */}
      <View style={styles.searchContainer}>
        <Feather name="search" size={18} color={colors.mutedForeground} />
        <TextInput
          style={styles.searchInput}
          placeholder="Search links..."
          placeholderTextColor={colors.mutedForeground}
          value={searchQuery}
          onChangeText={setSearchQuery}
          returnKeyType="search"
          onSubmitEditing={loadData}
        />
        {searchQuery.length > 0 && (
          <TouchableOpacity onPress={() => setSearchQuery('')}>
            <Feather name="x" size={18} color={colors.mutedForeground} />
          </TouchableOpacity>
        )}
      </View>

      {/* Section Title */}
      <View style={styles.sectionHeader}>
        <Text style={styles.sectionTitle}>Recent Links</Text>
        <Text style={styles.sectionCount}>{links.length} links</Text>
      </View>
    </View>
  );

  const renderEmptyState = () => (
    <View style={styles.emptyState}>
      <Feather name="link" size={48} color={colors.mutedForeground} />
      <Text style={styles.emptyTitle}>No links yet</Text>
      <Text style={styles.emptyText}>
        Tap the + button to create your first short link
      </Text>
    </View>
  );

  return (
    <SafeAreaView style={styles.container} edges={['top']}>
      {/* App Title */}
      <View style={styles.titleBar}>
        <Text style={styles.title}>Links</Text>
        <TouchableOpacity
          style={styles.profileButton}
          onPress={() => navigation.navigate('Settings')}
        >
          <Feather name="user" size={20} color={colors.foreground} />
        </TouchableOpacity>
      </View>

      <FlatList
        data={links}
        keyExtractor={(item) => item.code}
        renderItem={({ item }) => (
          <LinkCard
            link={item}
            onPress={() => navigation.navigate('LinkDetail', { code: item.code })}
            onCopy={() => handleCopyLink(item.code)}
            onDelete={() => handleDeleteLink(item.code)}
          />
        )}
        ListHeaderComponent={renderHeader}
        ListEmptyComponent={!loading && renderEmptyState}
        contentContainerStyle={styles.listContent}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={onRefresh}
            tintColor={colors.indigo}
          />
        }
        showsVerticalScrollIndicator={false}
      />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background,
  },
  titleBar: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: spacing.xl,
    paddingVertical: spacing.md,
  },
  title: {
    fontSize: typography.xxxl,
    fontWeight: typography.bold,
    color: colors.foreground,
  },
  profileButton: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: colors.muted,
    justifyContent: 'center',
    alignItems: 'center',
  },
  header: {
    paddingHorizontal: spacing.xl,
    paddingBottom: spacing.lg,
  },
  statsRow: {
    flexDirection: 'row',
    gap: spacing.md,
    marginBottom: spacing.lg,
  },
  searchContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.muted,
    borderRadius: borderRadius.lg,
    paddingHorizontal: spacing.lg,
    height: 44,
    gap: spacing.sm,
    marginBottom: spacing.xl,
  },
  searchInput: {
    flex: 1,
    color: colors.foreground,
    fontSize: typography.base,
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  sectionTitle: {
    fontSize: typography.lg,
    fontWeight: typography.semibold,
    color: colors.foreground,
  },
  sectionCount: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
  },
  listContent: {
    paddingBottom: 100,
  },
  emptyState: {
    alignItems: 'center',
    paddingVertical: spacing.xxxl * 2,
    paddingHorizontal: spacing.xl,
  },
  emptyTitle: {
    fontSize: typography.xl,
    fontWeight: typography.semibold,
    color: colors.foreground,
    marginTop: spacing.lg,
    marginBottom: spacing.sm,
  },
  emptyText: {
    fontSize: typography.base,
    color: colors.mutedForeground,
    textAlign: 'center',
  },
});
