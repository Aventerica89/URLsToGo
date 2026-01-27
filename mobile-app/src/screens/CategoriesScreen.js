import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TouchableOpacity,
  RefreshControl,
  Alert,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Feather } from '@expo/vector-icons';
import { colors, spacing, borderRadius, typography } from '../constants/theme';
import { categoriesApi, tagsApi } from '../services/api';

export default function CategoriesScreen() {
  const [categories, setCategories] = useState([]);
  const [tags, setTags] = useState([]);
  const [refreshing, setRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState('categories');

  const loadData = useCallback(async () => {
    try {
      const [catsData, tagsData] = await Promise.all([
        categoriesApi.getAll(),
        tagsApi.getAll(),
      ]);
      setCategories(catsData || []);
      setTags(tagsData || []);
    } catch (error) {
      console.error('Failed to load data:', error);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await loadData();
    setRefreshing(false);
  }, [loadData]);

  const getCategoryColor = (colorName) => {
    const categoryColors = {
      work: colors.categories.work,
      personal: colors.categories.personal,
      social: colors.categories.social,
      marketing: colors.categories.marketing,
    };
    return categoryColors[colorName] || colors.mutedForeground;
  };

  const handleDeleteCategory = (id, name) => {
    Alert.alert(
      'Delete Category',
      `Are you sure you want to delete "${name}"?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            try {
              await categoriesApi.delete(id);
              loadData();
            } catch (error) {
              Alert.alert('Error', 'Failed to delete category');
            }
          },
        },
      ]
    );
  };

  const handleDeleteTag = (id, name) => {
    Alert.alert(
      'Delete Tag',
      `Are you sure you want to delete "${name}"?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            try {
              await tagsApi.delete(id);
              loadData();
            } catch (error) {
              Alert.alert('Error', 'Failed to delete tag');
            }
          },
        },
      ]
    );
  };

  const renderCategoryItem = ({ item }) => (
    <View style={styles.itemCard}>
      <View style={styles.itemContent}>
        <View
          style={[
            styles.categoryDot,
            { backgroundColor: getCategoryColor(item.color) },
          ]}
        />
        <View style={styles.itemInfo}>
          <Text style={styles.itemName}>{item.name}</Text>
          <Text style={styles.itemMeta}>{item.link_count || 0} links</Text>
        </View>
      </View>
      <TouchableOpacity
        style={styles.deleteButton}
        onPress={() => handleDeleteCategory(item.id, item.name)}
      >
        <Feather name="trash-2" size={18} color={colors.mutedForeground} />
      </TouchableOpacity>
    </View>
  );

  const renderTagItem = ({ item }) => (
    <View style={styles.itemCard}>
      <View style={styles.itemContent}>
        <Feather name="hash" size={18} color={colors.indigo} />
        <View style={styles.itemInfo}>
          <Text style={styles.itemName}>{item.name}</Text>
          <Text style={styles.itemMeta}>{item.link_count || 0} links</Text>
        </View>
      </View>
      <TouchableOpacity
        style={styles.deleteButton}
        onPress={() => handleDeleteTag(item.id, item.name)}
      >
        <Feather name="trash-2" size={18} color={colors.mutedForeground} />
      </TouchableOpacity>
    </View>
  );

  return (
    <SafeAreaView style={styles.container} edges={['top']}>
      <View style={styles.titleBar}>
        <Text style={styles.title}>Organize</Text>
      </View>

      {/* Tabs */}
      <View style={styles.tabs}>
        <TouchableOpacity
          style={[styles.tab, activeTab === 'categories' && styles.tabActive]}
          onPress={() => setActiveTab('categories')}
        >
          <Text
            style={[
              styles.tabText,
              activeTab === 'categories' && styles.tabTextActive,
            ]}
          >
            Categories
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tab, activeTab === 'tags' && styles.tabActive]}
          onPress={() => setActiveTab('tags')}
        >
          <Text
            style={[
              styles.tabText,
              activeTab === 'tags' && styles.tabTextActive,
            ]}
          >
            Tags
          </Text>
        </TouchableOpacity>
      </View>

      {activeTab === 'categories' ? (
        <FlatList
          data={categories}
          keyExtractor={(item) => item.id.toString()}
          renderItem={renderCategoryItem}
          contentContainerStyle={styles.list}
          refreshControl={
            <RefreshControl
              refreshing={refreshing}
              onRefresh={onRefresh}
              tintColor={colors.indigo}
            />
          }
          ListEmptyComponent={
            <View style={styles.emptyState}>
              <Feather name="folder" size={48} color={colors.mutedForeground} />
              <Text style={styles.emptyTitle}>No categories</Text>
              <Text style={styles.emptyText}>
                Create categories in the web dashboard
              </Text>
            </View>
          }
        />
      ) : (
        <FlatList
          data={tags}
          keyExtractor={(item) => item.id.toString()}
          renderItem={renderTagItem}
          contentContainerStyle={styles.list}
          refreshControl={
            <RefreshControl
              refreshing={refreshing}
              onRefresh={onRefresh}
              tintColor={colors.indigo}
            />
          }
          ListEmptyComponent={
            <View style={styles.emptyState}>
              <Feather name="hash" size={48} color={colors.mutedForeground} />
              <Text style={styles.emptyTitle}>No tags</Text>
              <Text style={styles.emptyText}>
                Create tags in the web dashboard
              </Text>
            </View>
          }
        />
      )}
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
  tabs: {
    flexDirection: 'row',
    paddingHorizontal: spacing.xl,
    marginBottom: spacing.lg,
    gap: spacing.sm,
  },
  tab: {
    paddingVertical: spacing.sm,
    paddingHorizontal: spacing.lg,
    borderRadius: borderRadius.md,
    backgroundColor: colors.muted,
  },
  tabActive: {
    backgroundColor: colors.foreground,
  },
  tabText: {
    fontSize: typography.sm,
    fontWeight: typography.medium,
    color: colors.mutedForeground,
  },
  tabTextActive: {
    color: colors.background,
  },
  list: {
    paddingHorizontal: spacing.xl,
    paddingBottom: 100,
  },
  itemCard: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: colors.card,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
    marginBottom: spacing.md,
  },
  itemContent: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
  },
  categoryDot: {
    width: 12,
    height: 12,
    borderRadius: 6,
  },
  itemInfo: {
    gap: 2,
  },
  itemName: {
    fontSize: typography.base,
    fontWeight: typography.medium,
    color: colors.foreground,
  },
  itemMeta: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
  },
  deleteButton: {
    padding: spacing.sm,
  },
  emptyState: {
    alignItems: 'center',
    paddingVertical: spacing.xxxl * 2,
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
