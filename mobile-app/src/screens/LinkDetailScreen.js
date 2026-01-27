import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Alert,
  Share,
} from 'react-native';
import { Feather } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import * as Haptics from 'expo-haptics';
import { colors, spacing, borderRadius, typography } from '../constants/theme';
import { linksApi } from '../services/api';
import { API_BASE_URL } from '../constants/config';

export default function LinkDetailScreen({ route, navigation }) {
  const { code } = route.params;
  const [link, setLink] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadLink();
  }, [code]);

  const loadLink = async () => {
    try {
      const data = await linksApi.get(code);
      setLink(data);
    } catch (error) {
      Alert.alert('Error', 'Failed to load link details');
      navigation.goBack();
    } finally {
      setLoading(false);
    }
  };

  const shortUrl = `${API_BASE_URL}/${code}`;

  const handleCopy = async () => {
    await Clipboard.setStringAsync(shortUrl);
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
    Alert.alert('Copied!', 'Link copied to clipboard');
  };

  const handleShare = async () => {
    try {
      await Share.share({
        message: shortUrl,
        url: shortUrl,
      });
    } catch (error) {
      console.error('Share error:', error);
    }
  };

  const handleDelete = () => {
    Alert.alert(
      'Delete Link',
      'Are you sure you want to delete this link? This action cannot be undone.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            try {
              await linksApi.delete(code);
              Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
              navigation.goBack();
            } catch (error) {
              Alert.alert('Error', 'Failed to delete link');
            }
          },
        },
      ]
    );
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  const getCategoryColor = (colorName) => {
    const categoryColors = {
      work: colors.categories.work,
      personal: colors.categories.personal,
      social: colors.categories.social,
      marketing: colors.categories.marketing,
    };
    return categoryColors[colorName] || colors.mutedForeground;
  };

  if (loading || !link) {
    return (
      <View style={[styles.container, styles.centered]}>
        <Text style={styles.loadingText}>Loading...</Text>
      </View>
    );
  }

  return (
    <ScrollView style={styles.container} showsVerticalScrollIndicator={false}>
      {/* Short URL Card */}
      <View style={styles.urlCard}>
        <Text style={styles.shortUrlLabel}>Short URL</Text>
        <Text style={styles.shortUrl}>/{link.code}</Text>
        <View style={styles.urlActions}>
          <TouchableOpacity style={styles.urlButton} onPress={handleCopy}>
            <Feather name="copy" size={18} color={colors.foreground} />
            <Text style={styles.urlButtonText}>Copy</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.urlButton} onPress={handleShare}>
            <Feather name="share" size={18} color={colors.foreground} />
            <Text style={styles.urlButtonText}>Share</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Stats */}
      <View style={styles.statsRow}>
        <View style={styles.statItem}>
          <Feather name="mouse-pointer" size={20} color={colors.indigo} />
          <Text style={styles.statValue}>{link.clicks}</Text>
          <Text style={styles.statLabel}>Clicks</Text>
        </View>
        <View style={styles.statDivider} />
        <View style={styles.statItem}>
          <Feather name="calendar" size={20} color={colors.indigo} />
          <Text style={styles.statValue}>
            {new Date(link.created_at).toLocaleDateString('en-US', {
              month: 'short',
              day: 'numeric',
            })}
          </Text>
          <Text style={styles.statLabel}>Created</Text>
        </View>
        {link.is_protected && (
          <>
            <View style={styles.statDivider} />
            <View style={styles.statItem}>
              <Feather name="lock" size={20} color={colors.indigo} />
              <Text style={styles.statValue}>Yes</Text>
              <Text style={styles.statLabel}>Protected</Text>
            </View>
          </>
        )}
      </View>

      {/* Details */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Details</Text>
        <View style={styles.detailCard}>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Destination</Text>
            <Text style={styles.detailValue} numberOfLines={2}>
              {link.destination}
            </Text>
          </View>

          {link.category_name && (
            <View style={styles.detailRow}>
              <Text style={styles.detailLabel}>Category</Text>
              <View style={styles.categoryBadge}>
                <View
                  style={[
                    styles.categoryDot,
                    { backgroundColor: getCategoryColor(link.category_color) },
                  ]}
                />
                <Text style={styles.categoryText}>{link.category_name}</Text>
              </View>
            </View>
          )}

          {link.tags && link.tags.length > 0 && (
            <View style={styles.detailRow}>
              <Text style={styles.detailLabel}>Tags</Text>
              <View style={styles.tagsContainer}>
                {link.tags.map((tag, index) => (
                  <View key={index} style={styles.tag}>
                    <Text style={styles.tagText}>{tag}</Text>
                  </View>
                ))}
              </View>
            </View>
          )}

          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Created</Text>
            <Text style={styles.detailValue}>{formatDate(link.created_at)}</Text>
          </View>

          {link.expires_at && (
            <View style={styles.detailRow}>
              <Text style={styles.detailLabel}>Expires</Text>
              <Text style={styles.detailValue}>{formatDate(link.expires_at)}</Text>
            </View>
          )}
        </View>
      </View>

      {/* Danger Zone */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Danger Zone</Text>
        <TouchableOpacity style={styles.deleteButton} onPress={handleDelete}>
          <Feather name="trash-2" size={18} color={colors.error} />
          <Text style={styles.deleteButtonText}>Delete Link</Text>
        </TouchableOpacity>
      </View>

      <View style={{ height: 40 }} />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background,
    padding: spacing.xl,
  },
  centered: {
    justifyContent: 'center',
    alignItems: 'center',
  },
  loadingText: {
    fontSize: typography.base,
    color: colors.mutedForeground,
  },
  urlCard: {
    backgroundColor: colors.card,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.xl,
    alignItems: 'center',
  },
  shortUrlLabel: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
    marginBottom: spacing.sm,
  },
  shortUrl: {
    fontSize: typography.xxl,
    fontWeight: typography.bold,
    color: colors.foreground,
    marginBottom: spacing.lg,
  },
  urlActions: {
    flexDirection: 'row',
    gap: spacing.md,
  },
  urlButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.muted,
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.sm,
    borderRadius: borderRadius.md,
    gap: spacing.sm,
  },
  urlButtonText: {
    fontSize: typography.sm,
    fontWeight: typography.medium,
    color: colors.foreground,
  },
  statsRow: {
    flexDirection: 'row',
    backgroundColor: colors.card,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.border,
    marginTop: spacing.lg,
    padding: spacing.lg,
  },
  statItem: {
    flex: 1,
    alignItems: 'center',
  },
  statDivider: {
    width: 1,
    backgroundColor: colors.border,
    marginHorizontal: spacing.md,
  },
  statValue: {
    fontSize: typography.lg,
    fontWeight: typography.bold,
    color: colors.foreground,
    marginTop: spacing.sm,
  },
  statLabel: {
    fontSize: typography.xs,
    color: colors.mutedForeground,
    marginTop: 2,
  },
  section: {
    marginTop: spacing.xl,
  },
  sectionTitle: {
    fontSize: typography.sm,
    fontWeight: typography.semibold,
    color: colors.mutedForeground,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: spacing.md,
  },
  detailCard: {
    backgroundColor: colors.card,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
  },
  detailRow: {
    marginBottom: spacing.lg,
  },
  detailLabel: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
    marginBottom: spacing.xs,
  },
  detailValue: {
    fontSize: typography.base,
    color: colors.foreground,
  },
  categoryBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
  },
  categoryDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  categoryText: {
    fontSize: typography.base,
    color: colors.foreground,
  },
  tagsContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: spacing.sm,
  },
  tag: {
    backgroundColor: colors.muted,
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.xs,
    borderRadius: borderRadius.sm,
  },
  tagText: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
  },
  deleteButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: `${colors.error}15`,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: `${colors.error}30`,
    padding: spacing.lg,
    gap: spacing.sm,
  },
  deleteButtonText: {
    fontSize: typography.base,
    fontWeight: typography.medium,
    color: colors.error,
  },
});
