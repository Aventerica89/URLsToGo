import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { Feather } from '@expo/vector-icons';
import { colors, spacing, borderRadius, typography } from '../constants/theme';

export default function LinkCard({ link, onPress, onCopy, onDelete }) {
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
    });
  };

  const truncateUrl = (url, maxLength = 35) => {
    if (!url) return '';
    // Remove protocol
    const clean = url.replace(/^https?:\/\//, '');
    if (clean.length <= maxLength) return clean;
    return clean.substring(0, maxLength) + '...';
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

  return (
    <TouchableOpacity
      style={styles.container}
      onPress={onPress}
      activeOpacity={0.7}
    >
      <View style={styles.content}>
        {/* Short URL */}
        <View style={styles.row}>
          <View style={styles.codeContainer}>
            {link.is_protected && (
              <Feather
                name="lock"
                size={12}
                color={colors.indigo}
                style={styles.lockIcon}
              />
            )}
            <Text style={styles.code}>/{link.code}</Text>
          </View>
          <View style={styles.actions}>
            <TouchableOpacity
              style={styles.actionButton}
              onPress={onCopy}
              hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}
            >
              <Feather name="copy" size={16} color={colors.mutedForeground} />
            </TouchableOpacity>
            <TouchableOpacity
              style={styles.actionButton}
              onPress={onDelete}
              hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}
            >
              <Feather name="trash-2" size={16} color={colors.mutedForeground} />
            </TouchableOpacity>
          </View>
        </View>

        {/* Destination URL */}
        <Text style={styles.destination} numberOfLines={1}>
          {truncateUrl(link.destination)}
        </Text>

        {/* Meta row */}
        <View style={styles.metaRow}>
          {/* Category badge */}
          {link.category_name && (
            <View
              style={[
                styles.categoryBadge,
                { backgroundColor: `${getCategoryColor(link.category_color)}20` },
              ]}
            >
              <View
                style={[
                  styles.categoryDot,
                  { backgroundColor: getCategoryColor(link.category_color) },
                ]}
              />
              <Text
                style={[
                  styles.categoryText,
                  { color: getCategoryColor(link.category_color) },
                ]}
              >
                {link.category_name}
              </Text>
            </View>
          )}

          {/* Clicks */}
          <View style={styles.clicksContainer}>
            <Feather name="mouse-pointer" size={12} color={colors.mutedForeground} />
            <Text style={styles.clicks}>{link.clicks}</Text>
          </View>

          {/* Date */}
          <Text style={styles.date}>{formatDate(link.created_at)}</Text>
        </View>

        {/* Tags */}
        {link.tags && link.tags.length > 0 && (
          <View style={styles.tagsRow}>
            {link.tags.slice(0, 3).map((tag, index) => (
              <View key={index} style={styles.tag}>
                <Text style={styles.tagText}>{tag}</Text>
              </View>
            ))}
            {link.tags.length > 3 && (
              <Text style={styles.moreText}>+{link.tags.length - 3}</Text>
            )}
          </View>
        )}
      </View>

      {/* Chevron */}
      <Feather name="chevron-right" size={20} color={colors.mutedForeground} />
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.card,
    marginHorizontal: spacing.xl,
    marginTop: spacing.md,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.border,
    padding: spacing.lg,
  },
  content: {
    flex: 1,
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: spacing.xs,
  },
  codeContainer: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  lockIcon: {
    marginRight: spacing.xs,
  },
  code: {
    fontSize: typography.lg,
    fontWeight: typography.semibold,
    color: colors.foreground,
  },
  actions: {
    flexDirection: 'row',
    gap: spacing.md,
  },
  actionButton: {
    padding: spacing.xs,
  },
  destination: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
    marginBottom: spacing.md,
  },
  metaRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.md,
  },
  categoryBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.xs,
    borderRadius: borderRadius.sm,
    gap: spacing.xs,
  },
  categoryDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
  },
  categoryText: {
    fontSize: typography.xs,
    fontWeight: typography.medium,
  },
  clicksContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
  },
  clicks: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
  },
  date: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
  },
  tagsRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: spacing.sm,
    gap: spacing.sm,
  },
  tag: {
    backgroundColor: colors.muted,
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.xs - 2,
    borderRadius: borderRadius.sm,
  },
  tagText: {
    fontSize: typography.xs,
    color: colors.mutedForeground,
  },
  moreText: {
    fontSize: typography.xs,
    color: colors.mutedForeground,
  },
});
