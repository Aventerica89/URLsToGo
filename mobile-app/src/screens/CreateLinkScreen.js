import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TextInput,
  TouchableOpacity,
  ScrollView,
  Alert,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import { Feather } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import { colors, spacing, borderRadius, typography } from '../constants/theme';
import { linksApi, categoriesApi } from '../services/api';

export default function CreateLinkScreen({ navigation }) {
  const [destination, setDestination] = useState('');
  const [customCode, setCustomCode] = useState('');
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadCategories();
  }, []);

  const loadCategories = async () => {
    try {
      const data = await categoriesApi.getAll();
      setCategories(data || []);
    } catch (error) {
      console.error('Failed to load categories:', error);
    }
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

  const handleCreate = async () => {
    if (!destination.trim()) {
      Alert.alert('Error', 'Please enter a destination URL');
      return;
    }

    // Basic URL validation
    let url = destination.trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }

    setLoading(true);
    try {
      const data = {
        destination: url,
      };

      if (customCode.trim()) {
        data.code = customCode.trim();
      }

      if (selectedCategory) {
        data.category_id = selectedCategory;
      }

      await linksApi.create(data);
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      navigation.goBack();
    } catch (error) {
      Alert.alert('Error', error.message || 'Failed to create link');
    } finally {
      setLoading(false);
    }
  };

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
    >
      <ScrollView
        style={styles.content}
        keyboardShouldPersistTaps="handled"
        showsVerticalScrollIndicator={false}
      >
        {/* Destination URL */}
        <View style={styles.field}>
          <Text style={styles.label}>Destination URL</Text>
          <View style={styles.inputContainer}>
            <Feather name="link" size={18} color={colors.mutedForeground} />
            <TextInput
              style={styles.input}
              placeholder="https://example.com/your-long-url"
              placeholderTextColor={colors.mutedForeground}
              value={destination}
              onChangeText={setDestination}
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="url"
            />
          </View>
        </View>

        {/* Custom Code (Optional) */}
        <View style={styles.field}>
          <Text style={styles.label}>Custom Code (Optional)</Text>
          <View style={styles.inputContainer}>
            <Text style={styles.prefix}>/</Text>
            <TextInput
              style={styles.input}
              placeholder="my-custom-link"
              placeholderTextColor={colors.mutedForeground}
              value={customCode}
              onChangeText={setCustomCode}
              autoCapitalize="none"
              autoCorrect={false}
            />
          </View>
          <Text style={styles.hint}>
            Leave empty for auto-generated code
          </Text>
        </View>

        {/* Category Selection */}
        <View style={styles.field}>
          <Text style={styles.label}>Category (Optional)</Text>
          <View style={styles.categoryGrid}>
            <TouchableOpacity
              style={[
                styles.categoryChip,
                selectedCategory === null && styles.categoryChipSelected,
              ]}
              onPress={() => setSelectedCategory(null)}
            >
              <Text
                style={[
                  styles.categoryChipText,
                  selectedCategory === null && styles.categoryChipTextSelected,
                ]}
              >
                None
              </Text>
            </TouchableOpacity>
            {categories.map((cat) => (
              <TouchableOpacity
                key={cat.id}
                style={[
                  styles.categoryChip,
                  selectedCategory === cat.id && styles.categoryChipSelected,
                  selectedCategory === cat.id && {
                    borderColor: getCategoryColor(cat.color),
                  },
                ]}
                onPress={() => setSelectedCategory(cat.id)}
              >
                <View
                  style={[
                    styles.categoryDot,
                    { backgroundColor: getCategoryColor(cat.color) },
                  ]}
                />
                <Text
                  style={[
                    styles.categoryChipText,
                    selectedCategory === cat.id && styles.categoryChipTextSelected,
                  ]}
                >
                  {cat.name}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        </View>

        {/* Create Button */}
        <TouchableOpacity
          style={[styles.createButton, loading && styles.createButtonDisabled]}
          onPress={handleCreate}
          disabled={loading}
          activeOpacity={0.8}
        >
          <Feather name="plus" size={20} color="#fff" />
          <Text style={styles.createButtonText}>
            {loading ? 'Creating...' : 'Create Link'}
          </Text>
        </TouchableOpacity>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.background,
  },
  content: {
    flex: 1,
    padding: spacing.xl,
  },
  field: {
    marginBottom: spacing.xl,
  },
  label: {
    fontSize: typography.sm,
    fontWeight: typography.medium,
    color: colors.foreground,
    marginBottom: spacing.sm,
  },
  inputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.card,
    borderRadius: borderRadius.lg,
    borderWidth: 1,
    borderColor: colors.border,
    paddingHorizontal: spacing.lg,
    height: 52,
    gap: spacing.sm,
  },
  prefix: {
    fontSize: typography.base,
    color: colors.mutedForeground,
    fontWeight: typography.medium,
  },
  input: {
    flex: 1,
    fontSize: typography.base,
    color: colors.foreground,
  },
  hint: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
    marginTop: spacing.sm,
    marginLeft: spacing.xs,
  },
  categoryGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: spacing.sm,
  },
  categoryChip: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.card,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.border,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    gap: spacing.sm,
  },
  categoryChipSelected: {
    backgroundColor: colors.muted,
    borderColor: colors.foreground,
  },
  categoryDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  categoryChipText: {
    fontSize: typography.sm,
    color: colors.mutedForeground,
  },
  categoryChipTextSelected: {
    color: colors.foreground,
  },
  createButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: colors.indigo,
    borderRadius: borderRadius.lg,
    height: 52,
    gap: spacing.sm,
    marginTop: spacing.lg,
  },
  createButtonDisabled: {
    opacity: 0.6,
  },
  createButtonText: {
    fontSize: typography.base,
    fontWeight: typography.semibold,
    color: '#fff',
  },
});
