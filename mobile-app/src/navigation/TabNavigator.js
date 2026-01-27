import React from 'react';
import { View, StyleSheet, TouchableOpacity } from 'react-native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { Feather } from '@expo/vector-icons';

import LinksScreen from '../screens/LinksScreen';
import AnalyticsScreen from '../screens/AnalyticsScreen';
import CategoriesScreen from '../screens/CategoriesScreen';
import SettingsScreen from '../screens/SettingsScreen';
import { colors, spacing } from '../constants/theme';

const Tab = createBottomTabNavigator();

// Custom center button for "Add" action
const AddButton = ({ onPress }) => (
  <TouchableOpacity style={styles.addButton} onPress={onPress} activeOpacity={0.8}>
    <View style={styles.addButtonInner}>
      <Feather name="plus" size={28} color="#fff" />
    </View>
  </TouchableOpacity>
);

// Placeholder component for the Add tab (never actually shown)
const AddPlaceholder = () => null;

export default function TabNavigator({ navigation, onLogout }) {
  return (
    <Tab.Navigator
      screenOptions={{
        headerShown: false,
        tabBarStyle: styles.tabBar,
        tabBarActiveTintColor: colors.foreground,
        tabBarInactiveTintColor: colors.mutedForeground,
        tabBarShowLabel: true,
        tabBarLabelStyle: styles.tabBarLabel,
      }}
    >
      <Tab.Screen
        name="Links"
        component={LinksScreen}
        options={{
          tabBarIcon: ({ color, size }) => (
            <Feather name="link" size={22} color={color} />
          ),
        }}
      />
      <Tab.Screen
        name="Analytics"
        component={AnalyticsScreen}
        options={{
          tabBarIcon: ({ color, size }) => (
            <Feather name="bar-chart-2" size={22} color={color} />
          ),
        }}
      />
      <Tab.Screen
        name="Add"
        component={AddPlaceholder}
        options={{
          tabBarButton: (props) => (
            <AddButton
              onPress={() => navigation.navigate('CreateLink')}
            />
          ),
        }}
        listeners={{
          tabPress: (e) => {
            e.preventDefault();
            navigation.navigate('CreateLink');
          },
        }}
      />
      <Tab.Screen
        name="Categories"
        component={CategoriesScreen}
        options={{
          tabBarIcon: ({ color, size }) => (
            <Feather name="grid" size={22} color={color} />
          ),
        }}
      />
      <Tab.Screen
        name="Settings"
        options={{
          tabBarIcon: ({ color, size }) => (
            <Feather name="settings" size={22} color={color} />
          ),
        }}
      >
        {(props) => <SettingsScreen {...props} onLogout={onLogout} />}
      </Tab.Screen>
    </Tab.Navigator>
  );
}

const styles = StyleSheet.create({
  tabBar: {
    backgroundColor: colors.card,
    borderTopColor: colors.border,
    borderTopWidth: 1,
    height: 85,
    paddingTop: spacing.sm,
    paddingBottom: 25,
  },
  tabBarLabel: {
    fontSize: 11,
    fontWeight: '500',
    marginTop: 4,
  },
  addButton: {
    top: -20,
    justifyContent: 'center',
    alignItems: 'center',
  },
  addButtonInner: {
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: colors.indigo,
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: colors.indigo,
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.4,
    shadowRadius: 8,
    elevation: 8,
  },
});
