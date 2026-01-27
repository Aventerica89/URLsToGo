import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';

import TabNavigator from './TabNavigator';
import CreateLinkScreen from '../screens/CreateLinkScreen';
import LinkDetailScreen from '../screens/LinkDetailScreen';
import LoginScreen from '../screens/LoginScreen';
import { colors } from '../constants/theme';

const Stack = createNativeStackNavigator();

export default function AppNavigator({ isAuthenticated, onLogin, onLogout }) {
  return (
    <NavigationContainer>
      <Stack.Navigator
        screenOptions={{
          headerStyle: {
            backgroundColor: colors.background,
          },
          headerTintColor: colors.foreground,
          headerTitleStyle: {
            fontWeight: '600',
          },
          contentStyle: {
            backgroundColor: colors.background,
          },
        }}
      >
        {!isAuthenticated ? (
          <Stack.Screen
            name="Login"
            options={{ headerShown: false }}
          >
            {(props) => <LoginScreen {...props} onLogin={onLogin} />}
          </Stack.Screen>
        ) : (
          <>
            <Stack.Screen
              name="Main"
              options={{ headerShown: false }}
            >
              {(props) => <TabNavigator {...props} onLogout={onLogout} />}
            </Stack.Screen>
            <Stack.Screen
              name="CreateLink"
              component={CreateLinkScreen}
              options={{
                presentation: 'modal',
                title: 'New Link',
              }}
            />
            <Stack.Screen
              name="LinkDetail"
              component={LinkDetailScreen}
              options={{
                title: 'Link Details',
              }}
            />
          </>
        )}
      </Stack.Navigator>
    </NavigationContainer>
  );
}
