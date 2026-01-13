import React, { createContext, useState, useEffect } from 'react';
import { getUserFromToken } from '../utils/authUtils';
import { API_BASE } from '../api/api';


// Create the Auth Context
export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Initialize auth state from localStorage on mount
  useEffect(() => {
    const storedToken = localStorage.getItem('auth_token');
    const storedTier = localStorage.getItem('is_premium');
    if (storedToken) {
      setToken(storedToken);
      setUser({
        ...getUserFromToken(storedToken),
        is_premium: storedTier === "true",
      });
      //setUser(getUserFromToken(storedToken));

      setIsAuthenticated(true);
      // Optionally, verify token with backend here
      // For now, we trust the stored token
    }
    setIsLoading(false);
  }, []);

  // Login function
  const login = async (email, password) => {
    setIsLoading(true);
    try {
      //const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body:  JSON.stringify({
          email,
          password,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || 'Login failed.  Please check your credentials.');
      }

      const data = await response.json();
      const authToken = data.access_token || data.token;

      if (!authToken) {
        throw new Error('No authorization token received from server.');
      }

      const decodedUser = getUserFromToken(authToken);

      // Store token and update state
      localStorage.setItem('auth_token', authToken);
      localStorage.setItem('is_premium', data.is_premium);
      setToken(authToken);
      
      setUser({
        ...decodedUser,
        is_premium: data.is_premium,
      });

      //localStorage.setItem("is_premium", data.is_premium);

      //setUser(getUserFromToken(authToken));
      setIsAuthenticated(true);

      return { success: true };
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, error: error.message };
    } finally {
      setIsLoading(false);
    }
  };

  // Register function
  const register = async (email, password, isPremium = false) => {
    setIsLoading(true);
    try {
      //const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';
      const response = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          password,
          is_premium:  isPremium,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(
          errorData.message || 'Registration failed. Please try again with different credentials.'
        );
      }

      const data = await response.json();
      const authToken = data.access_token || data.token;

      if (!authToken) {
        throw new Error('No authorization token received from server.');
      }

      // Store token and update state
      const decodedUser = getUserFromToken(authToken);

      localStorage.setItem('is_premium', isPremium);
      localStorage.setItem('auth_token', authToken);
      setToken(authToken);
      setUser({
        ...decodedUser,
        is_premium: isPremium,
      });
      
      //setUser(getUserFromToken(authToken));
      setIsAuthenticated(true);

      return { success:  true };
    } catch (error) {
      console.error('Register error:', error);
      return { success: false, error: error.message };
    } finally {
      setIsLoading(false);
    }
  };

  // Logout function
  const logout = () => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('is_premium');
    setToken(null);
    setUser(null);
    setIsAuthenticated(false);
  };

  // Get authorization header (useful for making authenticated requests)
  const getAuthHeader = () => {
    if (! token) return {};
    return {
      Authorization: `Bearer ${token}`,
    };
  };

  const value = {
    user,
    token,
    isAuthenticated,
    isLoading,
    login,
    register,
    logout,
    getAuthHeader,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// Custom hook for using auth context
export function useAuth() {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}