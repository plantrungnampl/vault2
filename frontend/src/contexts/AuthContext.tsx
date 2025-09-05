import React, { createContext, useContext, useReducer, useEffect } from 'react';
import axios from 'axios';

// Types
export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: string;
  status: string;
  mfa_enabled: boolean;
  email_verified: boolean;
  last_login_at?: string;
  preferences: {
    language: string;
    theme: string;
    timezone: string;
    notifications: {
      email: boolean;
      sms: boolean;
      push: boolean;
      security: boolean;
    };
  };
  created_at: string;
  updated_at: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  mfaRequired: boolean;
  mfaMethods: any[];
}

type AuthAction =
  | { type: 'LOGIN_START' }
  | { type: 'LOGIN_SUCCESS'; payload: { user: User; token: string; refreshToken: string } }
  | { type: 'LOGIN_FAILURE'; payload: string }
  | { type: 'MFA_REQUIRED'; payload: { mfaMethods: any[] } }
  | { type: 'LOGOUT' }
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'UPDATE_USER'; payload: User };

// Initial state
const initialState: AuthState = {
  user: null,
  token: localStorage.getItem('access_token'),
  refreshToken: localStorage.getItem('refresh_token'),
  isAuthenticated: false,
  isLoading: false,
  error: null,
  mfaRequired: false,
  mfaMethods: [],
};

// Reducer
function authReducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case 'LOGIN_START':
      return {
        ...state,
        isLoading: true,
        error: null,
        mfaRequired: false,
      };

    case 'LOGIN_SUCCESS':
      return {
        ...state,
        user: action.payload.user,
        token: action.payload.token,
        refreshToken: action.payload.refreshToken,
        isAuthenticated: true,
        isLoading: false,
        error: null,
        mfaRequired: false,
      };

    case 'LOGIN_FAILURE':
      return {
        ...state,
        isLoading: false,
        error: action.payload,
        isAuthenticated: false,
        mfaRequired: false,
      };

    case 'MFA_REQUIRED':
      return {
        ...state,
        isLoading: false,
        mfaRequired: true,
        mfaMethods: action.payload.mfaMethods,
        error: null,
      };

    case 'LOGOUT':
      return {
        ...initialState,
        token: null,
        refreshToken: null,
      };

    case 'SET_LOADING':
      return {
        ...state,
        isLoading: action.payload,
      };

    case 'SET_ERROR':
      return {
        ...state,
        error: action.payload,
      };

    case 'UPDATE_USER':
      return {
        ...state,
        user: action.payload,
      };

    default:
      return state;
  }
}

// Context
const AuthContext = createContext<{
  state: AuthState;
  login: (email: string, password: string, mfaCode?: string) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => void;
  verifyMFA: (code: string) => Promise<void>;
  updateProfile: (data: Partial<User>) => Promise<void>;
  refreshAccessToken: () => Promise<boolean>;
} | null>(null);

// Register data interface
export interface RegisterData {
  email: string;
  password: string;
  confirm_password: string;
  first_name: string;
  last_name: string;
}

// API configuration
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080/api/v1';

// Setup axios interceptor for auto token refresh
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        try {
          const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: refreshToken,
          });

          const { access_token, refresh_token: newRefreshToken } = response.data;
          localStorage.setItem('access_token', access_token);
          localStorage.setItem('refresh_token', newRefreshToken);

          // Update the authorization header
          originalRequest.headers.Authorization = `Bearer ${access_token}`;

          return axios(originalRequest);
        } catch (refreshError) {
          // Refresh failed, redirect to login
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          window.location.href = '/login';
          return Promise.reject(refreshError);
        }
      }
    }

    return Promise.reject(error);
  }
);

// Provider component
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Setup axios interceptor for adding auth header
  useEffect(() => {
    const interceptor = axios.interceptors.request.use(
      (config) => {
        if (state.token) {
          config.headers.Authorization = `Bearer ${state.token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    return () => {
      axios.interceptors.request.eject(interceptor);
    };
  }, [state.token]);

  // Check if user is authenticated on mount
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('access_token');
      if (token) {
        try {
          dispatch({ type: 'SET_LOADING', payload: true });
          const response = await axios.get(`${API_BASE_URL}/auth/profile`);
          dispatch({
            type: 'LOGIN_SUCCESS',
            payload: {
              user: response.data,
              token,
              refreshToken: localStorage.getItem('refresh_token') || '',
            },
          });
        } catch (error) {
          // Token is invalid, clear storage
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          dispatch({ type: 'LOGOUT' });
        } finally {
          dispatch({ type: 'SET_LOADING', payload: false });
        }
      }
    };

    checkAuth();
  }, []);

  const login = async (email: string, password: string, mfaCode?: string) => {
    try {
      dispatch({ type: 'LOGIN_START' });

      const response = await axios.post(`${API_BASE_URL}/auth/login`, {
        email,
        password,
        mfa_code: mfaCode,
      });

      const { access_token, refresh_token, user, mfa_required, mfa_methods } = response.data;

      if (mfa_required) {
        dispatch({
          type: 'MFA_REQUIRED',
          payload: { mfaMethods: mfa_methods },
        });
        return;
      }

      // Store tokens
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('refresh_token', refresh_token);

      dispatch({
        type: 'LOGIN_SUCCESS',
        payload: {
          user,
          token: access_token,
          refreshToken: refresh_token,
        },
      });
    } catch (error: any) {
      const errorMessage = error.response?.data?.error || 'Đăng nhập thất bại';
      dispatch({ type: 'LOGIN_FAILURE', payload: errorMessage });
      throw new Error(errorMessage);
    }
  };

  const register = async (data: RegisterData) => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true });

      await axios.post(`${API_BASE_URL}/auth/register`, data);

      // Registration successful, you might want to auto-login or redirect
      dispatch({ type: 'SET_LOADING', payload: false });
    } catch (error: any) {
      const errorMessage = error.response?.data?.error || 'Đăng ký thất bại';
      dispatch({ type: 'SET_ERROR', payload: errorMessage });
      throw new Error(errorMessage);
    }
  };

  const logout = async () => {
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        await axios.post(`${API_BASE_URL}/auth/logout`, {
          refresh_token: refreshToken,
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear local storage regardless of API call success
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      dispatch({ type: 'LOGOUT' });
    }
  };

  const verifyMFA = async (code: string) => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true });

      const response = await axios.post(`${API_BASE_URL}/auth/verify-mfa`, {
        mfa_code: code,
      });

      const { access_token, refresh_token, user } = response.data;

      // Store tokens
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('refresh_token', refresh_token);

      dispatch({
        type: 'LOGIN_SUCCESS',
        payload: {
          user,
          token: access_token,
          refreshToken: refresh_token,
        },
      });
    } catch (error: any) {
      const errorMessage = error.response?.data?.error || 'Mã MFA không hợp lệ';
      dispatch({ type: 'LOGIN_FAILURE', payload: errorMessage });
      throw new Error(errorMessage);
    }
  };

  const updateProfile = async (data: Partial<User>) => {
    try {
      const response = await axios.put(`${API_BASE_URL}/auth/profile`, data);
      dispatch({ type: 'UPDATE_USER', payload: response.data });
    } catch (error: any) {
      const errorMessage = error.response?.data?.error || 'Cập nhật thông tin thất bại';
      throw new Error(errorMessage);
    }
  };

  const refreshAccessToken = async (): Promise<boolean> => {
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) {
        return false;
      }

      const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
        refresh_token: refreshToken,
      });

      const { access_token, refresh_token: newRefreshToken } = response.data;
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('refresh_token', newRefreshToken);

      return true;
    } catch (error) {
      return false;
    }
  };

  return (
    <AuthContext.Provider
      value={{
        state,
        login,
        register,
        logout,
        verifyMFA,
        updateProfile,
        refreshAccessToken,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

// Hook to use auth context
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
