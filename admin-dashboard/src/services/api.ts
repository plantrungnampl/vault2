import axios from 'axios';
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080/api/v1';

export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: 'basic_user' | 'premium_user' | 'team_member' | 'vault_admin' | 'security_admin' | 'super_admin';
  status: 'active' | 'pending' | 'suspended' | 'deactive';
  mfa_enabled: boolean;
  email_verified: boolean;
  last_login_at: string | null;
  last_login_ip: string | null;
  created_at: string;
  updated_at: string;
  preferences?: {
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
}

export interface CreateUserRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  role: User['role'];
  status?: User['status'];
}

export interface UpdateUserRequest {
  email?: string;
  firstName?: string;
  lastName?: string;
  role?: User['role'];
  status?: User['status'];
}

export interface PaginationResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export interface DashboardStats {
  totalUsers: number;
  activeUsers: number;
  totalVaultItems: number;
  securityIncidents: number;
  systemUptime: string;
  storageUsed: string;
  mfaEnabledUsers: number;
  newUsersThisMonth: number;
}

export interface SecurityIncident {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  user_id?: string;
  ip_address: string;
  details: any;
  resolved: boolean;
  resolved_by?: string;
  resolved_at?: string;
  timestamp: string;
}

export interface AuditLog {
  id: string;
  user_id: string;
  action: string;
  resource: string;
  resource_id?: string;
  ip_address: string;
  user_agent: string;
  success: boolean;
  error_code?: string;
  details?: any;
  timestamp: string;
  user?: {
    email: string;
    first_name: string;
    last_name: string;
  };
}

export interface SystemHealth {
  database: {
    connected: boolean;
    latency: number;
  };
  redis: {
    connected: boolean;
    latency: number;
  };
  services: {
    auth: boolean;
    vault: boolean;
    audit: boolean;
  };
}

class ApiClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add request interceptor to include auth token
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('admin_access_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Add response interceptor to handle errors
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          // Token expired or invalid
          localStorage.removeItem('admin_access_token');
          localStorage.removeItem('admin_refresh_token');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  private handleResponse<T>(response: AxiosResponse<T>): T {
    return response.data;
  }

  private handleError(error: any): never {
    console.error('API Error:', error);
    throw error.response?.data?.error || error.message || 'An unexpected error occurred';
  }

  // Authentication
  async login(email: string, password: string): Promise<{
    user: User;
    access_token: string;
    refresh_token: string;
    expires_in: number;
  }> {
    try {
      const response = await this.client.post('/auth/login', {
        email,
        password,
      });
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async refreshToken(refreshToken: string): Promise<{
    access_token: string;
    refresh_token: string;
    expires_in: number;
  }> {
    try {
      const response = await this.client.post('/auth/refresh', {
        refresh_token: refreshToken,
      });
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async logout(): Promise<void> {
    try {
      await this.client.post('/auth/logout');
    } catch (error) {
      // Don't throw error on logout, just clear local storage
      console.warn('Logout failed:', error);
    } finally {
      localStorage.removeItem('admin_access_token');
      localStorage.removeItem('admin_refresh_token');
    }
  }

  // Admin Users Management
  async getUsers(params: {
    page?: number;
    limit?: number;
    role?: string;
    status?: string;
    search?: string;
  } = {}): Promise<PaginationResponse<User>> {
    try {
      const response = await this.client.get('/admin/users', { params });
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getUser(id: string): Promise<{ data: User }> {
    try {
      const response = await this.client.get(`/admin/users/${id}`);
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async createUser(userData: CreateUserRequest): Promise<{ data: User }> {
    try {
      const response = await this.client.post('/admin/users', userData);
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async updateUser(id: string, userData: UpdateUserRequest): Promise<{ data: User }> {
    try {
      const response = await this.client.put(`/admin/users/${id}`, userData);
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async deleteUser(id: string): Promise<void> {
    try {
      await this.client.delete(`/admin/users/${id}`);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async suspendUser(id: string): Promise<void> {
    try {
      await this.client.post(`/admin/users/${id}/suspend`);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async activateUser(id: string): Promise<void> {
    try {
      await this.client.post(`/admin/users/${id}/activate`);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async resetUserPassword(id: string, newPassword: string): Promise<void> {
    try {
      await this.client.post(`/admin/users/${id}/reset-password`, {
        new_password: newPassword,
      });
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Dashboard Stats
  async getDashboardStats(): Promise<DashboardStats> {
    try {
      // Fetch multiple endpoints in parallel
      const [usersResponse, systemResponse] = await Promise.all([
        this.client.get('/admin/users?limit=1'), // Just to get total count
        this.client.get('/admin/system/health'),
      ]);

      const usersData = this.handleResponse(usersResponse);
      const systemData = this.handleResponse(systemResponse);

      // Mock some additional stats that would come from different endpoints
      return {
        totalUsers: usersData.pagination?.total || 0,
        activeUsers: Math.floor((usersData.pagination?.total || 0) * 0.8), // 80% active assumption
        totalVaultItems: 0, // Would come from vault stats endpoint
        securityIncidents: 0, // Would come from security incidents endpoint
        systemUptime: "99.9%",
        storageUsed: "2.1GB",
        mfaEnabledUsers: 0, // Would come from user stats
        newUsersThisMonth: 0, // Would come from user stats
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // System Health
  async getSystemHealth(): Promise<SystemHealth> {
    try {
      const response = await this.client.get('/admin/system/health');
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Security Management
  async getSecurityIncidents(params: {
    page?: number;
    limit?: number;
    severity?: string;
    resolved?: boolean;
  } = {}): Promise<PaginationResponse<SecurityIncident>> {
    try {
      const response = await this.client.get('/admin/security/incidents', { params });
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async resolveSecurityIncident(id: string, resolution: string): Promise<void> {
    try {
      await this.client.post(`/admin/security/incidents/${id}/resolve`, {
        resolution,
      });
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Audit Logs
  async getAuditLogs(params: {
    page?: number;
    limit?: number;
    user_id?: string;
    action?: string;
    start_date?: string;
    end_date?: string;
  } = {}): Promise<PaginationResponse<AuditLog>> {
    try {
      const response = await this.client.get('/admin/audit/logs', { params });
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async exportAuditLogs(params: {
    start_date: string;
    end_date: string;
    format?: 'csv' | 'json';
  }): Promise<Blob> {
    try {
      const response = await this.client.post('/admin/audit/export', params, {
        responseType: 'blob',
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }
}

// Create singleton instance
export const apiClient = new ApiClient();
export default apiClient;

// Re-export all interfaces for easier importing
export type {
  User,
  CreateUserRequest,
  UpdateUserRequest,
  PaginationResponse,
  DashboardStats,
  SecurityIncident,
  AuditLog,
  SystemHealth
};