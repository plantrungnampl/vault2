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

export interface VaultItem {
  id: string;
  user_id: string;
  name: string;
  type: 'password' | 'secure_note' | 'credit_card' | 'identity' | 'crypto_key' | 'file';
  data: any; // Encrypted data
  notes: string;
  folder_id?: string;
  tags: string[];
  favorite: boolean;
  reprompt: boolean;
  shared_with: string[];
  permissions: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface VaultFolder {
  id: string;
  user_id: string;
  name: string;
  color: string;
  icon: string;
  parent_id?: string;
  item_count: number;
  created_at: string;
  updated_at: string;
}

export interface CreateVaultItemRequest {
  name: string;
  type: VaultItem['type'];
  data: any;
  notes?: string;
  folder_id?: string;
  tags?: string[];
  favorite?: boolean;
  reprompt?: boolean;
}

export interface UpdateVaultItemRequest {
  name?: string;
  type?: VaultItem['type'];
  data?: any;
  notes?: string;
  folder_id?: string;
  tags?: string[];
  favorite?: boolean;
  reprompt?: boolean;
}

export interface CreateFolderRequest {
  name: string;
  color?: string;
  icon?: string;
  parent_id?: string;
}

export interface VaultStats {
  total_items: number;
  total_folders: number;
  favorite_items: number;
  recent_items: number;
  type_stats: Record<string, number>;
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
        const token = localStorage.getItem('access_token');
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
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
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
  async login(email: string, password: string, mfaCode?: string): Promise<{
    user: User;
    access_token: string;
    refresh_token: string;
    expires_in: number;
    mfa_required?: boolean;
    mfa_methods?: string[];
  }> {
    try {
      const response = await this.client.post('/auth/login', {
        email,
        password,
        mfa_code: mfaCode,
      });
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async verifyMFA(code: string): Promise<{
    user: User;
    access_token: string;
    refresh_token: string;
    expires_in: number;
  }> {
    try {
      const response = await this.client.post('/auth/verify-mfa', {
        mfa_code: code,
      });
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async register(userData: {
    email: string;
    password: string;
    first_name: string;
    last_name: string;
  }): Promise<{
    user: User;
    access_token: string;
    refresh_token: string;
    expires_in: number;
  }> {
    try {
      const response = await this.client.post('/auth/register', userData);
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
      console.warn('Logout failed:', error);
    } finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    }
  }

  async getProfile(): Promise<User> {
    try {
      const response = await this.client.get('/auth/profile');
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async updateProfile(userData: Partial<User>): Promise<User> {
    try {
      const response = await this.client.put('/auth/profile', userData);
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    try {
      await this.client.post('/auth/change-password', {
        current_password: currentPassword,
        new_password: newPassword,
      });
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Vault Items
  async getVaultItems(params: {
    page?: number;
    limit?: number;
    type?: string;
    folder_id?: string;
    search?: string;
  } = {}): Promise<PaginationResponse<VaultItem>> {
    try {
      const response = await this.client.get('/vault/items', { params });
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getVaultItem(id: string): Promise<VaultItem> {
    try {
      const response = await this.client.get(`/vault/items/${id}`);
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async createVaultItem(itemData: CreateVaultItemRequest): Promise<VaultItem> {
    try {
      const response = await this.client.post('/vault/items', itemData);
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async updateVaultItem(id: string, itemData: UpdateVaultItemRequest): Promise<VaultItem> {
    try {
      const response = await this.client.put(`/vault/items/${id}`, itemData);
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async deleteVaultItem(id: string): Promise<void> {
    try {
      await this.client.delete(`/vault/items/${id}`);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async toggleFavorite(id: string): Promise<void> {
    try {
      await this.client.post(`/vault/items/${id}/favorite`);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Vault Folders
  async getVaultFolders(): Promise<VaultFolder[]> {
    try {
      const response = await this.client.get('/vault/folders');
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async createVaultFolder(folderData: CreateFolderRequest): Promise<VaultFolder> {
    try {
      const response = await this.client.post('/vault/folders', folderData);
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async updateVaultFolder(id: string, folderData: Partial<CreateFolderRequest>): Promise<VaultFolder> {
    try {
      const response = await this.client.put(`/vault/folders/${id}`, folderData);
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async deleteVaultFolder(id: string): Promise<void> {
    try {
      await this.client.delete(`/vault/folders/${id}`);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Vault Stats
  async getVaultStats(): Promise<VaultStats> {
    try {
      const response = await this.client.get('/vault/stats');
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Recent Items
  async getRecentItems(limit: number = 10): Promise<VaultItem[]> {
    try {
      const response = await this.client.get('/vault/recent', {
        params: { limit },
      });
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Search
  async searchVaultItems(query: string, filters?: {
    type?: string;
    tags?: string;
  }): Promise<VaultItem[]> {
    try {
      const response = await this.client.get('/search/items', {
        params: { q: query, ...filters },
      });
      return this.handleResponse(response);
    } catch (error) {
      throw this.handleError(error);
    }
  }
}

// Create singleton instance
export const apiClient = new ApiClient();
export default apiClient;

// Explicit re-exports for better compatibility
export type {
  User,
  VaultItem,
  VaultFolder,
  CreateVaultItemRequest,
  UpdateVaultItemRequest,
  CreateFolderRequest,
  VaultStats,
  PaginationResponse
};