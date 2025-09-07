import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';

// API Response types
export interface ApiResponse<T = any> {
  data: T;
  message?: string;
  success: boolean;
}

export interface PaginatedResponse<T = any> extends ApiResponse<T[]> {
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export interface ApiError {
  error: string;
  code?: string;
  details?: any;
}

// Request types
export interface LoginRequest {
  email: string;
  password: string;
  mfa_code?: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

export interface RefreshTokenRequest {
  refresh_token: string;
}

// API Client Class
class ApiClient {
  private client: AxiosInstance;
  private baseURL: string;

  constructor() {
    this.baseURL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080/api/v1';
    
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        // Add auth token
        const token = localStorage.getItem('access_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }

        // Add request timestamp
        config.headers['X-Request-Time'] = new Date().toISOString();

        // Log request in development
        if (import.meta.env.DEV) {
          console.log(`=€ API Request: ${config.method?.toUpperCase()} ${config.url}`, {
            data: config.data,
            params: config.params,
          });
        }

        return config;
      },
      (error) => {
        console.error('Request interceptor error:', error);
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response: AxiosResponse) => {
        // Log response in development
        if (import.meta.env.DEV) {
          console.log(` API Response: ${response.config.method?.toUpperCase()} ${response.config.url}`, {
            status: response.status,
            data: response.data,
          });
        }

        return response;
      },
      async (error) => {
        const originalRequest = error.config;

        // Handle 401 errors with token refresh
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;

          const refreshToken = localStorage.getItem('refresh_token');
          if (refreshToken) {
            try {
              const response = await axios.post(`${this.baseURL}/auth/refresh`, {
                refresh_token: refreshToken,
              });

              const { access_token, refresh_token: newRefreshToken } = response.data;
              
              // Update stored tokens
              localStorage.setItem('access_token', access_token);
              localStorage.setItem('refresh_token', newRefreshToken);

              // Retry original request with new token
              originalRequest.headers.Authorization = `Bearer ${access_token}`;
              return this.client(originalRequest);
            } catch (refreshError) {
              // Refresh failed, redirect to login
              localStorage.removeItem('access_token');
              localStorage.removeItem('refresh_token');
              window.location.href = '/login';
              return Promise.reject(refreshError);
            }
          } else {
            // No refresh token, redirect to login
            window.location.href = '/login';
          }
        }

        // Log error in development
        if (import.meta.env.DEV) {
          console.error(`L API Error: ${originalRequest.method?.toUpperCase()} ${originalRequest.url}`, {
            status: error.response?.status,
            data: error.response?.data,
            message: error.message,
          });
        }

        return Promise.reject(error);
      }
    );
  }

  // Generic request methods
  async get<T = any>(url: string, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    const response = await this.client.get<ApiResponse<T>>(url, config);
    return response.data;
  }

  async post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    const response = await this.client.post<ApiResponse<T>>(url, data, config);
    return response.data;
  }

  async put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    const response = await this.client.put<ApiResponse<T>>(url, data, config);
    return response.data;
  }

  async patch<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    const response = await this.client.patch<ApiResponse<T>>(url, data, config);
    return response.data;
  }

  async delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    const response = await this.client.delete<ApiResponse<T>>(url, config);
    return response.data;
  }

  // Authentication endpoints
  async login(data: LoginRequest) {
    return this.post('/auth/login', data);
  }

  async register(data: RegisterRequest) {
    return this.post('/auth/register', data);
  }

  async logout() {
    const refreshToken = localStorage.getItem('refresh_token');
    return this.post('/auth/logout', { refresh_token: refreshToken });
  }

  async refreshToken(data: RefreshTokenRequest) {
    return this.post('/auth/refresh', data);
  }

  async getProfile() {
    return this.get('/auth/profile');
  }

  async updateProfile(data: any) {
    return this.put('/auth/profile', data);
  }

  async changePassword(data: { currentPassword: string; newPassword: string }) {
    return this.post('/auth/change-password', data);
  }

  async verifyMFA(code: string) {
    return this.post('/auth/verify-mfa', { mfa_code: code });
  }

  // Vault endpoints
  async getVaultItems(params?: any) {
    return this.get('/vault/items', { params });
  }

  async createVaultItem(data: any) {
    return this.post('/vault/items', data);
  }

  async getVaultItem(id: string) {
    return this.get(`/vault/items/${id}`);
  }

  async updateVaultItem(id: string, data: any) {
    return this.put(`/vault/items/${id}`, data);
  }

  async deleteVaultItem(id: string) {
    return this.delete(`/vault/items/${id}`);
  }

  async toggleFavorite(id: string) {
    return this.post(`/vault/items/${id}/favorite`);
  }

  async getVaultFolders() {
    return this.get('/vault/folders');
  }

  async createVaultFolder(data: any) {
    return this.post('/vault/folders', data);
  }

  async updateVaultFolder(id: string, data: any) {
    return this.put(`/vault/folders/${id}`, data);
  }

  async deleteVaultFolder(id: string) {
    return this.delete(`/vault/folders/${id}`);
  }

  async getVaultStats() {
    return this.get('/vault/stats');
  }

  async getRecentItems() {
    return this.get('/vault/recent');
  }

  async searchVaultItems(query: string, filters?: any) {
    return this.get('/search/items', { params: { q: query, ...filters } });
  }

  // Admin endpoints
  async getUsers(params?: any) {
    return this.get('/admin/users', { params });
  }

  async createUser(data: any) {
    return this.post('/admin/users', data);
  }

  async getUser(id: string) {
    return this.get(`/admin/users/${id}`);
  }

  async updateUser(id: string, data: any) {
    return this.put(`/admin/users/${id}`, data);
  }

  async deleteUser(id: string) {
    return this.delete(`/admin/users/${id}`);
  }

  async suspendUser(id: string) {
    return this.post(`/admin/users/${id}/suspend`);
  }

  async activateUser(id: string) {
    return this.post(`/admin/users/${id}/activate`);
  }

  async resetUserPassword(id: string) {
    return this.post(`/admin/users/${id}/reset-password`);
  }

  // System endpoints
  async getSystemHealth() {
    return this.get('/admin/system/health');
  }

  async getSystemMetrics() {
    return this.get('/admin/system/metrics');
  }

  async getSystemConfig() {
    return this.get('/admin/system/config');
  }

  async updateSystemConfig(data: any) {
    return this.put('/admin/system/config', data);
  }

  // Security endpoints
  async getSecurityPolicies() {
    return this.get('/admin/security/policies');
  }

  async updateSecurityPolicies(data: any) {
    return this.put('/admin/security/policies', data);
  }

  async getSecurityIncidents(params?: any) {
    return this.get('/admin/security/incidents', { params });
  }

  async resolveSecurityIncident(id: string) {
    return this.post(`/admin/security/incidents/${id}/resolve`);
  }

  // Audit endpoints
  async getAuditLogs(params?: any) {
    return this.get('/admin/audit/logs', { params });
  }

  async generateComplianceReport(data: any) {
    return this.post('/admin/audit/reports', data);
  }

  async exportAuditLogs(data: any) {
    return this.post('/admin/audit/export', data);
  }

  // Health check
  async healthCheck() {
    return this.get('/health');
  }

  async readinessCheck() {
    return this.get('/ready');
  }

  // File upload
  async uploadFile(file: File, onUploadProgress?: (progress: number) => void) {
    const formData = new FormData();
    formData.append('file', file);

    return this.post('/files/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (progressEvent.total && onUploadProgress) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onUploadProgress(progress);
        }
      },
    });
  }

  // Download file
  async downloadFile(url: string, filename?: string) {
    const response = await this.client.get(url, {
      responseType: 'blob',
    });

    // Create download link
    const blob = new Blob([response.data]);
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename || 'download';
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(downloadUrl);
  }

  // Update base URL
  setBaseURL(url: string) {
    this.baseURL = url;
    this.client.defaults.baseURL = url;
  }

  // Set auth token
  setAuthToken(token: string) {
    this.client.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }

  // Remove auth token
  removeAuthToken() {
    delete this.client.defaults.headers.common['Authorization'];
  }

  // Get base URL
  getBaseURL(): string {
    return this.baseURL;
  }
}

// Create singleton instance
const apiClient = new ApiClient();

export default apiClient;

// Export for custom usage
export { ApiClient };