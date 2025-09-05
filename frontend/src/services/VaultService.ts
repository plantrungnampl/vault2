import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080/api/v1';

export interface VaultItem {
  id: string;
  user_id: string;
  folder_id?: string;
  type: 'password' | 'secure_note' | 'credit_card' | 'identity' | 'crypto_key' | 'file';
  name: string;
  data: EncryptedData;
  tags?: string[];
  favorite: boolean;
  shared_with?: ShareInfo[];
  last_used?: string;
  expires_at?: string;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface EncryptedData {
  data: string;
  nonce: string;
  algorithm: string;
  key_id: string;
  timestamp: string;
}

export interface ShareInfo {
  user_id: string;
  email: string;
  permissions: {
    read: boolean;
    write: boolean;
    delete: boolean;
    share: boolean;
  };
  shared_at: string;
  expires_at?: string;
}

export interface Folder {
  id: string;
  user_id: string;
  parent_id?: string;
  name: string;
  color: string;
  icon: string;
  shared_with?: ShareInfo[];
  created_at: string;
  updated_at: string;
}

export interface VaultItemData {
  // Password data
  url?: string;
  username?: string;
  password?: string;
  notes?: string;
  
  // Secure note data
  content?: string;
  
  // Credit card data
  cardholderName?: string;
  cardNumber?: string;
  expiryMonth?: string;
  expiryYear?: string;
  cvv?: string;
  
  // Identity data
  title?: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  phone?: string;
  address?: string;
  
  // Crypto key data
  privateKey?: string;
  publicKey?: string;
  keyType?: string;
  
  // File data
  fileName?: string;
  fileSize?: number;
  fileType?: string;
  fileContent?: string;
}

export class VaultService {
  private apiClient = axios.create({
    baseURL: API_BASE_URL,
  });

  constructor() {
    // Add auth header interceptor
    this.apiClient.interceptors.request.use((config) => {
      const token = localStorage.getItem('access_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });
  }

  // Get all vault items
  async getItems(folderId?: string): Promise<VaultItem[]> {
    try {
      const params = folderId ? { folder_id: folderId } : {};
      const response = await this.apiClient.get('/vault/items', { params });
      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể tải danh sách vault');
    }
  }

  // Get a specific vault item
  async getItem(id: string): Promise<VaultItem> {
    try {
      const response = await this.apiClient.get(`/vault/items/${id}`);
      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể tải mục vault');
    }
  }

  // Create a new vault item
  async createItem(itemData: Partial<VaultItem>): Promise<VaultItem> {
    try {
      const response = await this.apiClient.post('/vault/items', itemData);
      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể tạo mục vault');
    }
  }

  // Update a vault item
  async updateItem(id: string, updates: Partial<VaultItem>): Promise<VaultItem> {
    try {
      const response = await this.apiClient.put(`/vault/items/${id}`, updates);
      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể cập nhật mục vault');
    }
  }

  // Delete a vault item
  async deleteItem(id: string): Promise<void> {
    try {
      await this.apiClient.delete(`/vault/items/${id}`);
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể xóa mục vault');
    }
  }

  // Search vault items
  async searchItems(query: string): Promise<VaultItem[]> {
    try {
      const response = await this.apiClient.get('/search', {
        params: { q: query }
      });
      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể tìm kiếm vault');
    }
  }

  // Share a vault item
  async shareItem(id: string, shareData: {
    email: string;
    permissions: {
      read: boolean;
      write: boolean;
      delete: boolean;
      share: boolean;
    };
    expires_at?: string;
  }): Promise<void> {
    try {
      await this.apiClient.post(`/vault/items/${id}/share`, shareData);
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể chia sẻ mục vault');
    }
  }

  // Get shared items
  async getSharedItems(): Promise<VaultItem[]> {
    try {
      const response = await this.apiClient.get('/vault/shared');
      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể tải mục chia sẻ');
    }
  }

  // Folder operations
  async getFolders(): Promise<Folder[]> {
    try {
      const response = await this.apiClient.get('/vault/folders');
      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể tải danh sách thư mục');
    }
  }

  async createFolder(folderData: {
    name: string;
    parent_id?: string;
    color?: string;
    icon?: string;
  }): Promise<Folder> {
    try {
      const response = await this.apiClient.post('/vault/folders', folderData);
      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể tạo thư mục');
    }
  }

  async updateFolder(id: string, updates: Partial<Folder>): Promise<Folder> {
    try {
      const response = await this.apiClient.put(`/vault/folders/${id}`, updates);
      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể cập nhật thư mục');
    }
  }

  async deleteFolder(id: string): Promise<void> {
    try {
      await this.apiClient.delete(`/vault/folders/${id}`);
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể xóa thư mục');
    }
  }

  // Encryption helpers (client-side encryption)
  async encryptData(data: VaultItemData, masterKey: string): Promise<EncryptedData> {
    // This would implement client-side encryption using Web Crypto API
    // For now, return mock encrypted data
    const jsonData = JSON.stringify(data);
    const timestamp = new Date().toISOString();
    
    return {
      data: btoa(jsonData), // Base64 encode for demo
      nonce: this.generateNonce(),
      algorithm: 'AES-256-GCM',
      key_id: 'user_master_key',
      timestamp,
    };
  }

  async decryptData(encryptedData: EncryptedData, masterKey: string): Promise<VaultItemData> {
    // This would implement client-side decryption
    // For now, return mock decrypted data
    try {
      const jsonData = atob(encryptedData.data); // Base64 decode for demo
      return JSON.parse(jsonData);
    } catch (error) {
      throw new Error('Không thể giải mã dữ liệu');
    }
  }

  private generateNonce(): string {
    const array = new Uint8Array(12);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  // Password generation
  generatePassword(options: {
    length?: number;
    includeUppercase?: boolean;
    includeLowercase?: boolean;
    includeNumbers?: boolean;
    includeSymbols?: boolean;
    excludeSimilar?: boolean;
  } = {}): string {
    const {
      length = 16,
      includeUppercase = true,
      includeLowercase = true,
      includeNumbers = true,
      includeSymbols = true,
      excludeSimilar = false,
    } = options;

    let charset = '';
    
    if (includeUppercase) {
      charset += excludeSimilar ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    }
    
    if (includeLowercase) {
      charset += excludeSimilar ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
    }
    
    if (includeNumbers) {
      charset += excludeSimilar ? '23456789' : '0123456789';
    }
    
    if (includeSymbols) {
      charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    }

    let password = '';
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);

    for (let i = 0; i < length; i++) {
      password += charset[array[i] % charset.length];
    }

    return password;
  }

  // Password strength checker
  checkPasswordStrength(password: string): {
    score: number;
    feedback: string[];
    isStrong: boolean;
  } {
    let score = 0;
    const feedback: string[] = [];

    // Length check
    if (password.length >= 8) score += 1;
    else feedback.push('Mật khẩu nên có ít nhất 8 ký tự');

    if (password.length >= 14) score += 1;
    else if (password.length >= 8) feedback.push('Mật khẩu mạnh hơn với ít nhất 14 ký tự');

    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Thêm chữ thường');

    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Thêm chữ hoa');

    if (/[0-9]/.test(password)) score += 1;
    else feedback.push('Thêm số');

    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    else feedback.push('Thêm ký tự đặc biệt');

    // Common patterns
    if (!/(.)\1{2,}/.test(password)) score += 1;
    else feedback.push('Tránh lặp lại ký tự');

    const isStrong = score >= 5;
    
    return {
      score: Math.min(score, 5),
      feedback,
      isStrong,
    };
  }
}
