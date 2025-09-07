import axios from 'axios';
import CryptoService from './CryptoService';
import type { EncryptionResult, DecryptionParams, VaultItemKeys } from './CryptoService';

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
  encryptedData: string;
  iv: string;
  salt: string;
  authTag: string;
  algorithm: string;
  keyId: string;
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
  private cryptoService = CryptoService.getInstance();
  private itemKeysCache = new Map<string, VaultItemKeys>();

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

  /**
   * Initialize the vault service with user's master password
   * This sets up zero-knowledge encryption for the session
   */
  async initializeEncryption(masterPassword: string, userSalt?: string): Promise<void> {
    try {
      const salt = userSalt ? this.base64ToArrayBuffer(userSalt) : undefined;
      await this.cryptoService.initializeMasterKey(masterPassword, salt ? new Uint8Array(salt) : undefined);
    } catch (error) {
      console.error('Failed to initialize encryption:', error);
      throw new Error('Không thể khởi tạo mã hóa. Vui lòng kiểm tra mật khẩu.');
    }
  }

  // Get all vault items (with automatic decryption)
  async getItems(folderId?: string): Promise<VaultItem[]> {
    try {
      const params = folderId ? { folder_id: folderId } : {};
      const response = await this.apiClient.get('/vault/items', { params });
      const encryptedItems: VaultItem[] = response.data;
      
      // Decrypt each item's data
      const decryptedItems = await Promise.all(
        encryptedItems.map(async (item) => {
          try {
            const decryptedData = await this.decryptVaultItemData(item.data);
            return {
              ...item,
              data: decryptedData
            };
          } catch (error) {
            console.warn(`Failed to decrypt item ${item.id}:`, error);
            // Return item with encrypted data if decryption fails
            return item;
          }
        })
      );
      
      return decryptedItems;
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể tải danh sách vault');
    }
  }

  // Get a specific vault item (with automatic decryption)
  async getItem(id: string): Promise<VaultItem> {
    try {
      const response = await this.apiClient.get(`/vault/items/${id}`);
      const encryptedItem: VaultItem = response.data;
      
      // Decrypt the item's data
      try {
        const decryptedData = await this.decryptVaultItemData(encryptedItem.data);
        return {
          ...encryptedItem,
          data: decryptedData
        };
      } catch (error) {
        console.warn(`Failed to decrypt item ${id}:`, error);
        return encryptedItem;
      }
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể tải mục vault');
    }
  }

  // Create a new vault item (with automatic encryption)
  async createItem(itemData: Partial<VaultItem> & { plainData: VaultItemData }): Promise<VaultItem> {
    try {
      // Encrypt the plain data before sending
      const encryptedData = await this.encryptVaultItemData(itemData.plainData);
      
      const payload = {
        ...itemData,
        data: encryptedData
      };
      delete payload.plainData;
      
      const response = await this.apiClient.post('/vault/items', payload);
      const createdItem: VaultItem = response.data;
      
      // Return with decrypted data for immediate use
      return {
        ...createdItem,
        data: itemData.plainData
      };
    } catch (error: any) {
      throw new Error(error.response?.data?.error || 'Không thể tạo mục vault');
    }
  }

  // Update a vault item (with automatic encryption)
  async updateItem(id: string, updates: Partial<VaultItem> & { plainData?: VaultItemData }): Promise<VaultItem> {
    try {
      let payload = { ...updates };
      
      // If plainData is provided, encrypt it
      if (updates.plainData) {
        const encryptedData = await this.encryptVaultItemData(updates.plainData);
        payload.data = encryptedData;
        delete payload.plainData;
      }
      
      const response = await this.apiClient.put(`/vault/items/${id}`, payload);
      const updatedItem: VaultItem = response.data;
      
      // Return with decrypted data if we have it
      if (updates.plainData) {
        return {
          ...updatedItem,
          data: updates.plainData
        };
      } else {
        // Decrypt the returned data
        try {
          const decryptedData = await this.decryptVaultItemData(updatedItem.data);
          return {
            ...updatedItem,
            data: decryptedData
          };
        } catch (error) {
          console.warn(`Failed to decrypt updated item ${id}:`, error);
          return updatedItem;
        }
      }
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

  // Zero-knowledge encryption methods
  private async encryptVaultItemData(data: VaultItemData): Promise<EncryptedData> {
    try {
      const encryptionResult = await this.cryptoService.encryptVaultItem(data);
      return {
        encryptedData: encryptionResult.encryptedData,
        iv: encryptionResult.iv,
        salt: encryptionResult.salt,
        authTag: encryptionResult.authTag,
        algorithm: encryptionResult.algorithm,
        keyId: encryptionResult.keyId,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Encryption failed:', error);
      throw new Error('Không thể mã hóa dữ liệu');
    }
  }

  private async decryptVaultItemData(encryptedData: EncryptedData): Promise<VaultItemData> {
    try {
      const decryptionParams: DecryptionParams = {
        encryptedData: encryptedData.encryptedData,
        iv: encryptedData.iv,
        salt: encryptedData.salt,
        authTag: encryptedData.authTag,
        algorithm: encryptedData.algorithm,
        keyId: encryptedData.keyId
      };
      
      return await this.cryptoService.decryptVaultItem(decryptionParams);
    } catch (error) {
      console.error('Decryption failed:', error);
      throw new Error('Không thể giải mã dữ liệu');
    }
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

  // Advanced password strength checker using crypto service
  async checkPasswordStrength(password: string): Promise<{
    score: number;
    feedback: string[];
    entropy: number;
    estimatedTime: string;
    isStrong: boolean;
  }> {
    try {
      const analysis = await this.cryptoService.analyzePasswordStrength(password);
      return {
        ...analysis,
        isStrong: analysis.score >= 75 // 75% or higher is considered strong
      };
    } catch (error) {
      console.error('Password strength analysis failed:', error);
      // Fallback to basic analysis
      return this.basicPasswordStrengthCheck(password);
    }
  }

  private basicPasswordStrengthCheck(password: string): {
    score: number;
    feedback: string[];
    entropy: number;
    estimatedTime: string;
    isStrong: boolean;
  } {
    let score = 0;
    const feedback: string[] = [];

    // Length check
    if (password.length >= 12) score += 20;
    else feedback.push('Sử dụng ít nhất 12 ký tự');

    if (password.length >= 16) score += 10;

    // Character variety
    if (/[a-z]/.test(password)) score += 15;
    else feedback.push('Thêm chữ thường');

    if (/[A-Z]/.test(password)) score += 15;
    else feedback.push('Thêm chữ hoa');

    if (/[0-9]/.test(password)) score += 15;
    else feedback.push('Thêm số');

    if (/[^A-Za-z0-9]/.test(password)) score += 15;
    else feedback.push('Thêm ký tự đặc biệt');

    // Pattern checks
    if (!/(.)\1{2,}/.test(password)) score += 10;
    else feedback.push('Tránh lặp lại ký tự');

    const entropy = this.calculateBasicEntropy(password);
    const isStrong = score >= 75;
    
    return {
      score: Math.min(score, 100),
      feedback,
      entropy,
      estimatedTime: this.estimateCrackTime(entropy),
      isStrong,
    };
  }

  private calculateBasicEntropy(password: string): number {
    const charSets = [
      { regex: /[a-z]/g, size: 26 },
      { regex: /[A-Z]/g, size: 26 },
      { regex: /[0-9]/g, size: 10 },
      { regex: /[^a-zA-Z0-9]/g, size: 32 }
    ];

    let charsetSize = 0;
    charSets.forEach(set => {
      if (set.regex.test(password)) {
        charsetSize += set.size;
      }
    });

    return password.length * Math.log2(charsetSize || 1);
  }

  private estimateCrackTime(entropy: number): string {
    const guessesPerSecond = 1000000000; // 1 billion
    const seconds = Math.pow(2, entropy - 1) / guessesPerSecond;
    
    if (seconds < 60) return 'Dưới 1 phút';
    if (seconds < 3600) return `${Math.round(seconds / 60)} phút`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} giờ`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} ngày`;
    return `${Math.round(seconds / 31536000)} năm`;
  }

  /**
   * Clear encryption keys and secure memory when logging out
   */
  async clearEncryption(): Promise<void> {
    try {
      await this.cryptoService.clearSecureMemory();
      this.itemKeysCache.clear();
    } catch (error) {
      console.error('Failed to clear encryption:', error);
    }
  }

  /**
   * Setup biometric authentication
   */
  async setupBiometricAuth(masterPassword: string): Promise<void> {
    try {
      const biometricData = await this.cryptoService.setupBiometricEncryption(masterPassword);
      // Store biometric data securely (in production, this would be more sophisticated)
      localStorage.setItem('biometric_auth', JSON.stringify(biometricData));
    } catch (error) {
      console.error('Failed to setup biometric auth:', error);
      throw new Error('Không thể thiết lập xác thực sinh trắc học');
    }
  }

  /**
   * Check if key rotation is needed
   */
  async checkKeyRotation(): Promise<boolean> {
    try {
      // This would check against stored rotation schedule
      // For now, simulate based on localStorage timestamp
      const lastRotation = localStorage.getItem('last_key_rotation');
      if (!lastRotation) return true;
      
      const rotationDate = new Date(lastRotation);
      const now = new Date();
      const daysSinceRotation = (now.getTime() - rotationDate.getTime()) / (1000 * 60 * 60 * 24);
      
      return daysSinceRotation >= 90; // 90 days
    } catch (error) {
      console.error('Key rotation check failed:', error);
      return false;
    }
  }

  /**
   * Perform key rotation
   */
  async rotateKeys(): Promise<void> {
    try {
      const rotationInfo = await this.cryptoService.rotateKeys();
      localStorage.setItem('last_key_rotation', new Date().toISOString());
      localStorage.setItem('key_rotation_info', JSON.stringify(rotationInfo));
    } catch (error) {
      console.error('Key rotation failed:', error);
      throw new Error('Không thể xoay vòng khóa bảo mật');
    }
  }

  // Helper methods
  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
