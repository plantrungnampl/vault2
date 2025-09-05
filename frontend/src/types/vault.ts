export type VaultItemType = 'login' | 'card' | 'identity' | 'secure_note';

export interface LoginData {
  username?: string;
  password?: string;
  url?: string;
  totp?: string;
}

export interface CardData {
  cardholderName?: string;
  cardNumber?: string;
  expiryDate?: string;
  cvv?: string;
  pin?: string;
}

export interface IdentityData {
  firstName?: string;
  lastName?: string;
  email?: string;
  phone?: string;
  address?: string;
  ssn?: string;
  passportNumber?: string;
}

export interface SecureNoteData {
  content?: string;
}

export interface VaultItem {
  id: string;
  name: string;
  type: VaultItemType;
  data: LoginData | CardData | IdentityData | SecureNoteData;
  notes?: string;
  folder?: string;
  tags?: string[];
  favorite: boolean;
  reprompt: boolean;
  createdAt: string;
  updatedAt: string;
  userId: string;
}

export interface VaultFolder {
  id: string;
  name: string;
  color?: string;
  icon?: string;
  itemCount: number;
  createdAt: string;
  updatedAt: string;
  userId: string;
}

export interface VaultStats {
  totalItems: number;
  loginItems: number;
  cardItems: number;
  identityItems: number;
  noteItems: number;
  weakPasswords: number;
  duplicatePasswords: number;
  compromisedPasswords: number;
  totalFolders: number;
}

export interface ShareRequest {
  id: string;
  itemId: string;
  fromUserId: string;
  toEmail: string;
  message?: string;
  permissions: {
    canView: boolean;
    canEdit: boolean;
    canShare: boolean;
  };
  expiresAt?: string;
  status: 'pending' | 'accepted' | 'rejected' | 'expired';
  createdAt: string;
  updatedAt: string;
}

export interface VaultSearchFilters {
  query?: string;
  type?: VaultItemType;
  folder?: string;
  tags?: string[];
  favorite?: boolean;
  compromised?: boolean;
  weakPassword?: boolean;
  duplicatePassword?: boolean;
}

export interface VaultSortOptions {
  field: 'name' | 'type' | 'createdAt' | 'updatedAt' | 'folder';
  direction: 'asc' | 'desc';
}

export interface CreateVaultItemRequest {
  name: string;
  type: VaultItemType;
  data: LoginData | CardData | IdentityData | SecureNoteData;
  notes?: string;
  folder?: string;
  tags?: string[];
  favorite?: boolean;
  reprompt?: boolean;
}

export interface UpdateVaultItemRequest extends Partial<CreateVaultItemRequest> {
  id: string;
}

export interface VaultExportData {
  items: VaultItem[];
  folders: VaultFolder[];
  exportedAt: string;
  version: string;
}

export interface PasswordGeneratorOptions {
  length: number;
  includeUppercase: boolean;
  includeLowercase: boolean;
  includeNumbers: boolean;
  includeSymbols: boolean;
  excludeSimilar: boolean;
  excludeAmbiguous: boolean;
}

export interface PasswordStrength {
  score: number; // 0-4
  feedback: string[];
  warning: string;
  suggestions: string[];
}

export interface SecurityReport {
  weakPasswords: VaultItem[];
  duplicatePasswords: VaultItem[];
  compromisedPasswords: VaultItem[];
  oldPasswords: VaultItem[];
  score: number;
  lastUpdated: string;
}
