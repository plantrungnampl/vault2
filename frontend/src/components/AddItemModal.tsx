import React, { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  XMarkIcon,
  EyeIcon,
  EyeSlashIcon,
  KeyIcon,
  CreditCardIcon,
  IdentificationIcon,
  DocumentTextIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline';
import type { 
  VaultItemType, 
  CreateVaultItemRequest, 
  VaultFolder
} from '../types/vault';
import { VaultService } from '../services/VaultService';

interface AddItemModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: CreateVaultItemRequest) => void;
  folders: VaultFolder[];
  editItem?: any; // For editing existing items
}

const itemTypes = [
  { value: 'login', label: 'Đăng nhập', icon: KeyIcon },
  { value: 'card', label: 'Thẻ tín dụng', icon: CreditCardIcon },
  { value: 'identity', label: 'Danh tính', icon: IdentificationIcon },
  { value: 'secure_note', label: 'Ghi chú bảo mật', icon: DocumentTextIcon },
];

const itemSchema = z.object({
  name: z.string().min(1, 'Tên không được để trống'),
  type: z.enum(['login', 'card', 'identity', 'secure_note']),
  folder: z.string().optional(),
  notes: z.string().optional(),
  favorite: z.boolean().optional().default(false),
  reprompt: z.boolean().optional().default(false),
  // Data fields
  username: z.string().optional(),
  password: z.string().optional(),
  url: z.string().url('URL không hợp lệ').optional().or(z.literal('')),
  cardholderName: z.string().optional(),
  cardNumber: z.string().optional(),
  expiryDate: z.string().optional(),
  cvv: z.string().optional(),
  firstName: z.string().optional(),
  lastName: z.string().optional(),
  email: z.string().email('Email không hợp lệ').optional().or(z.literal('')),
  phone: z.string().optional(),
  address: z.string().optional(),
  content: z.string().optional(),
});

type FormData = z.infer<typeof itemSchema>;

const AddItemModal: React.FC<AddItemModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  folders,
  editItem,
}) => {
  const [selectedType, setSelectedType] = useState<VaultItemType>('login');
  const [showPassword, setShowPassword] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState<any>(null);
  const vaultService = new VaultService();

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<FormData>({
    resolver: zodResolver(itemSchema),
    defaultValues: {
      type: selectedType,
      favorite: false,
      reprompt: false,
    },
  });

  const watchedPassword = watch('password');

  useEffect(() => {
    if (editItem) {
      setSelectedType(editItem.type);
      reset({
        name: editItem.name,
        type: editItem.type,
        folder: editItem.folder,
        notes: editItem.notes,
        favorite: editItem.favorite,
        reprompt: editItem.reprompt,
        // Populate data fields based on type
        ...editItem.data,
      });
    } else {
      reset({
        type: selectedType,
        favorite: false,
        reprompt: false,
      });
    }
  }, [editItem, selectedType, reset]);

  useEffect(() => {
    if (watchedPassword) {
      const strength = vaultService.checkPasswordStrength(watchedPassword);
      setPasswordStrength(strength);
    } else {
      setPasswordStrength(null);
    }
  }, [watchedPassword, vaultService]);

  const handleTypeChange = (type: VaultItemType) => {
    setSelectedType(type);
    setValue('type', type);
  };

  const handleGeneratePassword = () => {
    const password = vaultService.generatePassword({
      length: 16,
      includeUppercase: true,
      includeLowercase: true,
      includeNumbers: true,
      includeSymbols: true,
      excludeSimilar: true,
    });
    setValue('password', password);
  };

  const onFormSubmit = (formData: FormData) => {
    // Transform form data to CreateVaultItemRequest format
    const { name, type, folder, notes, favorite, reprompt, ...dataFields } = formData;
    
    // Filter data fields based on type
    let data: any = {};
    if (type === 'login') {
      data = {
        username: formData.username,
        password: formData.password,
        url: formData.url,
      };
    } else if (type === 'card') {
      data = {
        cardholderName: formData.cardholderName,
        cardNumber: formData.cardNumber,
        expiryDate: formData.expiryDate,
        cvv: formData.cvv,
      };
    } else if (type === 'identity') {
      data = {
        firstName: formData.firstName,
        lastName: formData.lastName,
        email: formData.email,
        phone: formData.phone,
        address: formData.address,
      };
    } else if (type === 'secure_note') {
      data = {
        content: formData.content,
      };
    }

    const requestData: CreateVaultItemRequest = {
      name,
      type,
      data,
      folder,
      notes,
      favorite,
      reprompt,
    };

    onSubmit(requestData);
    reset();
    onClose();
  };

  const renderLoginFields = () => (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Tên đăng nhập
        </label>
        <input
          {...register('username')}
          type="text"
          className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          placeholder="Nhập tên đăng nhập"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Mật khẩu
        </label>
        <div className="relative">
          <input
            {...register('password')}
            type={showPassword ? 'text' : 'password'}
            className="w-full border border-gray-300 rounded-lg px-3 py-2 pr-20 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="Nhập mật khẩu"
          />
          <div className="absolute inset-y-0 right-0 flex items-center space-x-1 pr-3">
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="text-gray-400 hover:text-gray-600"
            >
              {showPassword ? (
                <EyeSlashIcon className="h-4 w-4" />
              ) : (
                <EyeIcon className="h-4 w-4" />
              )}
            </button>
            <button
              type="button"
              onClick={handleGeneratePassword}
              className="text-gray-400 hover:text-gray-600"
              title="Tạo mật khẩu"
            >
              <ArrowPathIcon className="h-4 w-4" />
            </button>
          </div>
        </div>
        {passwordStrength && (
          <div className="mt-2">
            <div className="flex items-center space-x-2">
              <div className="flex-1 bg-gray-200 rounded-full h-2">
                <div
                  className={`h-2 rounded-full transition-all ${
                    passwordStrength.score <= 1
                      ? 'bg-red-500 w-1/5'
                      : passwordStrength.score === 2
                      ? 'bg-orange-500 w-2/5'
                      : passwordStrength.score === 3
                      ? 'bg-yellow-500 w-3/5'
                      : passwordStrength.score === 4
                      ? 'bg-blue-500 w-4/5'
                      : 'bg-green-500 w-full'
                  }`}
                />
              </div>
              <span className="text-xs text-gray-600">
                {passwordStrength.isStrong ? 'Mạnh' : 'Yếu'}
              </span>
            </div>
          </div>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Website URL
        </label>
        <input
          {...register('url')}
          type="url"
          className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          placeholder="https://example.com"
        />
        {errors.url && (
          <p className="text-red-500 text-sm mt-1">{errors.url.message}</p>
        )}
      </div>
    </div>
  );

  const renderCardFields = () => (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Tên chủ thẻ
        </label>
        <input
          {...register('cardholderName')}
          type="text"
          className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          placeholder="Nguyễn Văn A"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Số thẻ
        </label>
        <input
          {...register('cardNumber')}
          type="text"
          className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          placeholder="1234 5678 9012 3456"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Ngày hết hạn
          </label>
          <input
            {...register('expiryDate')}
            type="text"
            className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="MM/YY"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            CVV
          </label>
          <input
            {...register('cvv')}
            type="text"
            className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="123"
          />
        </div>
      </div>
    </div>
  );

  const renderIdentityFields = () => (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Tên
          </label>
          <input
            {...register('firstName')}
            type="text"
            className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="Văn A"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Họ
          </label>
          <input
            {...register('lastName')}
            type="text"
            className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="Nguyễn"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Email
        </label>
        <input
          {...register('email')}
          type="email"
          className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          placeholder="example@email.com"
        />
        {errors.email && (
          <p className="text-red-500 text-sm mt-1">{errors.email.message}</p>
        )}
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Số điện thoại
        </label>
        <input
          {...register('phone')}
          type="tel"
          className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          placeholder="+84 123 456 789"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Địa chỉ
        </label>
        <textarea
          {...register('address')}
          className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          rows={3}
          placeholder="Địa chỉ đầy đủ"
        />
      </div>
    </div>
  );

  const renderNoteFields = () => (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">
        Nội dung ghi chú
      </label>
      <textarea
        {...register('content')}
        className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        rows={6}
        placeholder="Nhập nội dung ghi chú bảo mật..."
      />
    </div>
  );

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg w-full max-w-2xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <h2 className="text-xl font-semibold text-gray-900">
            {editItem ? 'Chỉnh sửa mục' : 'Thêm mục mới'}
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <XMarkIcon className="h-6 w-6" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-8rem)]">
          <form onSubmit={handleSubmit(onFormSubmit)} className="space-y-6">
            {/* Item Type Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-3">
                Loại mục
              </label>
              <div className="grid grid-cols-2 gap-3">
                {itemTypes.map((type) => {
                  const Icon = type.icon;
                  return (
                    <button
                      key={type.value}
                      type="button"
                      onClick={() => handleTypeChange(type.value as VaultItemType)}
                      className={`flex items-center space-x-3 p-3 border rounded-lg transition-colors ${
                        selectedType === type.value
                          ? 'border-blue-500 bg-blue-50 text-blue-700'
                          : 'border-gray-300 hover:border-gray-400'
                      }`}
                    >
                      <Icon className="h-5 w-5" />
                      <span className="font-medium">{type.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Basic Fields */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Tên mục *
              </label>
              <input
                {...register('name')}
                type="text"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Nhập tên mục"
              />
              {errors.name && (
                <p className="text-red-500 text-sm mt-1">{errors.name.message}</p>
              )}
            </div>

            {/* Folder Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Thư mục
              </label>
              <select
                {...register('folder')}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">Không có thư mục</option>
                {folders.map((folder) => (
                  <option key={folder.id} value={folder.id}>
                    {folder.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Type-specific Fields */}
            {selectedType === 'login' && renderLoginFields()}
            {selectedType === 'card' && renderCardFields()}
            {selectedType === 'identity' && renderIdentityFields()}
            {selectedType === 'secure_note' && renderNoteFields()}

            {/* Notes */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Ghi chú
              </label>
              <textarea
                {...register('notes')}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={3}
                placeholder="Ghi chú thêm..."
              />
            </div>

            {/* Options */}
            <div className="space-y-3">
              <label className="flex items-center space-x-2">
                <input
                  {...register('favorite')}
                  type="checkbox"
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-sm text-gray-700">Yêu thích</span>
              </label>
              
              <label className="flex items-center space-x-2">
                <input
                  {...register('reprompt')}
                  type="checkbox"
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-sm text-gray-700">
                  Yêu cầu xác thực lại khi truy cập
                </span>
              </label>
            </div>
          </form>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end space-x-3 p-6 border-t border-gray-200">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
          >
            Hủy
          </button>
          <button
            onClick={handleSubmit(onFormSubmit)}
            disabled={isSubmitting}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {isSubmitting ? 'Đang lưu...' : editItem ? 'Cập nhật' : 'Tạo mục'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default AddItemModal;
