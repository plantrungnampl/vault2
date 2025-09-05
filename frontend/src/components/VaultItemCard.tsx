import React, { useState } from 'react';
import {
  EyeIcon,
  EyeSlashIcon,
  PencilIcon,
  TrashIcon,
  ClipboardDocumentIcon,
  GlobeAltIcon,
  CreditCardIcon,
  IdentificationIcon,
  DocumentTextIcon,
  KeyIcon,
} from '@heroicons/react/24/outline';
import type { VaultItem } from '../types/vault';
import { formatDistanceToNow } from 'date-fns';
import { vi } from 'date-fns/locale';

interface VaultItemCardProps {
  item: VaultItem;
  onEdit: (item: VaultItem) => void;
  onDelete: (id: string) => void;
  onCopyField: (value: string, fieldName: string) => void;
}

const VaultItemCard: React.FC<VaultItemCardProps> = ({
  item,
  onEdit,
  onDelete,
  onCopyField,
}) => {
  const [showSensitiveData, setShowSensitiveData] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const getItemIcon = () => {
    switch (item.type) {
      case 'login':
        return <KeyIcon className="h-5 w-5 text-blue-500" />;
      case 'card':
        return <CreditCardIcon className="h-5 w-5 text-green-500" />;
      case 'identity':
        return <IdentificationIcon className="h-5 w-5 text-purple-500" />;
      case 'secure_note':
        return <DocumentTextIcon className="h-5 w-5 text-amber-500" />;
      default:
        return <DocumentTextIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  const getTypeLabel = () => {
    switch (item.type) {
      case 'login':
        return 'Đăng nhập';
      case 'card':
        return 'Thẻ';
      case 'identity':
        return 'Danh tính';
      case 'secure_note':
        return 'Ghi chú bảo mật';
      default:
        return 'Khác';
    }
  };

  const handleCopy = async (value: string, fieldName: string) => {
    try {
      await navigator.clipboard.writeText(value);
      onCopyField(value, fieldName);
      setCopiedField(fieldName);
      setTimeout(() => setCopiedField(null), 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  };

  const maskSensitiveValue = (value: string) => {
    if (showSensitiveData) return value;
    return '●'.repeat(Math.min(value.length, 12));
  };

  const renderLoginFields = () => {
    if (item.type !== 'login') return null;
    const data = item.data as any;

    return (
      <div className="space-y-3">
        {data.username && (
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium text-gray-600">
                Tên đăng nhập
              </label>
              <p className="text-gray-900 font-mono">
                {data.username}
              </p>
            </div>
            <button
              onClick={() => handleCopy(data.username, 'username')}
              className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
              title="Sao chép tên đăng nhập"
            >
              <ClipboardDocumentIcon className="h-4 w-4" />
            </button>
          </div>
        )}

        {data.password && (
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <label className="text-sm font-medium text-gray-600">
                Mật khẩu
              </label>
              <p className="text-gray-900 font-mono">
                {maskSensitiveValue(data.password)}
              </p>
            </div>
            <div className="flex items-center space-x-1">
              <button
                onClick={() => setShowSensitiveData(!showSensitiveData)}
                className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
                title={showSensitiveData ? 'Ẩn mật khẩu' : 'Hiện mật khẩu'}
              >
                {showSensitiveData ? (
                  <EyeSlashIcon className="h-4 w-4" />
                ) : (
                  <EyeIcon className="h-4 w-4" />
                )}
              </button>
              <button
                onClick={() => handleCopy(data.password, 'password')}
                className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
                title="Sao chép mật khẩu"
              >
                <ClipboardDocumentIcon className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {data.url && (
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <label className="text-sm font-medium text-gray-600">
                Website
              </label>
              <div className="flex items-center space-x-2">
                <GlobeAltIcon className="h-4 w-4 text-gray-400" />
                <a
                  href={data.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:text-blue-800 underline truncate"
                >
                  {data.url}
                </a>
              </div>
            </div>
            <button
              onClick={() => handleCopy(data.url, 'url')}
              className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
              title="Sao chép URL"
            >
              <ClipboardDocumentIcon className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>
    );
  };

  const renderCardFields = () => {
    if (item.type !== 'card') return null;
    const data = item.data as any;

    return (
      <div className="space-y-3">
        {data.cardholderName && (
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium text-gray-600">
                Tên chủ thẻ
              </label>
              <p className="text-gray-900">{data.cardholderName}</p>
            </div>
            <button
              onClick={() => handleCopy(data.cardholderName, 'cardholderName')}
              className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <ClipboardDocumentIcon className="h-4 w-4" />
            </button>
          </div>
        )}

        {data.cardNumber && (
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <label className="text-sm font-medium text-gray-600">
                Số thẻ
              </label>
              <p className="text-gray-900 font-mono">
                {maskSensitiveValue(data.cardNumber)}
              </p>
            </div>
            <div className="flex items-center space-x-1">
              <button
                onClick={() => setShowSensitiveData(!showSensitiveData)}
                className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
              >
                {showSensitiveData ? (
                  <EyeSlashIcon className="h-4 w-4" />
                ) : (
                  <EyeIcon className="h-4 w-4" />
                )}
              </button>
              <button
                onClick={() => handleCopy(data.cardNumber, 'cardNumber')}
                className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <ClipboardDocumentIcon className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 gap-3">
          {data.expiryDate && (
            <div>
              <label className="text-sm font-medium text-gray-600">
                Ngày hết hạn
              </label>
              <p className="text-gray-900 font-mono">{data.expiryDate}</p>
            </div>
          )}

          {data.cvv && (
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium text-gray-600">CVV</label>
                <p className="text-gray-900 font-mono">
                  {maskSensitiveValue(data.cvv)}
                </p>
              </div>
              <button
                onClick={() => handleCopy(data.cvv, 'cvv')}
                className="p-1 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded"
              >
                <ClipboardDocumentIcon className="h-3 w-3" />
              </button>
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderNoteFields = () => {
    if (item.type !== 'secure_note') return null;
    const data = item.data as any;

    return (
      <div className="space-y-3">
        {data.content && (
          <div>
            <label className="text-sm font-medium text-gray-600">
              Nội dung
            </label>
            <div className="mt-1 p-3 bg-gray-50 rounded-lg border">
              <p className="text-gray-900 whitespace-pre-wrap">
                {data.content}
              </p>
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="bg-white rounded-lg border border-gray-200 shadow-sm hover:shadow-md transition-shadow">
      <div className="p-4">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center space-x-3">
            {getItemIcon()}
            <div>
              <h3 className="text-lg font-semibold text-gray-900">
                {item.name}
              </h3>
              <div className="flex items-center space-x-2 text-sm text-gray-500">
                <span>{getTypeLabel()}</span>
                {item.folder && (
                  <>
                    <span>•</span>
                    <span>{item.folder}</span>
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => onEdit(item)}
              className="p-2 text-gray-500 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
              title="Chỉnh sửa"
            >
              <PencilIcon className="h-4 w-4" />
            </button>
            <button
              onClick={() => onDelete(item.id)}
              className="p-2 text-gray-500 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors"
              title="Xóa"
            >
              <TrashIcon className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Fields */}
        <div className="space-y-4">
          {renderLoginFields()}
          {renderCardFields()}
          {renderNoteFields()}

          {/* Notes */}
          {item.notes && (
            <div>
              <label className="text-sm font-medium text-gray-600">
                Ghi chú
              </label>
              <p className="text-gray-700 text-sm mt-1">{item.notes}</p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between mt-4 pt-3 border-t border-gray-100">
          <div className="flex items-center space-x-4 text-xs text-gray-500">
            <span>
              Tạo: {formatDistanceToNow(new Date(item.createdAt), { 
                addSuffix: true, 
                locale: vi 
              })}
            </span>
            {item.updatedAt !== item.createdAt && (
              <span>
                Cập nhật: {formatDistanceToNow(new Date(item.updatedAt), { 
                  addSuffix: true, 
                  locale: vi 
                })}
              </span>
            )}
          </div>

          {copiedField && (
            <div className="text-xs text-green-600 font-medium">
              Đã sao chép {copiedField}!
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default VaultItemCard;
