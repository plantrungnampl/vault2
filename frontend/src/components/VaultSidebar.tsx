import React from 'react';
import {
  HomeIcon,
  KeyIcon,
  CreditCardIcon,
  IdentificationIcon,
  DocumentTextIcon,
  TrashIcon,
  FolderIcon,
  PlusIcon,
  MagnifyingGlassIcon,
  ShieldCheckIcon,
  Cog6ToothIcon,
} from '@heroicons/react/24/outline';
import {
  HeartIcon as HeartSolidIcon,
  ShieldExclamationIcon,
} from '@heroicons/react/24/solid';
import type { VaultFolder, VaultStats } from '../types/vault';

interface VaultSidebarProps {
  selectedFilter: string;
  onFilterChange: (filter: string) => void;
  folders: VaultFolder[];
  stats: VaultStats;
  onCreateFolder: () => void;
  onDeleteFolder: (folderId: string) => void;
  onSecurityReport: () => void;
  className?: string;
}

const VaultSidebar: React.FC<VaultSidebarProps> = ({
  selectedFilter,
  onFilterChange,
  folders,
  stats,
  onCreateFolder,
  onDeleteFolder,
  onSecurityReport,
  className = '',
}) => {
  const defaultFilters = [
    {
      id: 'all',
      label: 'Tất cả',
      icon: <HomeIcon className="h-5 w-5" />,
      count: stats.totalItems,
    },
    {
      id: 'login',
      label: 'Đăng nhập',
      icon: <KeyIcon className="h-5 w-5" />,
      count: stats.loginItems,
    },
    {
      id: 'card',
      label: 'Thẻ tín dụng',
      icon: <CreditCardIcon className="h-5 w-5" />,
      count: stats.cardItems,
    },
    {
      id: 'identity',
      label: 'Danh tính',
      icon: <IdentificationIcon className="h-5 w-5" />,
      count: stats.identityItems,
    },
    {
      id: 'secure_note',
      label: 'Ghi chú bảo mật',
      icon: <DocumentTextIcon className="h-5 w-5" />,
      count: stats.noteItems,
    },
    {
      id: 'favorite',
      label: 'Yêu thích',
      icon: <HeartSolidIcon className="h-5 w-5 text-red-500" />,
      count: 0, // Will be calculated from items
    },
    {
      id: 'trash',
      label: 'Thùng rác',
      icon: <TrashIcon className="h-5 w-5" />,
      count: 0, // Will be calculated from deleted items
    },
  ];

  const securityFilters = [
    {
      id: 'weak-passwords',
      label: 'Mật khẩu yếu',
      icon: <ShieldExclamationIcon className="h-5 w-5 text-orange-500" />,
      count: stats.weakPasswords,
    },
    {
      id: 'duplicate-passwords',
      label: 'Mật khẩu trùng lặp',
      icon: <ShieldExclamationIcon className="h-5 w-5 text-red-500" />,
      count: stats.duplicatePasswords,
    },
    {
      id: 'compromised-passwords',
      label: 'Mật khẩu bị xâm phạm',
      icon: <ShieldExclamationIcon className="h-5 w-5 text-red-600" />,
      count: stats.compromisedPasswords,
    },
  ];

  const renderFilterItem = (filter: any, isActive: boolean) => (
    <button
      key={filter.id}
      onClick={() => onFilterChange(filter.id)}
      className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-left transition-colors ${
        isActive
          ? 'bg-blue-50 text-blue-700 border border-blue-200'
          : 'text-gray-700 hover:bg-gray-50'
      }`}
    >
      <div className="flex items-center space-x-3">
        {filter.icon}
        <span className="font-medium">{filter.label}</span>
      </div>
      {filter.count > 0 && (
        <span
          className={`px-2 py-1 text-xs font-semibold rounded-full ${
            isActive
              ? 'bg-blue-100 text-blue-800'
              : 'bg-gray-100 text-gray-600'
          }`}
        >
          {filter.count}
        </span>
      )}
    </button>
  );

  const renderFolderItem = (folder: VaultFolder) => {
    const isActive = selectedFilter === `folder:${folder.id}`;
    return (
      <div
        key={folder.id}
        className={`flex items-center justify-between px-3 py-2 rounded-lg group ${
          isActive ? 'bg-blue-50' : 'hover:bg-gray-50'
        }`}
      >
        <button
          onClick={() => onFilterChange(`folder:${folder.id}`)}
          className={`flex items-center space-x-3 flex-1 text-left ${
            isActive ? 'text-blue-700' : 'text-gray-700'
          }`}
        >
          <FolderIcon 
            className={`h-4 w-4 ${folder.color ? `text-${folder.color}-500` : 'text-gray-400'}`} 
          />
          <span className="font-medium truncate">{folder.name}</span>
        </button>
        
        <div className="flex items-center space-x-1">
          {folder.itemCount > 0 && (
            <span
              className={`px-2 py-1 text-xs font-semibold rounded-full ${
                isActive
                  ? 'bg-blue-100 text-blue-800'
                  : 'bg-gray-100 text-gray-600'
              }`}
            >
              {folder.itemCount}
            </span>
          )}
          <button
            onClick={() => onDeleteFolder(folder.id)}
            className="opacity-0 group-hover:opacity-100 p-1 text-gray-400 hover:text-red-500 transition-all"
            title="Xóa thư mục"
          >
            <TrashIcon className="h-3 w-3" />
          </button>
        </div>
      </div>
    );
  };

  const hasSecurityIssues = stats.weakPasswords > 0 || 
                           stats.duplicatePasswords > 0 || 
                           stats.compromisedPasswords > 0;

  return (
    <div className={`bg-white border-r border-gray-200 ${className}`}>
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center space-x-2 mb-4">
          <ShieldCheckIcon className="h-6 w-6 text-blue-600" />
          <h2 className="text-lg font-semibold text-gray-900">Vault</h2>
        </div>
        
        <div className="relative">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Tìm kiếm..."
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            onChange={(e) => onFilterChange(`search:${e.target.value}`)}
          />
        </div>
      </div>

      <div className="p-4 space-y-6 overflow-y-auto">
        {/* Default Filters */}
        <div>
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">
            Danh mục
          </h3>
          <div className="space-y-1">
            {defaultFilters.map((filter) =>
              renderFilterItem(filter, selectedFilter === filter.id)
            )}
          </div>
        </div>

        {/* Security Filters */}
        {hasSecurityIssues && (
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
                Bảo mật
              </h3>
              <button
                onClick={onSecurityReport}
                className="text-xs text-blue-600 hover:text-blue-800 font-medium"
              >
                Báo cáo chi tiết
              </button>
            </div>
            <div className="space-y-1">
              {securityFilters
                .filter(filter => filter.count > 0)
                .map((filter) =>
                  renderFilterItem(filter, selectedFilter === filter.id)
                )}
            </div>
          </div>
        )}

        {/* Folders */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
              Thư mục ({stats.totalFolders})
            </h3>
            <button
              onClick={onCreateFolder}
              className="p-1 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded transition-colors"
              title="Tạo thư mục mới"
            >
              <PlusIcon className="h-4 w-4" />
            </button>
          </div>
          <div className="space-y-1">
            {folders.map(renderFolderItem)}
            {folders.length === 0 && (
              <p className="text-sm text-gray-500 italic px-3 py-2">
                Chưa có thư mục nào
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Settings Button */}
      <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-gray-200 bg-white">
        <button
          onClick={() => onFilterChange('settings')}
          className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-left transition-colors ${
            selectedFilter === 'settings'
              ? 'bg-blue-50 text-blue-700'
              : 'text-gray-700 hover:bg-gray-50'
          }`}
        >
          <Cog6ToothIcon className="h-5 w-5" />
          <span className="font-medium">Cài đặt</span>
        </button>
      </div>
    </div>
  );
};

export default VaultSidebar;
