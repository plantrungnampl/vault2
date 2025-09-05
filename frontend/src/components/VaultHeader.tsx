import React from 'react';
import {
  PlusIcon,
  Bars3Icon,
  ArrowsUpDownIcon,
  FunnelIcon,
  Squares2X2Icon,
  ListBulletIcon,
  ShieldCheckIcon,
  UserCircleIcon,
  Cog6ToothIcon,
  ArrowRightOnRectangleIcon,
} from '@heroicons/react/24/outline';
import type { VaultSortOptions } from '../types/vault';

interface VaultHeaderProps {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  sortOptions: VaultSortOptions;
  onSortChange: (options: VaultSortOptions) => void;
  viewMode: 'grid' | 'list';
  onViewModeChange: (mode: 'grid' | 'list') => void;
  selectedCount: number;
  totalCount: number;
  onAddItem: () => void;
  onBulkAction: (action: string) => void;
  onSecurityReport: () => void;
  onToggleSidebar: () => void;
  onSettings: () => void;
  onProfile: () => void;
  onLogout: () => void;
  userName?: string;
}

const VaultHeader: React.FC<VaultHeaderProps> = ({
  searchQuery,
  onSearchChange,
  sortOptions,
  onSortChange,
  viewMode,
  onViewModeChange,
  selectedCount,
  totalCount,
  onAddItem,
  onBulkAction,
  onSecurityReport,
  onToggleSidebar,
  onSettings,
  onProfile,
  onLogout,
  userName = 'Người dùng',
}) => {
  const sortFields = [
    { value: 'name', label: 'Tên' },
    { value: 'type', label: 'Loại' },
    { value: 'createdAt', label: 'Ngày tạo' },
    { value: 'updatedAt', label: 'Ngày cập nhật' },
    { value: 'folder', label: 'Thư mục' },
  ];

  const bulkActions = [
    { value: 'delete', label: 'Xóa', danger: true },
    { value: 'move', label: 'Di chuyển' },
    { value: 'favorite', label: 'Yêu thích' },
    { value: 'export', label: 'Xuất file' },
  ];

  return (
    <header className="bg-white border-b border-gray-200 px-4 py-3">
      <div className="flex items-center justify-between">
        {/* Left Section */}
        <div className="flex items-center space-x-4">
          {/* Mobile Sidebar Toggle */}
          <button
            onClick={onToggleSidebar}
            className="lg:hidden p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
            title="Toggle sidebar"
          >
            <Bars3Icon className="h-5 w-5" />
          </button>

          {/* Title */}
          <div className="flex items-center space-x-2">
            <ShieldCheckIcon className="h-6 w-6 text-blue-600" />
            <h1 className="text-xl font-semibold text-gray-900 hidden sm:block">
              Vault Manager
            </h1>
          </div>

          {/* Item Count */}
          <div className="hidden md:flex items-center text-sm text-gray-500">
            {selectedCount > 0 ? (
              <span className="font-medium">
                Đã chọn {selectedCount} / {totalCount} mục
              </span>
            ) : (
              <span>
                {totalCount} mục
              </span>
            )}
          </div>
        </div>

        {/* Center Section - Search */}
        <div className="flex-1 max-w-lg mx-4">
          <div className="relative">
            <input
              type="text"
              placeholder="Tìm kiếm vault..."
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              className="w-full pl-4 pr-10 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <div className="absolute inset-y-0 right-0 flex items-center pr-3">
              <FunnelIcon className="h-4 w-4 text-gray-400" />
            </div>
          </div>
        </div>

        {/* Right Section */}
        <div className="flex items-center space-x-3">
          {/* Bulk Actions (when items selected) */}
          {selectedCount > 0 && (
            <div className="flex items-center space-x-2">
              <select
                onChange={(e) => onBulkAction(e.target.value)}
                className="text-sm border border-gray-300 rounded-lg px-3 py-1.5 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                defaultValue=""
              >
                <option value="" disabled>
                  Hành động ({selectedCount})
                </option>
                {bulkActions.map((action) => (
                  <option
                    key={action.value}
                    value={action.value}
                    className={action.danger ? 'text-red-600' : ''}
                  >
                    {action.label}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Sort Options */}
          <div className="hidden sm:flex items-center space-x-2">
            <select
              value={sortOptions.field}
              onChange={(e) =>
                onSortChange({
                  ...sortOptions,
                  field: e.target.value as any,
                })
              }
              className="text-sm border border-gray-300 rounded-lg px-3 py-1.5 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              {sortFields.map((field) => (
                <option key={field.value} value={field.value}>
                  {field.label}
                </option>
              ))}
            </select>

            <button
              onClick={() =>
                onSortChange({
                  ...sortOptions,
                  direction: sortOptions.direction === 'asc' ? 'desc' : 'asc',
                })
              }
              className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
              title={`Sắp xếp ${sortOptions.direction === 'asc' ? 'giảm dần' : 'tăng dần'}`}
            >
              <ArrowsUpDownIcon className="h-4 w-4" />
            </button>
          </div>

          {/* View Mode Toggle */}
          <div className="hidden sm:flex border border-gray-300 rounded-lg">
            <button
              onClick={() => onViewModeChange('grid')}
              className={`p-2 rounded-l-lg transition-colors ${
                viewMode === 'grid'
                  ? 'bg-blue-50 text-blue-600'
                  : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
              }`}
              title="Hiển thị dạng lưới"
            >
              <Squares2X2Icon className="h-4 w-4" />
            </button>
            <button
              onClick={() => onViewModeChange('list')}
              className={`p-2 rounded-r-lg transition-colors ${
                viewMode === 'list'
                  ? 'bg-blue-50 text-blue-600'
                  : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50'
              }`}
              title="Hiển thị dạng danh sách"
            >
              <ListBulletIcon className="h-4 w-4" />
            </button>
          </div>

          {/* Security Report Button */}
          <button
            onClick={onSecurityReport}
            className="p-2 text-gray-500 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
            title="Báo cáo bảo mật"
          >
            <ShieldCheckIcon className="h-5 w-5" />
          </button>

          {/* Add Item Button */}
          <button
            onClick={onAddItem}
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium transition-colors flex items-center space-x-2"
          >
            <PlusIcon className="h-4 w-4" />
            <span className="hidden sm:inline">Thêm mục</span>
          </button>

          {/* User Menu */}
          <div className="relative group">
            <button className="flex items-center space-x-2 p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors">
              <UserCircleIcon className="h-6 w-6" />
              <span className="hidden md:inline text-sm font-medium">
                {userName}
              </span>
            </button>

            {/* Dropdown Menu */}
            <div className="absolute right-0 mt-2 w-48 bg-white border border-gray-200 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50">
              <div className="py-1">
                <button
                  onClick={onProfile}
                  className="w-full flex items-center space-x-3 px-4 py-2 text-left text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  <UserCircleIcon className="h-4 w-4" />
                  <span>Hồ sơ cá nhân</span>
                </button>
                <button
                  onClick={onSettings}
                  className="w-full flex items-center space-x-3 px-4 py-2 text-left text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  <Cog6ToothIcon className="h-4 w-4" />
                  <span>Cài đặt</span>
                </button>
                <hr className="my-1" />
                <button
                  onClick={onLogout}
                  className="w-full flex items-center space-x-3 px-4 py-2 text-left text-red-600 hover:bg-red-50 transition-colors"
                >
                  <ArrowRightOnRectangleIcon className="h-4 w-4" />
                  <span>Đăng xuất</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Mobile search (hidden on desktop) */}
      <div className="mt-3 sm:hidden">
        <div className="relative">
          <input
            type="text"
            placeholder="Tìm kiếm..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="w-full pl-4 pr-10 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
          <div className="absolute inset-y-0 right-0 flex items-center pr-3">
            <FunnelIcon className="h-4 w-4 text-gray-400" />
          </div>
        </div>
      </div>
    </header>
  );
};

export default VaultHeader;
