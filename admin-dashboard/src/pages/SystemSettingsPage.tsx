import React, { useState } from 'react';
import {
  CogIcon,
  ShieldCheckIcon,
  ServerIcon,
  KeyIcon,
  BellIcon,
  ClockIcon,

  CloudArrowUpIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';

interface SystemSettings {
  security: {
    passwordMinLength: number;
    passwordComplexity: boolean;
    maxLoginAttempts: number;
    accountLockoutTime: number;
    sessionTimeout: number;
    mfaRequired: boolean;
    passwordHistoryCount: number;
    keyRotationInterval: number;
  };
  backup: {
    enabled: boolean;
    frequency: string;
    retention: number;
    encryptionEnabled: boolean;
    storageProvider: string;
  };
  notifications: {
    emailEnabled: boolean;
    smsEnabled: boolean;
    securityAlertsEnabled: boolean;
    adminNotificationsEnabled: boolean;
  };
  system: {
    maintenanceMode: boolean;
    allowRegistration: boolean;
    maxUsers: number;
    maxVaultItemsPerUser: number;
    fileUploadMaxSize: number;
  };
}

const SystemSettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<SystemSettings>({
    security: {
      passwordMinLength: 14,
      passwordComplexity: true,
      maxLoginAttempts: 5,
      accountLockoutTime: 30,
      sessionTimeout: 120,
      mfaRequired: false,
      passwordHistoryCount: 24,
      keyRotationInterval: 90,
    },
    backup: {
      enabled: true,
      frequency: '24h',
      retention: 90,
      encryptionEnabled: true,
      storageProvider: 'local',
    },
    notifications: {
      emailEnabled: true,
      smsEnabled: false,
      securityAlertsEnabled: true,
      adminNotificationsEnabled: true,
    },
    system: {
      maintenanceMode: false,
      allowRegistration: true,
      maxUsers: 1000,
      maxVaultItemsPerUser: -1,
      fileUploadMaxSize: 100,
    },
  });

  const [hasChanges, setHasChanges] = useState(false);
  const [activeTab, setActiveTab] = useState('security');

  const handleSettingChange = (category: keyof SystemSettings, key: string, value: any) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: value,
      },
    }));
    setHasChanges(true);
  };

  const handleSave = async () => {
    try {
      // API call to save settings
      console.log('Saving settings:', settings);
      setHasChanges(false);
      // Show success toast
    } catch (error) {
      console.error('Failed to save settings:', error);
      // Show error toast
    }
  };

  const handleReset = () => {
    // Reset to default values
    setHasChanges(false);
  };

  const tabs = [
    { id: 'security', name: 'Bảo mật', icon: ShieldCheckIcon },
    { id: 'backup', name: 'Backup', icon: CloudArrowUpIcon },
    { id: 'notifications', name: 'Thông báo', icon: BellIcon },
    { id: 'system', name: 'Hệ thống', icon: CogIcon },
  ];

  const renderSecuritySettings = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Chính sách mật khẩu</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Độ dài tối thiểu
            </label>
            <input
              type="number"
              min="8"
              max="32"
              value={settings.security.passwordMinLength}
              onChange={(e) => handleSettingChange('security', 'passwordMinLength', parseInt(e.target.value))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Lịch sử mật khẩu
            </label>
            <input
              type="number"
              min="0"
              max="50"
              value={settings.security.passwordHistoryCount}
              onChange={(e) => handleSettingChange('security', 'passwordHistoryCount', parseInt(e.target.value))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <div className="md:col-span-2">
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={settings.security.passwordComplexity}
                onChange={(e) => handleSettingChange('security', 'passwordComplexity', e.target.checked)}
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <span className="ml-2 text-sm text-gray-700">
                Yêu cầu độ phức tạp cao (chữ hoa, chữ thường, số, ký tự đặc biệt)
              </span>
            </label>
          </div>
        </div>
      </div>

      <div>
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Bảo mật đăng nhập</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Số lần thử tối đa
            </label>
            <input
              type="number"
              min="1"
              max="10"
              value={settings.security.maxLoginAttempts}
              onChange={(e) => handleSettingChange('security', 'maxLoginAttempts', parseInt(e.target.value))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Thời gian khóa (phút)
            </label>
            <input
              type="number"
              min="5"
              max="1440"
              value={settings.security.accountLockoutTime}
              onChange={(e) => handleSettingChange('security', 'accountLockoutTime', parseInt(e.target.value))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Timeout session (phút)
            </label>
            <input
              type="number"
              min="15"
              max="480"
              value={settings.security.sessionTimeout}
              onChange={(e) => handleSettingChange('security', 'sessionTimeout', parseInt(e.target.value))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Key rotation (ngày)
            </label>
            <input
              type="number"
              min="30"
              max="365"
              value={settings.security.keyRotationInterval}
              onChange={(e) => handleSettingChange('security', 'keyRotationInterval', parseInt(e.target.value))}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <div className="md:col-span-2">
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={settings.security.mfaRequired}
                onChange={(e) => handleSettingChange('security', 'mfaRequired', e.target.checked)}
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <span className="ml-2 text-sm text-gray-700">
                Bắt buộc xác thực đa yếu tố (MFA) cho tất cả người dùng
              </span>
            </label>
          </div>
        </div>
      </div>
    </div>
  );

  const renderBackupSettings = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Cấu hình Backup</h3>
        <div className="space-y-6">
          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={settings.backup.enabled}
                onChange={(e) => handleSettingChange('backup', 'enabled', e.target.checked)}
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <span className="ml-2 text-sm font-medium text-gray-700">
                Kích hoạt backup tự động
              </span>
            </label>
          </div>

          {settings.backup.enabled && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Tần suất backup
                  </label>
                  <select
                    value={settings.backup.frequency}
                    onChange={(e) => handleSettingChange('backup', 'frequency', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="4h">Mỗi 4 giờ</option>
                    <option value="12h">Mỗi 12 giờ</option>
                    <option value="24h">Hàng ngày</option>
                    <option value="7d">Hàng tuần</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Thời gian lưu trữ (ngày)
                  </label>
                  <input
                    type="number"
                    min="7"
                    max="365"
                    value={settings.backup.retention}
                    onChange={(e) => handleSettingChange('backup', 'retention', parseInt(e.target.value))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Nhà cung cấp lưu trữ
                  </label>
                  <select
                    value={settings.backup.storageProvider}
                    onChange={(e) => handleSettingChange('backup', 'storageProvider', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="local">Local Storage</option>
                    <option value="s3">Amazon S3</option>
                    <option value="gcs">Google Cloud Storage</option>
                    <option value="azure">Azure Storage</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={settings.backup.encryptionEnabled}
                    onChange={(e) => handleSettingChange('backup', 'encryptionEnabled', e.target.checked)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-700">
                    Mã hóa backup files
                  </span>
                </label>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );

  const renderNotificationSettings = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Cấu hình thông báo</h3>
        <div className="space-y-4">
          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={settings.notifications.emailEnabled}
                onChange={(e) => handleSettingChange('notifications', 'emailEnabled', e.target.checked)}
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <span className="ml-2 text-sm text-gray-700">
                Kích hoạt thông báo email
              </span>
            </label>
          </div>

          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={settings.notifications.smsEnabled}
                onChange={(e) => handleSettingChange('notifications', 'smsEnabled', e.target.checked)}
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <span className="ml-2 text-sm text-gray-700">
                Kích hoạt thông báo SMS
              </span>
            </label>
          </div>

          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={settings.notifications.securityAlertsEnabled}
                onChange={(e) => handleSettingChange('notifications', 'securityAlertsEnabled', e.target.checked)}
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <span className="ml-2 text-sm text-gray-700">
                Thông báo cảnh báo bảo mật
              </span>
            </label>
          </div>

          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={settings.notifications.adminNotificationsEnabled}
                onChange={(e) => handleSettingChange('notifications', 'adminNotificationsEnabled', e.target.checked)}
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <span className="ml-2 text-sm text-gray-700">
                Thông báo quản trị viên
              </span>
            </label>
          </div>
        </div>
      </div>
    </div>
  );

  const renderSystemSettings = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Cấu hình hệ thống</h3>
        <div className="space-y-6">
          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={settings.system.maintenanceMode}
                onChange={(e) => handleSettingChange('system', 'maintenanceMode', e.target.checked)}
                className="h-4 w-4 text-red-600 focus:ring-red-500 border-gray-300 rounded"
              />
              <span className="ml-2 text-sm text-gray-700">
                Chế độ bảo trì (khóa tất cả người dùng)
              </span>
            </label>
            {settings.system.maintenanceMode && (
              <div className="mt-2 p-3 bg-yellow-50 border border-yellow-200 rounded-md">
                <div className="flex">
                  <ExclamationTriangleIcon className="h-5 w-5 text-yellow-400" />
                  <div className="ml-3">
                    <p className="text-sm text-yellow-700">
                      Chế độ bảo trì sẽ ngăn tất cả người dùng truy cập vào hệ thống.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="flex items-center mb-3">
                <input
                  type="checkbox"
                  checked={settings.system.allowRegistration}
                  onChange={(e) => handleSettingChange('system', 'allowRegistration', e.target.checked)}
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
                <span className="ml-2 text-sm text-gray-700">
                  Cho phép đăng ký mới
                </span>
              </label>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Số người dùng tối đa
              </label>
              <input
                type="number"
                min="1"
                value={settings.system.maxUsers}
                onChange={(e) => handleSettingChange('system', 'maxUsers', parseInt(e.target.value))}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Vault items/người dùng (-1 = không giới hạn)
              </label>
              <input
                type="number"
                min="-1"
                value={settings.system.maxVaultItemsPerUser}
                onChange={(e) => handleSettingChange('system', 'maxVaultItemsPerUser', parseInt(e.target.value))}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Kích thước file tối đa (MB)
              </label>
              <input
                type="number"
                min="1"
                max="1024"
                value={settings.system.fileUploadMaxSize}
                onChange={(e) => handleSettingChange('system', 'fileUploadMaxSize', parseInt(e.target.value))}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderActiveTab = () => {
    switch (activeTab) {
      case 'security':
        return renderSecuritySettings();
      case 'backup':
        return renderBackupSettings();
      case 'notifications':
        return renderNotificationSettings();
      case 'system':
        return renderSystemSettings();
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Cài đặt hệ thống</h1>
          <p className="text-gray-600">Quản lý cấu hình và chính sách hệ thống</p>
        </div>
        {hasChanges && (
          <div className="flex space-x-3">
            <button
              onClick={handleReset}
              className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
            >
              Hủy bỏ
            </button>
            <button
              onClick={handleSave}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Lưu thay đổi
            </button>
          </div>
        )}
      </div>

      <div className="bg-white shadow rounded-lg">
        {/* Tabs */}
        <div className="border-b border-gray-200">
          <nav className="-mb-px flex space-x-8 px-6">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <tab.icon className="h-5 w-5" />
                <span>{tab.name}</span>
              </button>
            ))}
          </nav>
        </div>

        {/* Content */}
        <div className="p-6">
          {renderActiveTab()}
        </div>
      </div>
    </div>
  );
};

export default SystemSettingsPage;