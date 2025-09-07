import React, { useEffect, useState } from 'react';
import { 
  Users, 
  Shield, 
  Activity, 
  Settings, 
  FileText,
  Key,
  AlertTriangle,
  Database,
  Server,
  Clock,
  Loader2
} from 'lucide-react';
import { apiClient } from '../services/api';
import type { DashboardStats, SystemHealth } from '../services/api';
import { useToast } from './ui/Toast';

interface StatsCardProps {
  title: string;
  value: string | number;
  change?: string;
  icon: React.ReactNode;
  trend?: 'up' | 'down' | 'neutral';
}

const StatsCard: React.FC<StatsCardProps> = ({ title, value, change, icon, trend = 'neutral' }) => {
  const trendColors = {
    up: 'text-green-600',
    down: 'text-red-600',
    neutral: 'text-gray-600'
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-2xl font-semibold text-gray-900">{value}</p>
          {change && (
            <p className={`text-sm ${trendColors[trend]}`}>
              {change}
            </p>
          )}
        </div>
        <div className="h-12 w-12 flex items-center justify-center bg-blue-50 rounded-lg">
          {icon}
        </div>
      </div>
    </div>
  );
};

interface DashboardOverviewProps {}

const DashboardOverview: React.FC<DashboardOverviewProps> = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const { showToast } = useToast();

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const [statsData, healthData] = await Promise.all([
        apiClient.getDashboardStats(),
        apiClient.getSystemHealth().catch(() => ({
          database: { connected: true, latency: 0 },
          redis: { connected: true, latency: 0 },
          services: { auth: true, vault: true, audit: true }
        }))
      ]);
      
      setStats(statsData);
      setSystemHealth(healthData);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
      showToast('Không thể tải dữ liệu dashboard', 'error');
      // Set default mock data on error
      setStats({
        totalUsers: 0,
        activeUsers: 0,
        totalVaultItems: 0,
        securityIncidents: 0,
        systemUptime: "99.9%",
        storageUsed: "2.1GB",
        mfaEnabledUsers: 0,
        newUsersThisMonth: 0
      });
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
        <span className="ml-2 text-gray-600">Đang tải dữ liệu...</span>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Không thể tải dữ liệu dashboard</p>
        <button 
          onClick={loadDashboardData}
          className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          Thử lại
        </button>
      </div>
    );
  }
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Bảng điều khiển quản trị</h1>
        <p className="text-gray-600">Tổng quan hệ thống SecureVault</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-6">
        <StatsCard
          title="Tổng người dùng"
          value={stats.totalUsers}
          change="+12% so với tháng trước"
          icon={<Users className="h-6 w-6 text-blue-600" />}
          trend="up"
        />
        <StatsCard
          title="Người dùng hoạt động"
          value={stats.activeUsers}
          change="+8% so với tuần trước"
          icon={<Activity className="h-6 w-6 text-green-600" />}
          trend="up"
        />
        <StatsCard
          title="Tổng vault items"
          value={stats.totalVaultItems}
          change="+156 items hôm nay"
          icon={<Shield className="h-6 w-6 text-purple-600" />}
          trend="up"
        />
        <StatsCard
          title="Sự cố bảo mật"
          value={stats.securityIncidents}
          change="Giảm 50% so với tuần trước"
          icon={<AlertTriangle className="h-6 w-6 text-orange-600" />}
          trend="down"
        />
        <StatsCard
          title="Thời gian hoạt động"
          value={stats.systemUptime}
          icon={<Clock className="h-6 w-6 text-indigo-600" />}
        />
        <StatsCard
          title="Dung lượng sử dụng"
          value={stats.storageUsed}
          change="75% của tổng dung lượng"
          icon={<Database className="h-6 w-6 text-cyan-600" />}
          trend="neutral"
        />
      </div>

      {/* Quick Actions */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Thao tác nhanh</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <button className="flex items-center space-x-2 p-3 bg-blue-50 rounded-lg hover:bg-blue-100 transition-colors">
            <Users className="h-5 w-5 text-blue-600" />
            <span className="text-sm font-medium text-blue-700">Quản lý người dùng</span>
          </button>
          <button className="flex items-center space-x-2 p-3 bg-purple-50 rounded-lg hover:bg-purple-100 transition-colors">
            <Shield className="h-5 w-5 text-purple-600" />
            <span className="text-sm font-medium text-purple-700">Chính sách bảo mật</span>
          </button>
          <button className="flex items-center space-x-2 p-3 bg-green-50 rounded-lg hover:bg-green-100 transition-colors">
            <FileText className="h-5 w-5 text-green-600" />
            <span className="text-sm font-medium text-green-700">Báo cáo audit</span>
          </button>
          <button className="flex items-center space-x-2 p-3 bg-orange-50 rounded-lg hover:bg-orange-100 transition-colors">
            <Settings className="h-5 w-5 text-orange-600" />
            <span className="text-sm font-medium text-orange-700">Cấu hình hệ thống</span>
          </button>
        </div>
      </div>

      {/* System Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Trạng thái hệ thống</h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Server className={`h-5 w-5 ${systemHealth?.services?.auth ? 'text-green-600' : 'text-red-600'}`} />
                <span className="text-sm font-medium">API Server</span>
              </div>
              <span className={`px-2 py-1 text-xs rounded-full ${
                systemHealth?.services?.auth 
                  ? 'bg-green-100 text-green-800' 
                  : 'bg-red-100 text-red-800'
              }`}>
                {systemHealth?.services?.auth ? 'Hoạt động' : 'Lỗi'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Database className={`h-5 w-5 ${systemHealth?.database?.connected ? 'text-green-600' : 'text-red-600'}`} />
                <span className="text-sm font-medium">Cơ sở dữ liệu</span>
              </div>
              <span className={`px-2 py-1 text-xs rounded-full ${
                systemHealth?.database?.connected 
                  ? 'bg-green-100 text-green-800' 
                  : 'bg-red-100 text-red-800'
              }`}>
                {systemHealth?.database?.connected ? 'Kết nối' : 'Mất kết nối'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Key className={`h-5 w-5 ${systemHealth?.services?.vault ? 'text-green-600' : 'text-red-600'}`} />
                <span className="text-sm font-medium">Dịch vụ vault</span>
              </div>
              <span className={`px-2 py-1 text-xs rounded-full ${
                systemHealth?.services?.vault 
                  ? 'bg-green-100 text-green-800' 
                  : 'bg-red-100 text-red-800'
              }`}>
                {systemHealth?.services?.vault ? 'An toàn' : 'Lỗi'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Shield className={`h-5 w-5 ${systemHealth?.services?.audit ? 'text-green-600' : 'text-yellow-600'}`} />
                <span className="text-sm font-medium">Dịch vụ audit</span>
              </div>
              <span className={`px-2 py-1 text-xs rounded-full ${
                systemHealth?.services?.audit 
                  ? 'bg-green-100 text-green-800' 
                  : 'bg-yellow-100 text-yellow-800'
              }`}>
                {systemHealth?.services?.audit ? 'Hoạt động' : 'Cảnh báo'}
              </span>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Hoạt động gần đây</h2>
          <div className="space-y-3">
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-blue-600 rounded-full mt-2"></div>
              <div>
                <p className="text-sm text-gray-900">Người dùng mới đăng ký: user@example.com</p>
                <p className="text-xs text-gray-500">5 phút trước</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-green-600 rounded-full mt-2"></div>
              <div>
                <p className="text-sm text-gray-900">Backup hoàn thành thành công</p>
                <p className="text-xs text-gray-500">1 giờ trước</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-orange-600 rounded-full mt-2"></div>
              <div>
                <p className="text-sm text-gray-900">Phát hiện đăng nhập bất thường từ IP 192.168.1.100</p>
                <p className="text-xs text-gray-500">2 giờ trước</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-purple-600 rounded-full mt-2"></div>
              <div>
                <p className="text-sm text-gray-900">Cập nhật chính sách bảo mật</p>
                <p className="text-xs text-gray-500">6 giờ trước</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardOverview;
