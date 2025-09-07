import React, { useState } from 'react';
import {
  ChartBarIcon,
  DocumentTextIcon,
  ArrowDownTrayIcon,
  CalendarDaysIcon,
  UsersIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ClockIcon,
} from '@heroicons/react/24/outline';

interface ReportData {
  users: {
    total: number;
    active: number;
    suspended: number;
    newThisMonth: number;
  };
  security: {
    incidents: number;
    resolvedIncidents: number;
    criticalIncidents: number;
    averageResolutionTime: number;
  };
  vault: {
    totalItems: number;
    itemsCreated: number;
    itemsShared: number;
    weakPasswords: number;
  };
  compliance: {
    auditScore: number;
    lastAudit: string;
    complianceLevel: string;
    recommendations: number;
  };
}

const ReportsPage: React.FC = () => {
  const [dateRange, setDateRange] = useState({
    start: '2024-01-01',
    end: '2024-01-31',
  });
  const [reportType, setReportType] = useState('summary');
  const [reportData] = useState<ReportData>({
    users: {
      total: 1250,
      active: 1180,
      suspended: 45,
      newThisMonth: 127,
    },
    security: {
      incidents: 23,
      resolvedIncidents: 20,
      criticalIncidents: 2,
      averageResolutionTime: 4.5,
    },
    vault: {
      totalItems: 25630,
      itemsCreated: 1450,
      itemsShared: 320,
      weakPasswords: 89,
    },
    compliance: {
      auditScore: 94,
      lastAudit: '2024-01-15',
      complianceLevel: 'Excellent',
      recommendations: 3,
    },
  });

  const generateReport = async (type: string) => {
    try {
      // API call to generate report
      console.log(`Generating ${type} report for ${dateRange.start} to ${dateRange.end}`);
      // Show success toast
    } catch (error) {
      console.error('Failed to generate report:', error);
      // Show error toast
    }
  };

  const exportReport = (format: 'pdf' | 'csv' | 'xlsx') => {
    // Mock export functionality
    console.log(`Exporting report as ${format.toUpperCase()}`);
  };

  const reportTypes = [
    { id: 'summary', name: 'Tổng quan hệ thống', description: 'Báo cáo tổng quan về tất cả hoạt động' },
    { id: 'security', name: 'Báo cáo bảo mật', description: 'Chi tiết về các sự cố và cảnh báo bảo mật' },
    { id: 'users', name: 'Báo cáo người dùng', description: 'Thống kê hoạt động và hành vi người dùng' },
    { id: 'compliance', name: 'Báo cáo tuân thủ', description: 'Đánh giá tuân thủ các tiêu chuẩn bảo mật' },
    { id: 'audit', name: 'Báo cáo kiểm toán', description: 'Nhật ký chi tiết tất cả hoạt động hệ thống' },
  ];

  const renderSummaryReport = () => (
    <div className="space-y-6">
      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
          <div className="flex items-center">
            <UsersIcon className="h-8 w-8 text-blue-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-blue-600">Tổng người dùng</p>
              <p className="text-2xl font-bold text-blue-900">{reportData.users.total.toLocaleString()}</p>
              <p className="text-sm text-blue-700">+{reportData.users.newThisMonth} tháng này</p>
            </div>
          </div>
        </div>

        <div className="bg-green-50 border border-green-200 rounded-lg p-6">
          <div className="flex items-center">
            <ShieldCheckIcon className="h-8 w-8 text-green-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-green-600">Vault Items</p>
              <p className="text-2xl font-bold text-green-900">{reportData.vault.totalItems.toLocaleString()}</p>
              <p className="text-sm text-green-700">+{reportData.vault.itemsCreated} mới</p>
            </div>
          </div>
        </div>

        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-yellow-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-yellow-600">Sự cố bảo mật</p>
              <p className="text-2xl font-bold text-yellow-900">{reportData.security.incidents}</p>
              <p className="text-sm text-yellow-700">{reportData.security.resolvedIncidents} đã giải quyết</p>
            </div>
          </div>
        </div>

        <div className="bg-purple-50 border border-purple-200 rounded-lg p-6">
          <div className="flex items-center">
            <ChartBarIcon className="h-8 w-8 text-purple-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-purple-600">Điểm tuân thủ</p>
              <p className="text-2xl font-bold text-purple-900">{reportData.compliance.auditScore}%</p>
              <p className="text-sm text-purple-700">{reportData.compliance.complianceLevel}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Detailed Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border rounded-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Thống kê người dùng</h3>
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-gray-600">Người dùng hoạt động</span>
              <span className="font-semibold text-green-600">{reportData.users.active}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-600">Tài khoản bị khóa</span>
              <span className="font-semibold text-red-600">{reportData.users.suspended}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-600">Đăng ký mới tháng này</span>
              <span className="font-semibold text-blue-600">{reportData.users.newThisMonth}</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-green-600 h-2 rounded-full" 
                style={{ width: `${(reportData.users.active / reportData.users.total) * 100}%` }}
              ></div>
            </div>
            <p className="text-sm text-gray-500 text-center">
              {((reportData.users.active / reportData.users.total) * 100).toFixed(1)}% tỷ lệ hoạt động
            </p>
          </div>
        </div>

        <div className="bg-white border rounded-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Bảo mật & Tuân thủ</h3>
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-gray-600">Sự cố nghiêm trọng</span>
              <span className="font-semibold text-red-600">{reportData.security.criticalIncidents}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-600">Thời gian xử lý TB (giờ)</span>
              <span className="font-semibold text-yellow-600">{reportData.security.averageResolutionTime}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-600">Mật khẩu yếu</span>
              <span className="font-semibold text-orange-600">{reportData.vault.weakPasswords}</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-blue-600 h-2 rounded-full" 
                style={{ width: `${reportData.compliance.auditScore}%` }}
              ></div>
            </div>
            <p className="text-sm text-gray-500 text-center">
              Điểm tuân thủ: {reportData.compliance.auditScore}%
            </p>
          </div>
        </div>
      </div>

      {/* Recent Activities */}
      <div className="bg-white border rounded-lg p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Hoạt động gần đây</h3>
        <div className="space-y-3">
          <div className="flex items-center justify-between py-2 border-b border-gray-100">
            <div className="flex items-center space-x-3">
              <div className="w-2 h-2 bg-green-500 rounded-full"></div>
              <span className="text-gray-700">Backup hệ thống hoàn thành</span>
            </div>
            <span className="text-sm text-gray-500">2 giờ trước</span>
          </div>
          <div className="flex items-center justify-between py-2 border-b border-gray-100">
            <div className="flex items-center space-x-3">
              <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
              <span className="text-gray-700">15 người dùng mới đăng ký</span>
            </div>
            <span className="text-sm text-gray-500">6 giờ trước</span>
          </div>
          <div className="flex items-center justify-between py-2 border-b border-gray-100">
            <div className="flex items-center space-x-3">
              <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
              <span className="text-gray-700">Cảnh báo: Phát hiện 5 mật khẩu yếu mới</span>
            </div>
            <span className="text-sm text-gray-500">1 ngày trước</span>
          </div>
          <div className="flex items-center justify-between py-2">
            <div className="flex items-center space-x-3">
              <div className="w-2 h-2 bg-red-500 rounded-full"></div>
              <span className="text-gray-700">Sự cố bảo mật đã được giải quyết</span>
            </div>
            <span className="text-sm text-gray-500">2 ngày trước</span>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Báo cáo & Phân tích</h1>
          <p className="text-gray-600">Tạo và xuất báo cáo chi tiết về hoạt động hệ thống</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={() => exportReport('pdf')}
            className="flex items-center space-x-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
          >
            <ArrowDownTrayIcon className="h-4 w-4" />
            <span>PDF</span>
          </button>
          <button
            onClick={() => exportReport('csv')}
            className="flex items-center space-x-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
          >
            <ArrowDownTrayIcon className="h-4 w-4" />
            <span>CSV</span>
          </button>
          <button
            onClick={() => exportReport('xlsx')}
            className="flex items-center space-x-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
          >
            <ArrowDownTrayIcon className="h-4 w-4" />
            <span>Excel</span>
          </button>
        </div>
      </div>

      {/* Report Configuration */}
      <div className="bg-white shadow rounded-lg p-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Loại báo cáo
            </label>
            <select
              value={reportType}
              onChange={(e) => setReportType(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              {reportTypes.map(type => (
                <option key={type.id} value={type.id}>{type.name}</option>
              ))}
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Từ ngày
            </label>
            <input
              type="date"
              value={dateRange.start}
              onChange={(e) => setDateRange({ ...dateRange, start: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Đến ngày
            </label>
            <input
              type="date"
              value={dateRange.end}
              onChange={(e) => setDateRange({ ...dateRange, end: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={() => generateReport(reportType)}
              className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
            >
              Tạo báo cáo
            </button>
          </div>
        </div>
      </div>

      {/* Report Types Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {reportTypes.map((type) => (
          <div 
            key={type.id}
            className={`bg-white border-2 rounded-lg p-6 cursor-pointer transition-colors ${
              reportType === type.id 
                ? 'border-blue-500 bg-blue-50' 
                : 'border-gray-200 hover:border-gray-300'
            }`}
            onClick={() => setReportType(type.id)}
          >
            <div className="flex items-center mb-3">
              <DocumentTextIcon className="h-8 w-8 text-gray-600" />
              <h3 className="ml-3 text-lg font-semibold text-gray-900">{type.name}</h3>
            </div>
            <p className="text-sm text-gray-600">{type.description}</p>
            <div className="mt-4 flex items-center justify-between">
              <span className="text-xs text-gray-500">
                Cập nhật lần cuối: 1 giờ trước
              </span>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  generateReport(type.id);
                }}
                className="text-sm text-blue-600 hover:text-blue-800"
              >
                Tạo ngay
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Report Content */}
      <div className="bg-white shadow rounded-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-gray-900">
            {reportTypes.find(t => t.id === reportType)?.name}
          </h2>
          <div className="flex items-center text-sm text-gray-500">
            <CalendarDaysIcon className="h-4 w-4 mr-1" />
            {dateRange.start} - {dateRange.end}
          </div>
        </div>
        
        {renderSummaryReport()}
      </div>

      {/* Scheduled Reports */}
      <div className="bg-white shadow rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-900">Báo cáo định kỳ</h2>
          <button className="text-sm text-blue-600 hover:text-blue-800">
            + Thêm lịch báo cáo
          </button>
        </div>
        
        <div className="space-y-3">
          <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
            <div className="flex items-center space-x-3">
              <ClockIcon className="h-5 w-5 text-gray-400" />
              <div>
                <p className="font-medium text-gray-900">Báo cáo bảo mật hàng tuần</p>
                <p className="text-sm text-gray-500">Mỗi thứ 2 lúc 9:00 AM</p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <span className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full">
                Đang hoạt động
              </span>
              <button className="text-sm text-blue-600 hover:text-blue-800">Chỉnh sửa</button>
            </div>
          </div>

          <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
            <div className="flex items-center space-x-3">
              <ClockIcon className="h-5 w-5 text-gray-400" />
              <div>
                <p className="font-medium text-gray-900">Báo cáo tuân thủ hàng tháng</p>
                <p className="text-sm text-gray-500">Ngày 1 hàng tháng lúc 10:00 AM</p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <span className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full">
                Đang hoạt động
              </span>
              <button className="text-sm text-blue-600 hover:text-blue-800">Chỉnh sửa</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportsPage;