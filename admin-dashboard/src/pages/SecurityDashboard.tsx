import React, { useState } from 'react';
import { 
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  EyeIcon,
  XMarkIcon 
} from '@heroicons/react/24/outline';

interface SecurityIncident {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  user?: {
    id: string;
    email: string;
    name: string;
  };
  ipAddress: string;
  timestamp: string;
  status: 'open' | 'investigating' | 'resolved' | 'false_positive';
  metadata?: any;
}

const SecurityDashboard: React.FC = () => {
  const [incidents] = useState<SecurityIncident[]>([
    {
      id: '1',
      type: 'suspicious_login',
      severity: 'high',
      title: 'Đăng nhập đáng nghi từ địa điểm mới',
      description: 'Người dùng đăng nhập từ IP không quen thuộc ở quốc gia khác',
      user: {
        id: 'user1',
        email: 'john.doe@example.com',
        name: 'John Doe'
      },
      ipAddress: '185.220.100.240',
      timestamp: '2024-01-15T10:30:00Z',
      status: 'open',
      metadata: {
        country: 'Russia',
        previousCountry: 'Vietnam'
      }
    },
    {
      id: '2',
      type: 'multiple_failed_logins',
      severity: 'medium',
      title: 'Nhiều lần đăng nhập thất bại',
      description: 'Tài khoản bị khóa sau 5 lần đăng nhập thất bại',
      user: {
        id: 'user2',
        email: 'jane.smith@example.com',
        name: 'Jane Smith'
      },
      ipAddress: '192.168.1.100',
      timestamp: '2024-01-15T09:15:00Z',
      status: 'resolved'
    },
    {
      id: '3',
      type: 'password_breach',
      severity: 'critical',
      title: 'Mật khẩu bị rò rỉ',
      description: 'Phát hiện mật khẩu trong danh sách breach',
      user: {
        id: 'user3',
        email: 'admin@company.com',
        name: 'Admin User'
      },
      ipAddress: '10.0.0.1',
      timestamp: '2024-01-15T08:45:00Z',
      status: 'investigating'
    }
  ]);

  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident | null>(null);

  const getSeverityColor = (severity: string) => {
    const colors = {
      low: 'bg-green-100 text-green-800 border-green-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      critical: 'bg-red-100 text-red-800 border-red-200'
    };
    return colors[severity as keyof typeof colors] || colors.low;
  };

  const getStatusColor = (status: string) => {
    const colors = {
      open: 'bg-red-100 text-red-800',
      investigating: 'bg-yellow-100 text-yellow-800',
      resolved: 'bg-green-100 text-green-800',
      false_positive: 'bg-gray-100 text-gray-800'
    };
    return colors[status as keyof typeof colors] || colors.open;
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <ShieldExclamationIcon className="h-5 w-5 text-red-600" />;
      case 'high':
        return <ExclamationTriangleIcon className="h-5 w-5 text-orange-600" />;
      case 'medium':
        return <ExclamationTriangleIcon className="h-5 w-5 text-yellow-600" />;
      default:
        return <CheckCircleIcon className="h-5 w-5 text-green-600" />;
    }
  };

  const stats = {
    totalIncidents: incidents.length,
    openIncidents: incidents.filter(i => i.status === 'open').length,
    criticalIncidents: incidents.filter(i => i.severity === 'critical').length,
    resolvedToday: incidents.filter(i => i.status === 'resolved').length
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Bảng điều khiển bảo mật</h1>
        <p className="text-gray-600">Giám sát và quản lý các sự cố bảo mật</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg">
              <ShieldExclamationIcon className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Tổng sự cố</p>
              <p className="text-2xl font-semibold text-gray-900">{stats.totalIncidents}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-red-100 rounded-lg">
              <ExclamationTriangleIcon className="h-6 w-6 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Sự cố mở</p>
              <p className="text-2xl font-semibold text-gray-900">{stats.openIncidents}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-orange-100 rounded-lg">
              <ShieldExclamationIcon className="h-6 w-6 text-orange-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Nghiêm trọng</p>
              <p className="text-2xl font-semibold text-gray-900">{stats.criticalIncidents}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 rounded-lg">
              <CheckCircleIcon className="h-6 w-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Đã giải quyết</p>
              <p className="text-2xl font-semibold text-gray-900">{stats.resolvedToday}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Sự cố bảo mật gần đây</h2>
        </div>
        
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Sự cố
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Người dùng
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Độ nghiêm trọng
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Trạng thái
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Thời gian
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Hành động
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {incidents.map((incident) => (
                <tr key={incident.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div className="flex items-center">
                      <div className="flex-shrink-0">
                        {getSeverityIcon(incident.severity)}
                      </div>
                      <div className="ml-3">
                        <div className="text-sm font-medium text-gray-900">
                          {incident.title}
                        </div>
                        <div className="text-sm text-gray-500">
                          {incident.description}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    {incident.user && (
                      <div>
                        <div className="text-sm font-medium text-gray-900">
                          {incident.user.name}
                        </div>
                        <div className="text-sm text-gray-500">
                          {incident.user.email}
                        </div>
                      </div>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full border ${getSeverityColor(incident.severity)}`}>
                      {incident.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(incident.status)}`}>
                      {incident.status.replace('_', ' ').toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-500">
                    <div className="flex items-center">
                      <ClockIcon className="h-4 w-4 mr-1" />
                      {new Date(incident.timestamp).toLocaleString('vi-VN')}
                    </div>
                  </td>
                  <td className="px-6 py-4 text-right text-sm font-medium">
                    <button
                      onClick={() => setSelectedIncident(incident)}
                      className="text-blue-600 hover:text-blue-900 mr-3"
                    >
                      <EyeIcon className="h-4 w-4" />
                    </button>
                    {incident.status === 'open' && (
                      <button className="text-green-600 hover:text-green-900">
                        Giải quyết
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900">Chi tiết sự cố</h3>
              <button
                onClick={() => setSelectedIncident(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                <XMarkIcon className="h-6 w-6" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <h4 className="font-medium text-gray-900">{selectedIncident.title}</h4>
                <p className="text-sm text-gray-600 mt-1">{selectedIncident.description}</p>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Độ nghiêm trọng</label>
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full border mt-1 ${getSeverityColor(selectedIncident.severity)}`}>
                    {selectedIncident.severity.toUpperCase()}
                  </span>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Trạng thái</label>
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full mt-1 ${getStatusColor(selectedIncident.status)}`}>
                    {selectedIncident.status.replace('_', ' ').toUpperCase()}
                  </span>
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Địa chỉ IP</label>
                <p className="text-sm text-gray-900 mt-1">{selectedIncident.ipAddress}</p>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Thời gian</label>
                <p className="text-sm text-gray-900 mt-1">
                  {new Date(selectedIncident.timestamp).toLocaleString('vi-VN')}
                </p>
              </div>
              
              {selectedIncident.metadata && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">Thông tin bổ sung</label>
                  <pre className="text-sm text-gray-900 mt-1 bg-gray-100 p-2 rounded">
                    {JSON.stringify(selectedIncident.metadata, null, 2)}
                  </pre>
                </div>
              )}
              
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Đóng
                </button>
                {selectedIncident.status === 'open' && (
                  <button className="px-4 py-2 bg-green-600 text-white rounded-md text-sm font-medium hover:bg-green-700">
                    Đánh dấu đã giải quyết
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityDashboard;