import React, { useState, useEffect } from 'react';
import { 
  BellIcon,
  XMarkIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  InformationCircleIcon,
  CheckCircleIcon 
} from '@heroicons/react/24/outline';
import { useWebSocket, useSecurityAlerts, useAuditEvents, useSystemStatus, useNotifications } from '../../hooks/useWebSocket';

interface Notification {
  id: string;
  type: 'security_alert' | 'audit_event' | 'system_status' | 'notification';
  title: string;
  message: string;
  timestamp: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  priority?: 'low' | 'medium' | 'high';
  read: boolean;
  data?: any;
}

const NotificationCenter: React.FC = () => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting'>('disconnected');

  const ws = useWebSocket({
    onConnect: () => setConnectionStatus('connected'),
    onDisconnect: () => setConnectionStatus('disconnected'),
    onError: () => setConnectionStatus('disconnected'),
  });

  // Handle different types of real-time messages
  useSecurityAlerts((message) => {
    addNotification({
      id: Date.now().toString(),
      type: 'security_alert',
      title: message.data.title || 'Security Alert',
      message: message.data.message || 'A security event was detected',
      timestamp: message.timestamp,
      severity: message.data.severity || 'high',
      read: false,
      data: message.data,
    });
  });

  useAuditEvents((message) => {
    addNotification({
      id: Date.now().toString(),
      type: 'audit_event',
      title: message.data.title || 'Audit Event',
      message: message.data.message || 'An audit event occurred',
      timestamp: message.timestamp,
      severity: 'medium',
      read: false,
      data: message.data,
    });
  });

  useSystemStatus((message) => {
    addNotification({
      id: Date.now().toString(),
      type: 'system_status',
      title: message.data.title || 'System Status',
      message: message.data.message || 'System status updated',
      timestamp: message.timestamp,
      priority: message.data.priority || 'low',
      read: false,
      data: message.data,
    });
  });

  useNotifications((message) => {
    addNotification({
      id: Date.now().toString(),
      type: 'notification',
      title: message.data.title || 'Notification',
      message: message.data.message || 'You have a new notification',
      timestamp: message.timestamp,
      read: false,
      data: message.data,
    });
  });

  const addNotification = (notification: Notification) => {
    setNotifications(prev => [notification, ...prev.slice(0, 99)]); // Keep max 100 notifications
    
    // Auto-show critical notifications
    if (notification.severity === 'critical' || notification.priority === 'high') {
      setIsOpen(true);
    }
  };

  const markAsRead = (id: string) => {
    setNotifications(prev =>
      prev.map(notification =>
        notification.id === id
          ? { ...notification, read: true }
          : notification
      )
    );
  };

  const markAllAsRead = () => {
    setNotifications(prev =>
      prev.map(notification => ({ ...notification, read: true }))
    );
  };

  const removeNotification = (id: string) => {
    setNotifications(prev => prev.filter(notification => notification.id !== id));
  };

  const clearAll = () => {
    setNotifications([]);
  };

  const unreadCount = notifications.filter(n => !n.read).length;

  const getNotificationIcon = (type: Notification['type'], severity?: string) => {
    switch (type) {
      case 'security_alert':
        return (
          <ShieldExclamationIcon className={`h-6 w-6 ${
            severity === 'critical' ? 'text-red-500' : 'text-orange-500'
          }`} />
        );
      case 'audit_event':
        return <InformationCircleIcon className="h-6 w-6 text-blue-500" />;
      case 'system_status':
        return <ExclamationTriangleIcon className="h-6 w-6 text-yellow-500" />;
      default:
        return <CheckCircleIcon className="h-6 w-6 text-green-500" />;
    }
  };

  const getNotificationColor = (notification: Notification) => {
    if (!notification.read) {
      switch (notification.severity || notification.priority) {
        case 'critical':
          return 'border-red-200 bg-red-50';
        case 'high':
          return 'border-orange-200 bg-orange-50';
        case 'medium':
          return 'border-yellow-200 bg-yellow-50';
        default:
          return 'border-blue-200 bg-blue-50';
      }
    }
    return 'border-gray-200 bg-white';
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    
    return date.toLocaleDateString();
  };

  return (
    <div className="relative">
      {/* Notification Bell */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
      >
        <BellIcon className="h-6 w-6" />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 h-5 w-5 bg-red-500 text-white text-xs font-bold rounded-full flex items-center justify-center">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
        
        {/* Connection Status Indicator */}
        <span className={`absolute bottom-0 right-0 w-3 h-3 rounded-full border-2 border-white ${
          connectionStatus === 'connected' ? 'bg-green-500' :
          connectionStatus === 'connecting' ? 'bg-yellow-500' : 'bg-red-500'
        }`} />
      </button>

      {/* Notification Panel */}
      {isOpen && (
        <div className="absolute right-0 mt-2 w-96 bg-white rounded-lg shadow-xl border border-gray-200 z-50 max-h-96 flex flex-col">
          {/* Header */}
          <div className="p-4 border-b border-gray-200 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <h3 className="text-lg font-semibold text-gray-900">Notifications</h3>
              <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                connectionStatus === 'connected' ? 'bg-green-100 text-green-800' :
                connectionStatus === 'connecting' ? 'bg-yellow-100 text-yellow-800' :
                'bg-red-100 text-red-800'
              }`}>
                {connectionStatus}
              </span>
            </div>
            <div className="flex items-center space-x-2">
              {notifications.length > 0 && (
                <>
                  <button
                    onClick={markAllAsRead}
                    className="text-sm text-blue-600 hover:text-blue-800"
                  >
                    Mark all read
                  </button>
                  <button
                    onClick={clearAll}
                    className="text-sm text-red-600 hover:text-red-800"
                  >
                    Clear all
                  </button>
                </>
              )}
              <button
                onClick={() => setIsOpen(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <XMarkIcon className="h-5 w-5" />
              </button>
            </div>
          </div>

          {/* Notifications List */}
          <div className="flex-1 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="p-8 text-center text-gray-500">
                <BellIcon className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                <p>No notifications</p>
              </div>
            ) : (
              <div className="divide-y divide-gray-200">
                {notifications.map((notification) => (
                  <div
                    key={notification.id}
                    className={`p-4 hover:bg-gray-50 transition-colors border-l-4 ${getNotificationColor(notification)}`}
                    onClick={() => markAsRead(notification.id)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-3 flex-1">
                        {getNotificationIcon(notification.type, notification.severity || notification.priority)}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <p className={`text-sm font-medium ${
                              notification.read ? 'text-gray-600' : 'text-gray-900'
                            }`}>
                              {notification.title}
                            </p>
                            <p className="text-xs text-gray-500 ml-2">
                              {formatTimestamp(notification.timestamp)}
                            </p>
                          </div>
                          <p className={`mt-1 text-sm ${
                            notification.read ? 'text-gray-500' : 'text-gray-700'
                          }`}>
                            {notification.message}
                          </p>
                          {notification.data?.ip_address && (
                            <p className="mt-1 text-xs text-gray-400">
                              IP: {notification.data.ip_address}
                            </p>
                          )}
                        </div>
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          removeNotification(notification.id);
                        }}
                        className="ml-2 text-gray-400 hover:text-gray-600"
                      >
                        <XMarkIcon className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Click outside to close */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => setIsOpen(false)}
        />
      )}
    </div>
  );
};

export default NotificationCenter;