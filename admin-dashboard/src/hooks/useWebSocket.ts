import { useEffect, useRef, useState } from 'react';
import { useAuth } from '../contexts/AuthContext';

interface WSMessage {
  type: string;
  timestamp: string;
  user_id?: string;
  session_id?: string;
  data: any;
  metadata?: any;
}

type MessageHandler = (message: WSMessage) => void;

interface UseWebSocketOptions {
  url?: string;
  onMessage?: MessageHandler;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
  autoReconnect?: boolean;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

interface WebSocketState {
  isConnected: boolean;
  isConnecting: boolean;
  error: string | null;
  lastMessage: WSMessage | null;
  reconnectAttempts: number;
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const {
    url = `ws://localhost:8080/api/v1/ws`,
    onMessage,
    onConnect,
    onDisconnect,
    onError,
    autoReconnect = true,
    reconnectInterval = 5000,
    maxReconnectAttempts = 10,
  } = options;

  const { state: authState } = useAuth();
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const messageHandlersRef = useRef<Map<string, MessageHandler[]>>(new Map());
  
  const [wsState, setWsState] = useState<WebSocketState>({
    isConnected: false,
    isConnecting: false,
    error: null,
    lastMessage: null,
    reconnectAttempts: 0,
  });

  const connect = () => {
    if (!authState.token || wsState.isConnecting || wsState.isConnected) {
      return;
    }

    setWsState(prev => ({ ...prev, isConnecting: true, error: null }));

    try {
      const wsUrl = `${url}?token=${authState.token}`;
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('WebSocket connected');
        setWsState(prev => ({
          ...prev,
          isConnected: true,
          isConnecting: false,
          error: null,
          reconnectAttempts: 0,
        }));
        onConnect?.();
      };

      ws.onmessage = (event) => {
        try {
          const message: WSMessage = JSON.parse(event.data);
          console.log('WebSocket message received:', message);
          
          setWsState(prev => ({ ...prev, lastMessage: message }));
          
          // Call general message handler
          onMessage?.(message);
          
          // Call type-specific handlers
          const handlers = messageHandlersRef.current.get(message.type) || [];
          handlers.forEach(handler => handler(message));
          
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      ws.onclose = (event) => {
        console.log('WebSocket disconnected:', event.code, event.reason);
        setWsState(prev => ({
          ...prev,
          isConnected: false,
          isConnecting: false,
        }));
        
        onDisconnect?.();
        
        // Auto-reconnect if enabled and not a normal closure
        if (autoReconnect && event.code !== 1000 && wsState.reconnectAttempts < maxReconnectAttempts) {
          setWsState(prev => ({ ...prev, reconnectAttempts: prev.reconnectAttempts + 1 }));
          
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        }
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        setWsState(prev => ({
          ...prev,
          error: 'Connection failed',
          isConnecting: false,
        }));
        onError?.(error);
      };

      wsRef.current = ws;
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      setWsState(prev => ({
        ...prev,
        error: 'Failed to create connection',
        isConnecting: false,
      }));
    }
  };

  const disconnect = () => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.close(1000, 'User initiated disconnect');
    }
    
    wsRef.current = null;
    setWsState({
      isConnected: false,
      isConnecting: false,
      error: null,
      lastMessage: null,
      reconnectAttempts: 0,
    });
  };

  const sendMessage = (message: any) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
      return true;
    }
    return false;
  };

  const addMessageHandler = (messageType: string, handler: MessageHandler) => {
    const handlers = messageHandlersRef.current.get(messageType) || [];
    handlers.push(handler);
    messageHandlersRef.current.set(messageType, handlers);
    
    // Return cleanup function
    return () => {
      const currentHandlers = messageHandlersRef.current.get(messageType) || [];
      const updatedHandlers = currentHandlers.filter(h => h !== handler);
      
      if (updatedHandlers.length === 0) {
        messageHandlersRef.current.delete(messageType);
      } else {
        messageHandlersRef.current.set(messageType, updatedHandlers);
      }
    };
  };

  // Connect when authenticated and disconnect when not
  useEffect(() => {
    if (authState.isAuthenticated && authState.token) {
      connect();
    } else {
      disconnect();
    }

    // Cleanup on unmount
    return () => {
      disconnect();
    };
  }, [authState.isAuthenticated, authState.token]);

  // Health check ping
  useEffect(() => {
    if (!wsState.isConnected) return;

    const pingInterval = setInterval(() => {
      sendMessage({
        type: 'health_check',
        timestamp: new Date().toISOString(),
      });
    }, 30000); // Ping every 30 seconds

    return () => clearInterval(pingInterval);
  }, [wsState.isConnected]);

  return {
    ...wsState,
    connect,
    disconnect,
    sendMessage,
    addMessageHandler,
  };
}

// Hook for specific message types
export function useWebSocketMessage(messageType: string, handler: MessageHandler) {
  const ws = useWebSocket();
  
  useEffect(() => {
    if (!ws.isConnected) return;
    
    const cleanup = ws.addMessageHandler(messageType, handler);
    return cleanup;
  }, [messageType, handler, ws.isConnected]);
  
  return ws;
}

// Predefined hooks for common message types
export function useSecurityAlerts(handler: MessageHandler) {
  return useWebSocketMessage('security_alert', handler);
}

export function useAuditEvents(handler: MessageHandler) {
  return useWebSocketMessage('audit_event', handler);
}

export function useSystemStatus(handler: MessageHandler) {
  return useWebSocketMessage('system_status', handler);
}

export function useNotifications(handler: MessageHandler) {
  return useWebSocketMessage('notification', handler);
}