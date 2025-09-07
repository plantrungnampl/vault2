package websocket

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"securevault/internal/errors"
	"securevault/internal/logger"
	"securevault/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		origin := r.Header.Get("Origin")
		allowedOrigins := []string{
			"http://localhost:3000",
			"http://localhost:5173",
			"https://vault.example.com",
		}
		
		for _, allowed := range allowedOrigins {
			if origin == allowed {
				return true
			}
		}
		
		// Allow for development
		return true
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// Message types
const (
	MessageTypeSecurityAlert    = "security_alert"
	MessageTypeAuditEvent      = "audit_event"
	MessageTypeSystemStatus    = "system_status"
	MessageTypeUserActivity    = "user_activity"
	MessageTypeNotification    = "notification"
	MessageTypeHealthCheck     = "health_check"
)

// WebSocket message structure
type WSMessage struct {
	Type      string                 `json:"type"`
	Timestamp time.Time             `json:"timestamp"`
	UserID    *uuid.UUID            `json:"user_id,omitempty"`
	SessionID *uuid.UUID            `json:"session_id,omitempty"`
	Data      map[string]interface{} `json:"data"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Client represents a WebSocket client
type Client struct {
	ID       uuid.UUID
	UserID   uuid.UUID
	Role     string
	Conn     *websocket.Conn
	Send     chan WSMessage
	Hub      *Hub
	LastSeen time.Time
}

// Hub maintains active clients and broadcasts messages
type Hub struct {
	clients    map[uuid.UUID]*Client
	register   chan *Client
	unregister chan *Client
	broadcast  chan WSMessage
	mutex      sync.RWMutex
	logger     *log.Logger
}

// NewHub creates a new WebSocket hub
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[uuid.UUID]*Client),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan WSMessage),
		logger:     log.New(log.Writer(), "WebSocket: ", log.LstdFlags),
	}
}

// Run starts the hub's main loop
func (h *Hub) Run() {
	log := logger.GetLogger()
	log.Info("Starting WebSocket hub")
	
	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			h.clients[client.ID] = client
			h.mutex.Unlock()
			
			log.Info("Client connected",
				"client_id", client.ID,
				"user_id", client.UserID,
				"role", client.Role,
				"total_clients", len(h.clients),
			)
			
			// Send welcome message
			welcomeMsg := WSMessage{
				Type:      MessageTypeNotification,
				Timestamp: time.Now(),
				UserID:    &client.UserID,
				Data: map[string]interface{}{
					"message": "Connected to SecureVault real-time updates",
					"status":  "connected",
				},
			}
			
			select {
			case client.Send <- welcomeMsg:
			default:
				close(client.Send)
				h.mutex.Lock()
				delete(h.clients, client.ID)
				h.mutex.Unlock()
			}

		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client.ID]; ok {
				delete(h.clients, client.ID)
				close(client.Send)
			}
			h.mutex.Unlock()
			
			log.Info("Client disconnected",
				"client_id", client.ID,
				"user_id", client.UserID,
				"total_clients", len(h.clients),
			)

		case message := <-h.broadcast:
			h.mutex.RLock()
			for _, client := range h.clients {
				// Apply message filtering based on user role and permissions
				if h.shouldReceiveMessage(client, message) {
					select {
					case client.Send <- message:
					default:
						close(client.Send)
						delete(h.clients, client.ID)
					}
				}
			}
			h.mutex.RUnlock()
		}
	}
}

// shouldReceiveMessage determines if a client should receive a specific message
func (h *Hub) shouldReceiveMessage(client *Client, message WSMessage) bool {
	// Admin users get all messages
	if isAdminRole(client.Role) {
		return true
	}
	
	// Users only get messages related to them
	if message.UserID != nil && *message.UserID == client.UserID {
		return true
	}
	
	// Allow general notifications and system status for all users
	if message.Type == MessageTypeNotification || message.Type == MessageTypeSystemStatus {
		return true
	}
	
	return false
}

// BroadcastToAll sends a message to all connected clients
func (h *Hub) BroadcastToAll(message WSMessage) {
	select {
	case h.broadcast <- message:
	default:
		h.logger.Printf("Failed to broadcast message: channel full")
	}
}

// BroadcastToUser sends a message to a specific user
func (h *Hub) BroadcastToUser(userID uuid.UUID, message WSMessage) {
	message.UserID = &userID
	
	h.mutex.RLock()
	for _, client := range h.clients {
		if client.UserID == userID {
			select {
			case client.Send <- message:
			default:
				h.logger.Printf("Failed to send message to user %s", userID)
			}
		}
	}
	h.mutex.RUnlock()
}

// BroadcastToRole sends a message to all users with a specific role
func (h *Hub) BroadcastToRole(role string, message WSMessage) {
	h.mutex.RLock()
	for _, client := range h.clients {
		if client.Role == role {
			select {
			case client.Send <- message:
			default:
				h.logger.Printf("Failed to send message to role %s", role)
			}
		}
	}
	h.mutex.RUnlock()
}

// GetConnectedUsersCount returns the number of connected users
func (h *Hub) GetConnectedUsersCount() int {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return len(h.clients)
}

// GetConnectedUsers returns a list of connected users
func (h *Hub) GetConnectedUsers() []map[string]interface{} {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	
	users := make([]map[string]interface{}, 0, len(h.clients))
	for _, client := range h.clients {
		users = append(users, map[string]interface{}{
			"client_id": client.ID,
			"user_id":   client.UserID,
			"role":      client.Role,
			"last_seen": client.LastSeen,
		})
	}
	
	return users
}

// AuthValidator interface to avoid import cycles
type AuthValidator interface {
	ValidateToken(token string) (Claims, error)
}

// Claims interface for JWT claims
type Claims interface {
	GetUserID() uuid.UUID
	GetRole() string
}

// WebSocket handler
func HandleWebSocket(hub *Hub, authValidator AuthValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Authenticate WebSocket connection
		token := c.Query("token")
		if token == "" {
			errors.HandleError(c, errors.NewAuthenticationError("Missing authentication token"))
			return
		}
		
		claims, err := authValidator.ValidateToken(token)
		if err != nil {
			errors.HandleError(c, errors.NewAuthenticationError("Invalid authentication token"))
			return
		}
		
		// Upgrade HTTP connection to WebSocket
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			errors.HandleError(c, errors.NewInternalError("Failed to upgrade connection", err.Error()))
			return
		}
		
		// Create client
		client := &Client{
			ID:       uuid.New(),
			UserID:   claims.GetUserID(),
			Role:     claims.GetRole(),
			Conn:     conn,
			Send:     make(chan WSMessage, 256),
			Hub:      hub,
			LastSeen: time.Now(),
		}
		
		// Register client
		hub.register <- client
		
		// Start goroutines for reading and writing
		go client.writePump()
		go client.readPump()
	}
}

// readPump handles incoming messages from the client
func (c *Client) readPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
	}()
	
	// Set read deadline and pong handler
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		c.LastSeen = time.Now()
		return nil
	})
	
	for {
		var message WSMessage
		err := c.Conn.ReadJSON(&message)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}
		
		// Handle client messages (ping, heartbeat, etc.)
		c.handleClientMessage(message)
	}
}

// writePump handles outgoing messages to the client
func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()
	
	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			
			if err := c.Conn.WriteJSON(message); err != nil {
				return
			}
			
		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleClientMessage processes messages from the client
func (c *Client) handleClientMessage(message WSMessage) {
	switch message.Type {
	case MessageTypeHealthCheck:
		// Respond with health check
		response := WSMessage{
			Type:      MessageTypeHealthCheck,
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"status": "ok",
				"server_time": time.Now().Unix(),
			},
		}
		
		select {
		case c.Send <- response:
		default:
			// Client send buffer full
		}
		
	default:
		// Log unknown message types
		log.Printf("Unknown message type from client %s: %s", c.ID, message.Type)
	}
}

// Helper functions
func isAdminRole(role string) bool {
	adminRoles := []string{
		"vault_admin",
		"security_admin", 
		"super_admin",
	}
	
	for _, adminRole := range adminRoles {
		if role == adminRole {
			return true
		}
	}
	
	return false
}

// Notification service integration
type NotificationService struct {
	hub *Hub
}

func NewNotificationService(hub *Hub) *NotificationService {
	return &NotificationService{hub: hub}
}

// SendSecurityAlert sends a security alert to admins
func (ns *NotificationService) SendSecurityAlert(alert map[string]interface{}) {
	message := WSMessage{
		Type:      MessageTypeSecurityAlert,
		Timestamp: time.Now(),
		Data:      alert,
		Metadata: map[string]interface{}{
			"priority": "high",
			"category": "security",
		},
	}
	
	// Send to admin users only
	ns.hub.BroadcastToRole("vault_admin", message)
	ns.hub.BroadcastToRole("security_admin", message)
	ns.hub.BroadcastToRole("super_admin", message)
}

// SendAuditEvent sends an audit event notification
func (ns *NotificationService) SendAuditEvent(event map[string]interface{}) {
	message := WSMessage{
		Type:      MessageTypeAuditEvent,
		Timestamp: time.Now(),
		Data:      event,
		Metadata: map[string]interface{}{
			"category": "audit",
		},
	}
	
	// Send to admin users
	ns.hub.BroadcastToRole("vault_admin", message)
	ns.hub.BroadcastToRole("security_admin", message)
	ns.hub.BroadcastToRole("super_admin", message)
}

// SendSystemStatusUpdate sends system status updates
func (ns *NotificationService) SendSystemStatusUpdate(status map[string]interface{}) {
	message := WSMessage{
		Type:      MessageTypeSystemStatus,
		Timestamp: time.Now(),
		Data:      status,
		Metadata: map[string]interface{}{
			"category": "system",
		},
	}
	
	ns.hub.BroadcastToAll(message)
}

// SendUserNotification sends a notification to a specific user
func (ns *NotificationService) SendUserNotification(userID uuid.UUID, notification map[string]interface{}) {
	message := WSMessage{
		Type:      MessageTypeNotification,
		Timestamp: time.Now(),
		Data:      notification,
		Metadata: map[string]interface{}{
			"category": "user",
		},
	}
	
	ns.hub.BroadcastToUser(userID, message)
}

// Real-time notification functions for different event types

// NotifySecurityIncident sends real-time security incident notifications
func (ns *NotificationService) NotifySecurityIncident(incident *models.SecurityEvent) {
	alertData := map[string]interface{}{
		"id":          incident.ID,
		"type":        incident.Type,
		"severity":    incident.Severity,
		"description": getSecurityEventDescription(incident.Type),
		"timestamp":   incident.Timestamp,
		"ip_address":  incident.IPAddress,
		"resolved":    incident.Resolved,
	}

	if incident.UserID != nil {
		alertData["user_id"] = *incident.UserID
	}

	// Add specific details based on incident type
	switch incident.Type {
	case models.SecurityEventInvalidCredentials:
		alertData["title"] = "Invalid Login Attempt Detected"
		alertData["message"] = fmt.Sprintf("Multiple failed login attempts from IP %s", incident.IPAddress)
	case models.SecurityEventSuspiciousActivity:
		alertData["title"] = "Suspicious Activity Detected"
		alertData["message"] = "Unusual user behavior patterns detected"
	case models.SecurityEventLoginFailure:
		alertData["title"] = "Account Lockout"
		alertData["message"] = fmt.Sprintf("User account locked due to failed login attempts from IP %s", incident.IPAddress)
	default:
		alertData["title"] = "Security Alert"
		alertData["message"] = "Security event detected"
	}

	ns.SendSecurityAlert(alertData)
}

// NotifyAuditEvent sends real-time audit event notifications
func (ns *NotificationService) NotifyAuditEvent(log *models.AuditLog) {
	// Only notify for critical audit events
	if !isCriticalAuditAction(log.Action) {
		return
	}

	eventData := map[string]interface{}{
		"id":         log.ID,
		"user_id":    log.UserID,
		"action":     log.Action,
		"resource":   log.Resource,
		"success":    log.Success,
		"timestamp":  log.Timestamp,
		"ip_address": log.IPAddress,
		"title":      getAuditActionTitle(log.Action),
		"message":    getAuditActionMessage(log.Action, log.Success),
	}

	if log.Details != nil {
		eventData["details"] = log.Details
	}

	ns.SendAuditEvent(eventData)
}

// Helper functions for event descriptions

func getSecurityEventDescription(eventType models.SecurityEventType) string {
	descriptions := map[models.SecurityEventType]string{
		models.SecurityEventInvalidCredentials: "Multiple invalid login attempts detected",
		models.SecurityEventSuspiciousActivity: "Suspicious user behavior patterns detected",
		models.SecurityEventLoginFailure:       "Account locked due to failed login attempts",
	}
	
	if desc, exists := descriptions[eventType]; exists {
		return desc
	}
	
	return "Security event detected"
}

func isCriticalAuditAction(action string) bool {
	criticalActions := map[string]bool{
		"admin_create_user":     true,
		"admin_delete_user":     true,
		"admin_suspend_user":    true,
		"admin_reset_password":  true,
		"admin_update_policies": true,
		"vault_delete_item":     true,
		"password_change":       true,
		"mfa_enabled":           true,
		"mfa_disabled":          true,
	}
	
	if critical, exists := criticalActions[action]; exists {
		return critical
	}
	
	return false
}

func getAuditActionTitle(action string) string {
	titles := map[string]string{
		"admin_create_user":     "User Created",
		"admin_delete_user":     "User Deleted",
		"admin_suspend_user":    "User Suspended",
		"admin_reset_password":  "Password Reset by Admin",
		"admin_update_policies": "Security Policies Updated",
		"vault_delete_item":     "Vault Item Deleted",
		"password_change":       "Password Changed",
		"mfa_enabled":           "MFA Enabled",
		"mfa_disabled":          "MFA Disabled",
	}
	
	if title, exists := titles[action]; exists {
		return title
	}
	
	return "System Activity"
}

func getAuditActionMessage(action string, success bool) string {
	baseMessages := map[string]string{
		"admin_create_user":     "Administrator created a new user account",
		"admin_delete_user":     "Administrator deleted a user account",
		"admin_suspend_user":    "Administrator suspended a user account",
		"admin_reset_password":  "Administrator reset a user's password",
		"admin_update_policies": "Administrator updated security policies",
		"vault_delete_item":     "User permanently deleted a vault item",
		"password_change":       "User changed their password",
		"mfa_enabled":           "User enabled multi-factor authentication",
		"mfa_disabled":          "User disabled multi-factor authentication",
	}
	
	message := "System activity occurred"
	if baseMsg, exists := baseMessages[action]; exists {
		message = baseMsg
	}
	
	if !success {
		message += " (failed)"
	}
	
	return message
}