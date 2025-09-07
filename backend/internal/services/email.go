package services

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type EmailProvider string

const (
	SMTPProvider     EmailProvider = "smtp"
	SendGridProvider EmailProvider = "sendgrid"
	SESProvider      EmailProvider = "ses"
	MailgunProvider  EmailProvider = "mailgun"
)

type EmailTemplate string

const (
	SecurityAlertTemplate      EmailTemplate = "security_alert"
	LoginAttemptTemplate       EmailTemplate = "login_attempt"
	PasswordExpirationTemplate EmailTemplate = "password_expiration"
	AccountActivityTemplate    EmailTemplate = "account_activity"
	SystemMaintenanceTemplate  EmailTemplate = "system_maintenance"
	BreachNotificationTemplate EmailTemplate = "breach_notification"
	AccountLockedTemplate      EmailTemplate = "account_locked"
	TwoFactorTemplate          EmailTemplate = "two_factor"
	WelcomeTemplate            EmailTemplate = "welcome"
	PasswordResetTemplate      EmailTemplate = "password_reset"
)

type EmailPriority string

const (
	LowPriority      EmailPriority = "low"
	NormalPriority   EmailPriority = "normal"
	HighPriority     EmailPriority = "high"
	CriticalPriority EmailPriority = "critical"
)

type EmailConfig struct {
	Provider   EmailProvider `json:"provider"`
	SMTPHost   string        `json:"smtp_host"`
	SMTPPort   int           `json:"smtp_port"`
	Username   string        `json:"username"`
	Password   string        `json:"password"`
	FromEmail  string        `json:"from_email"`
	FromName   string        `json:"from_name"`
	APIKey     string        `json:"api_key"`
	Domain     string        `json:"domain"`
	EnableTLS  bool          `json:"enable_tls"`
	EnableAuth bool          `json:"enable_auth"`
	MaxRetries int           `json:"max_retries"`
	RetryDelay time.Duration `json:"retry_delay"`
}

type EmailRequest struct {
	ID          uuid.UUID              `json:"id"`
	To          []string               `json:"to"`
	CC          []string               `json:"cc,omitempty"`
	BCC         []string               `json:"bcc,omitempty"`
	Subject     string                 `json:"subject"`
	Template    EmailTemplate          `json:"template"`
	Data        map[string]interface{} `json:"data"`
	Priority    EmailPriority          `json:"priority"`
	ScheduledAt *time.Time             `json:"scheduled_at,omitempty"`
	UserID      *uuid.UUID             `json:"user_id,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	SentAt      *time.Time             `json:"sent_at,omitempty"`
	Status      string                 `json:"status"`
	Attempts    int                    `json:"attempts"`
	LastError   string                 `json:"last_error,omitempty"`
}

type EmailLog struct {
	ID          uuid.UUID              `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	MessageID   string                 `gorm:"index;not null" json:"message_id"`
	To          string                 `gorm:"not null" json:"to"`
	CC          string                 `json:"cc"`
	BCC         string                 `json:"bcc"`
	Subject     string                 `gorm:"not null" json:"subject"`
	Template    EmailTemplate          `gorm:"not null" json:"template"`
	Data        map[string]interface{} `gorm:"type:jsonb" json:"data"`
	Priority    EmailPriority          `gorm:"not null" json:"priority"`
	Status      string                 `gorm:"not null;index" json:"status"`
	SentAt      *time.Time             `json:"sent_at"`
	DeliveredAt *time.Time             `json:"delivered_at"`
	OpenedAt    *time.Time             `json:"opened_at"`
	ClickedAt   *time.Time             `json:"clicked_at"`
	Attempts    int                    `gorm:"default:0" json:"attempts"`
	LastError   string                 `json:"last_error"`
	UserID      *uuid.UUID             `gorm:"type:uuid;index" json:"user_id"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	CreatedAt   time.Time              `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt   time.Time              `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
}

type EmailService struct {
	db        *gorm.DB
	config    *EmailConfig
	templates map[EmailTemplate]*template.Template
	queue     chan *EmailRequest
	workers   int
	wg        sync.WaitGroup
	stopping  bool
	mu        sync.RWMutex
}

type SecurityAlertData struct {
	UserName      string    `json:"user_name"`
	AlertType     string    `json:"alert_type"`
	Description   string    `json:"description"`
	IPAddress     string    `json:"ip_address"`
	Location      string    `json:"location"`
	UserAgent     string    `json:"user_agent"`
	Timestamp     time.Time `json:"timestamp"`
	ActionTaken   string    `json:"action_taken"`
	SeverityLevel string    `json:"severity_level"`
}

type LoginAttemptData struct {
	UserName   string    `json:"user_name"`
	Success    bool      `json:"success"`
	IPAddress  string    `json:"ip_address"`
	Location   string    `json:"location"`
	UserAgent  string    `json:"user_agent"`
	Timestamp  time.Time `json:"timestamp"`
	DeviceInfo string    `json:"device_info"`
	Reason     string    `json:"reason,omitempty"`
}

func NewEmailService(db *gorm.DB, config *EmailConfig) (*EmailService, error) {
	service := &EmailService{
		db:        db,
		config:    config,
		templates: make(map[EmailTemplate]*template.Template),
		queue:     make(chan *EmailRequest, 1000),
		workers:   5,
	}

	if err := db.AutoMigrate(&EmailLog{}); err != nil {
		return nil, fmt.Errorf("failed to migrate email log table: %v", err)
	}

	if err := service.loadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load email templates: %v", err)
	}

	service.startWorkers()
	go service.startScheduledEmailProcessor()

	return service, nil
}

func (es *EmailService) loadTemplates() error {
	templates := map[EmailTemplate]string{
		SecurityAlertTemplate: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Alert - SecureVault</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #dc2626; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .alert-high { border-left: 4px solid #dc2626; padding: 10px; margin: 10px 0; }
        .footer { text-align: center; font-size: 12px; color: #666; padding: 20px; }
        .button { display: inline-block; padding: 10px 20px; background: #dc2626; color: white; text-decoration: none; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Alert</h1>
        </div>
        <div class="content">
            <p>Hello {{.UserName}},</p>
            
            <div class="alert-high">
                <h3>{{.AlertType}}</h3>
                <p>{{.Description}}</p>
            </div>
            
            <h4>Event Details:</h4>
            <ul>
                <li><strong>Time:</strong> {{.Timestamp.Format "January 2, 2006 at 3:04 PM MST"}}</li>
                <li><strong>IP Address:</strong> {{.IPAddress}}</li>
                <li><strong>Location:</strong> {{.Location}}</li>
                <li><strong>Device:</strong> {{.UserAgent}}</li>
                <li><strong>Severity:</strong> {{.SeverityLevel}}</li>
            </ul>
            
            <p><strong>Action Taken:</strong> {{.ActionTaken}}</p>
            
            <p>If this activity was not authorized by you, please secure your account immediately.</p>
            
            <p style="text-align: center;">
                <a href="#" class="button">Secure My Account</a>
            </p>
        </div>
        <div class="footer">
            <p>This is an automated security notification from SecureVault.</p>
            <p>Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>`,

		LoginAttemptTemplate: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login Activity - SecureVault</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: {{if .Success}}#059669{{else}}#dc2626{{end}}; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .footer { text-align: center; font-size: 12px; color: #666; padding: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{if .Success}}{{else}}L{{end}} Login Activity</h1>
        </div>
        <div class="content">
            <p>Hello {{.UserName}},</p>
            
            <p>We detected a {{if .Success}}successful{{else}}failed{{end}} login attempt on your account.</p>
            
            <h4>Login Details:</h4>
            <ul>
                <li><strong>Time:</strong> {{.Timestamp.Format "January 2, 2006 at 3:04 PM MST"}}</li>
                <li><strong>IP Address:</strong> {{.IPAddress}}</li>
                <li><strong>Location:</strong> {{.Location}}</li>
                <li><strong>Device:</strong> {{.DeviceInfo}}</li>
                {{if not .Success}}<li><strong>Reason:</strong> {{.Reason}}</li>{{end}}
            </ul>
            
            {{if not .Success}}
            <p style="color: #dc2626;"><strong>If this was not you, please secure your account immediately.</strong></p>
            {{end}}
        </div>
        <div class="footer">
            <p>This is an automated notification from SecureVault.</p>
        </div>
    </div>
</body>
</html>`,

		PasswordExpirationTemplate: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Expiration Warning - SecureVault</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f59e0b; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .footer { text-align: center; font-size: 12px; color: #666; padding: 20px; }
        .button { display: inline-block; padding: 10px 20px; background: #f59e0b; color: white; text-decoration: none; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>� Password Expiration Warning</h1>
        </div>
        <div class="content">
            <p>Hello {{.UserName}},</p>
            
            <p>Your SecureVault password will expire in <strong>{{.DaysUntilExpiration}} days</strong>.</p>
            
            <p>To maintain the security of your account, please update your password before it expires.</p>
            
            <p style="text-align: center;">
                <a href="{{.ChangePasswordURL}}" class="button">Change Password</a>
            </p>
            
            <p><strong>Security Tips:</strong></p>
            <ul>
                <li>Use a strong, unique password</li>
                <li>Include uppercase, lowercase, numbers, and symbols</li>
                <li>Avoid using personal information</li>
                <li>Don't reuse passwords from other accounts</li>
            </ul>
        </div>
        <div class="footer">
            <p>This is an automated notification from SecureVault.</p>
        </div>
    </div>
</body>
</html>`,
	}

	for templateName, templateContent := range templates {
		tmpl, err := template.New(string(templateName)).Parse(templateContent)
		if err != nil {
			return fmt.Errorf("failed to parse template %s: %v", templateName, err)
		}
		es.templates[templateName] = tmpl
	}

	return nil
}

func (es *EmailService) startWorkers() {
	for i := 0; i < es.workers; i++ {
		es.wg.Add(1)
		go es.emailWorker()
	}
}

func (es *EmailService) emailWorker() {
	defer es.wg.Done()

	for {
		select {
		case request := <-es.queue:
			if request == nil {
				return
			}
			es.processEmailRequest(request)
		default:
			es.mu.RLock()
			if es.stopping {
				es.mu.RUnlock()
				return
			}
			es.mu.RUnlock()
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func (es *EmailService) processEmailRequest(request *EmailRequest) {
	log.Printf("Processing email request: %s to %v", request.Subject, request.To)

	var emailLog EmailLog
	es.db.Where("message_id = ?", request.ID.String()).First(&emailLog)

	if emailLog.ID == uuid.Nil {
		emailLog = EmailLog{
			MessageID: request.ID.String(),
			To:        strings.Join(request.To, ","),
			CC:        strings.Join(request.CC, ","),
			BCC:       strings.Join(request.BCC, ","),
			Subject:   request.Subject,
			Template:  request.Template,
			Data:      request.Data,
			Priority:  request.Priority,
			Status:    "pending",
			UserID:    request.UserID,
		}
		es.db.Create(&emailLog)
	}

	if request.ScheduledAt != nil && time.Now().Before(*request.ScheduledAt) {
		log.Printf("Email %s scheduled for %v, skipping for now", request.ID, *request.ScheduledAt)
		return
	}

	err := es.sendEmail(request)

	emailLog.Attempts++
	if err != nil {
		emailLog.Status = "failed"
		emailLog.LastError = err.Error()
		log.Printf("Failed to send email %s: %v", request.ID, err)

		if emailLog.Attempts < es.config.MaxRetries {
			time.AfterFunc(es.config.RetryDelay*time.Duration(emailLog.Attempts), func() {
				select {
				case es.queue <- request:
				default:
					log.Printf("Email queue full, dropping retry for %s", request.ID)
				}
			})
		}
	} else {
		emailLog.Status = "sent"
		now := time.Now()
		emailLog.SentAt = &now
		log.Printf("Successfully sent email %s", request.ID)
	}

	es.db.Save(&emailLog)
}

func (es *EmailService) sendEmail(request *EmailRequest) error {
	template, exists := es.templates[request.Template]
	if !exists {
		return fmt.Errorf("template %s not found", request.Template)
	}

	var body bytes.Buffer
	if err := template.Execute(&body, request.Data); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	switch es.config.Provider {
	case SMTPProvider:
		return es.sendViaSMTP(request, body.String())
	case SendGridProvider:
		return es.sendViaSendGrid(request, body.String())
	case SESProvider:
		return es.sendViaSES(request, body.String())
	case MailgunProvider:
		return es.sendViaMailgun(request, body.String())
	default:
		return fmt.Errorf("unsupported email provider: %s", es.config.Provider)
	}
}

func (es *EmailService) sendViaSMTP(request *EmailRequest, body string) error {
	auth := smtp.PlainAuth("", es.config.Username, es.config.Password, es.config.SMTPHost)

	to := append(request.To, request.CC...)
	to = append(to, request.BCC...)

	headers := make(map[string]string)
	headers["From"] = fmt.Sprintf("%s <%s>", es.config.FromName, es.config.FromEmail)
	headers["To"] = strings.Join(request.To, ",")
	if len(request.CC) > 0 {
		headers["Cc"] = strings.Join(request.CC, ",")
	}
	headers["Subject"] = request.Subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"
	headers["Message-ID"] = fmt.Sprintf("<%s@securevault.local>", request.ID)
	headers["X-Priority"] = string(request.Priority)

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	addr := fmt.Sprintf("%s:%d", es.config.SMTPHost, es.config.SMTPPort)

	if es.config.EnableTLS {
		tlsConfig := &tls.Config{
			ServerName: es.config.SMTPHost,
		}

		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect with TLS: %v", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, es.config.SMTPHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %v", err)
		}
		defer client.Quit()

		if es.config.EnableAuth {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("SMTP authentication failed: %v", err)
			}
		}

		if err := client.Mail(es.config.FromEmail); err != nil {
			return fmt.Errorf("failed to set sender: %v", err)
		}

		for _, addr := range to {
			if err := client.Rcpt(addr); err != nil {
				return fmt.Errorf("failed to set recipient %s: %v", addr, err)
			}
		}

		writer, err := client.Data()
		if err != nil {
			return fmt.Errorf("failed to get data writer: %v", err)
		}

		_, err = writer.Write([]byte(message))
		if err != nil {
			return fmt.Errorf("failed to write message: %v", err)
		}

		return writer.Close()
	}

	return smtp.SendMail(addr, auth, es.config.FromEmail, to, []byte(message))
}

func (es *EmailService) sendViaSendGrid(request *EmailRequest, body string) error {
	return fmt.Errorf("SendGrid implementation not yet available")
}

func (es *EmailService) sendViaSES(request *EmailRequest, body string) error {
	return fmt.Errorf("SES implementation not yet available")
}

func (es *EmailService) sendViaMailgun(request *EmailRequest, body string) error {
	return fmt.Errorf("Mailgun implementation not yet available")
}

func (es *EmailService) SendSecurityAlert(userID uuid.UUID, userEmail, userName string, alertData *SecurityAlertData) error {
	requestID := uuid.New()

	request := &EmailRequest{
		ID:       requestID,
		To:       []string{userEmail},
		Subject:  fmt.Sprintf("=� Security Alert: %s", alertData.AlertType),
		Template: SecurityAlertTemplate,
		Data: map[string]interface{}{
			"UserName":      userName,
			"AlertType":     alertData.AlertType,
			"Description":   alertData.Description,
			"IPAddress":     alertData.IPAddress,
			"Location":      alertData.Location,
			"UserAgent":     alertData.UserAgent,
			"Timestamp":     alertData.Timestamp,
			"ActionTaken":   alertData.ActionTaken,
			"SeverityLevel": alertData.SeverityLevel,
		},
		Priority:  CriticalPriority,
		UserID:    &userID,
		CreatedAt: time.Now(),
		Status:    "queued",
	}

	select {
	case es.queue <- request:
		return nil
	default:
		return fmt.Errorf("email queue is full")
	}
}

func (es *EmailService) SendLoginNotification(userID uuid.UUID, userEmail, userName string, loginData *LoginAttemptData) error {
	requestID := uuid.New()

	subject := " Successful Login"
	priority := NormalPriority
	if !loginData.Success {
		subject = "L Failed Login Attempt"
		priority = HighPriority
	}

	request := &EmailRequest{
		ID:       requestID,
		To:       []string{userEmail},
		Subject:  subject,
		Template: LoginAttemptTemplate,
		Data: map[string]interface{}{
			"UserName":   userName,
			"Success":    loginData.Success,
			"IPAddress":  loginData.IPAddress,
			"Location":   loginData.Location,
			"UserAgent":  loginData.UserAgent,
			"DeviceInfo": loginData.DeviceInfo,
			"Timestamp":  loginData.Timestamp,
			"Reason":     loginData.Reason,
		},
		Priority:  priority,
		UserID:    &userID,
		CreatedAt: time.Now(),
		Status:    "queued",
	}

	select {
	case es.queue <- request:
		return nil
	default:
		return fmt.Errorf("email queue is full")
	}
}

func (es *EmailService) SendPasswordExpirationWarning(userID uuid.UUID, userEmail, userName string, daysUntilExpiration int, changePasswordURL string) error {
	requestID := uuid.New()

	request := &EmailRequest{
		ID:       requestID,
		To:       []string{userEmail},
		Subject:  fmt.Sprintf("� Password expires in %d days", daysUntilExpiration),
		Template: PasswordExpirationTemplate,
		Data: map[string]interface{}{
			"UserName":            userName,
			"DaysUntilExpiration": daysUntilExpiration,
			"ChangePasswordURL":   changePasswordURL,
		},
		Priority:  HighPriority,
		UserID:    &userID,
		CreatedAt: time.Now(),
		Status:    "queued",
	}

	select {
	case es.queue <- request:
		return nil
	default:
		return fmt.Errorf("email queue is full")
	}
}

func (es *EmailService) SendScheduledEmail(request *EmailRequest, scheduledAt time.Time) error {
	request.ScheduledAt = &scheduledAt
	request.Status = "scheduled"

	select {
	case es.queue <- request:
		return nil
	default:
		return fmt.Errorf("email queue is full")
	}
}

func (es *EmailService) startScheduledEmailProcessor() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			es.processScheduledEmails()
		}
	}
}

func (es *EmailService) processScheduledEmails() {
	var scheduledEmails []EmailLog
	es.db.Where("status = ? AND sent_at IS NULL", "scheduled").Find(&scheduledEmails)

	for _, email := range scheduledEmails {
		if email.SentAt == nil {
			request := &EmailRequest{
				ID:       uuid.MustParse(email.MessageID),
				To:       strings.Split(email.To, ","),
				CC:       strings.Split(email.CC, ","),
				BCC:      strings.Split(email.BCC, ","),
				Subject:  email.Subject,
				Template: email.Template,
				Data:     email.Data,
				Priority: email.Priority,
				UserID:   email.UserID,
			}

			select {
			case es.queue <- request:
			default:
				log.Printf("Failed to queue scheduled email %s: queue full", email.MessageID)
			}
		}
	}
}

func (es *EmailService) GetEmailStats(userID *uuid.UUID, days int) (*EmailStats, error) {
	stats := &EmailStats{}

	query := es.db.Model(&EmailLog{})
	if userID != nil {
		query = query.Where("user_id = ?", *userID)
	}
	if days > 0 {
		query = query.Where("created_at > ?", time.Now().AddDate(0, 0, -days))
	}

	query.Count(&stats.TotalSent)
	query.Where("status = ?", "sent").Count(&stats.Delivered)
	query.Where("status = ?", "failed").Count(&stats.Failed)
	query.Where("opened_at IS NOT NULL").Count(&stats.Opened)
	query.Where("clicked_at IS NOT NULL").Count(&stats.Clicked)

	return stats, nil
}

func (es *EmailService) MarkEmailOpened(messageID, userAgent, ipAddress string) error {
	now := time.Now()
	return es.db.Model(&EmailLog{}).
		Where("message_id = ? AND opened_at IS NULL", messageID).
		Updates(map[string]interface{}{
			"opened_at":  &now,
			"user_agent": userAgent,
			"ip_address": ipAddress,
		}).Error
}

func (es *EmailService) MarkEmailClicked(messageID, userAgent, ipAddress string) error {
	now := time.Now()
	return es.db.Model(&EmailLog{}).
		Where("message_id = ? AND clicked_at IS NULL", messageID).
		Updates(map[string]interface{}{
			"clicked_at": &now,
			"user_agent": userAgent,
			"ip_address": ipAddress,
		}).Error
}

func (es *EmailService) Shutdown() {
	log.Println("Shutting down email service...")

	es.mu.Lock()
	es.stopping = true
	es.mu.Unlock()

	close(es.queue)
	es.wg.Wait()

	log.Println("Email service stopped")
}

func generateTrackingPixel(messageID string) string {
	return fmt.Sprintf(`<img src="https://securevault.local/api/email/track/open/%s" width="1" height="1" style="display:none;" />`, messageID)
}

func generateSecureToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

type EmailStats struct {
	TotalSent int64 `json:"total_sent"`
	Delivered int64 `json:"delivered"`
	Failed    int64 `json:"failed"`
	Opened    int64 `json:"opened"`
	Clicked   int64 `json:"clicked"`
}
