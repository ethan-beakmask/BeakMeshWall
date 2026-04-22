// Package transport provides alternative report delivery mechanisms.
// The email transport sends encrypted reports via Gmail SMTP,
// designed for network-isolated environments where direct HTTP
// connectivity to Central is not available.
package transport

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"

	"github.com/anthropics/beakmeshwall-agent/internal/crypto"
)

// EmailConfig holds SMTP settings for email transport.
type EmailConfig struct {
	SMTPHost    string // e.g. smtp.gmail.com
	SMTPPort    int    // e.g. 587
	Username    string // Gmail address
	AppPassword string // Gmail App Password
	To          string // recipient address
	EncryptKey  string // AES-256 hex key (64 chars)
}

// EmailReporter sends agent reports as encrypted email attachments.
type EmailReporter struct {
	cfg      EmailConfig
	hostname string
	token    string // agent token for Central to identify the node
}

// NewEmailReporter creates an email-based reporter.
func NewEmailReporter(cfg EmailConfig, hostname, token string) *EmailReporter {
	return &EmailReporter{
		cfg:      cfg,
		hostname: hostname,
		token:    token,
	}
}

// envelope wraps report data with metadata for Central to process.
type envelope struct {
	Hostname  string                 `json:"hostname"`
	Token     string                 `json:"token"`
	Timestamp string                 `json:"timestamp"`
	Report    map[string]interface{} `json:"report"`
}

// Report encrypts and sends the report data via email.
func (e *EmailReporter) Report(data map[string]interface{}) error {
	env := envelope{
		Hostname:  e.hostname,
		Token:     e.token,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Report:    data,
	}

	plaintext, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	encrypted, err := crypto.Encrypt(plaintext, e.cfg.EncryptKey)
	if err != nil {
		return fmt.Errorf("encrypt report: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(encrypted)

	if err := e.sendMail(encoded); err != nil {
		return fmt.Errorf("send email: %w", err)
	}

	log.Printf("INFO: email report sent (%d bytes encrypted)", len(encrypted))
	return nil
}

// sendMail constructs a MIME email with the encrypted payload as attachment
// and sends it via SMTP.
func (e *EmailReporter) sendMail(payload string) error {
	addr := fmt.Sprintf("%s:%d", e.cfg.SMTPHost, e.cfg.SMTPPort)
	auth := smtp.PlainAuth("", e.cfg.Username, e.cfg.AppPassword, e.cfg.SMTPHost)

	boundary := fmt.Sprintf("BMWReport%d", time.Now().UnixNano())
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	subject := fmt.Sprintf("[BMW-REPORT] %s %s", e.hostname, ts)

	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: %s\r\n", e.cfg.Username))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", e.cfg.To))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
	msg.WriteString("\r\n")

	// Text part
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(fmt.Sprintf("BeakMeshWall Agent Report\r\nHost: %s\r\nTime: %s\r\n", e.hostname, ts))
	msg.WriteString("\r\n")

	// Attachment: encrypted report
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: application/octet-stream\r\n")
	msg.WriteString("Content-Transfer-Encoding: base64\r\n")
	msg.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"report_%s.enc\"\r\n", e.hostname))
	msg.WriteString("\r\n")

	// Split base64 into 76-char lines per RFC 2045
	for i := 0; i < len(payload); i += 76 {
		end := i + 76
		if end > len(payload) {
			end = len(payload)
		}
		msg.WriteString(payload[i:end])
		msg.WriteString("\r\n")
	}

	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	return smtp.SendMail(addr, auth, e.cfg.Username, []string{e.cfg.To}, []byte(msg.String()))
}
