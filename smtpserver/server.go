package smtpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/patrickhener/goshs/logger"
	"github.com/patrickhener/goshs/webhook"
	"github.com/patrickhener/goshs/ws"
)

type Backend struct {
	Hub     *ws.Hub
	WebHook *webhook.Webhook
}

func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{hub: b.Hub, conn: c, webhook: b.WebHook}, nil
}

type Session struct {
	hub     *ws.Hub
	webhook *webhook.Webhook
	conn    *smtp.Conn
	from    string
	to      []string
}

func (s *Session) AuthPlain(user, pass string) error { return nil } // accept all

func (s *Session) Mail(from string, _ *smtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *Session) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	raw, _ := io.ReadAll(r)
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(msg.Body)

	// CC and BCC come from headers, not the SMTP envelope
	cc := strings.Split(msg.Header.Get("Cc"), ",")
	bcc := strings.Split(msg.Header.Get("Bcc"), ",")

	event := ws.SMTPEvent{
		Type:      "smtp",
		From:      s.from,
		To:        s.to,
		CC:        cc,
		BCC:       bcc,
		Subject:   msg.Header.Get("Subject"),
		Body:      string(body),
		RawHeader: fmt.Sprintf("%v", msg.Header),
		Timestamp: time.Now(),
	}
	eventBytes, err := json.Marshal(event)
	if err != nil {
		logger.Errorf("Error marshalling dns query event: %v", err)
		return err
	}

	s.hub.Broadcast <- eventBytes

	logger.HandleWebhookSend(string(eventBytes), "smtp", *s.webhook)

	return nil
}

func (s *Session) Reset()        { s.to = nil }
func (s *Session) Logout() error { return nil }

type SMTPServer struct {
	IP      string
	Port    int
	Hub     *ws.Hub
	WebHook *webhook.Webhook
}

func (srv *SMTPServer) Start() {
	be := &Backend{Hub: srv.Hub, WebHook: srv.WebHook}
	s := smtp.NewServer(be)
	s.Addr = fmt.Sprintf("%s:%d", srv.IP, srv.Port)
	s.Domain = "goshs"
	s.AllowInsecureAuth = true // catch-all, no real auth needed
	logger.Infof("SMTP server listening on %s:%d", srv.IP, srv.Port)
	go func() { _ = s.ListenAndServe() }()
}
