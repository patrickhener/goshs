package smtpserver

import (
	"github.com/emersion/go-smtp"
	"github.com/patrickhener/goshs/webhook"
	"github.com/patrickhener/goshs/ws"
)

type Backend struct {
	Hub     *ws.Hub
	WebHook *webhook.Webhook
	Domain  string
}

func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{hub: b.Hub, conn: c, webhook: b.WebHook, domain: b.Domain}, nil
}
