package smtpserver

import (
	"fmt"

	"github.com/emersion/go-smtp"
	"goshs.de/goshs/logger"
	"goshs.de/goshs/options"
	"goshs.de/goshs/webhook"
	"goshs.de/goshs/ws"
)

type SMTPServer struct {
	IP      string
	Port    int
	Hub     *ws.Hub
	WebHook *webhook.Webhook
	Domain  string
}

func NewSMTP(opts *options.Options, hub *ws.Hub, wh *webhook.Webhook) *SMTPServer {
	return &SMTPServer{
		IP:      opts.IP,
		Port:    opts.SMTPPort,
		Domain:  opts.SMTPDomain,
		Hub:     hub,
		WebHook: wh,
	}
}

func (srv *SMTPServer) Start() {
	be := &Backend{Hub: srv.Hub, WebHook: srv.WebHook}
	s := smtp.NewServer(be)
	s.Addr = fmt.Sprintf("%s:%d", srv.IP, srv.Port)
	s.Domain = "goshs"
	s.AllowInsecureAuth = true // catch-all, no real auth needed
	if srv.Domain != "" {
		logger.Infof("SMTP catch-all listening on %s:%d (restricting to @%s)", srv.IP, srv.Port, srv.Domain)
	} else {
		logger.Infof("SMTP catch-all listening on %s:%d (open relay)", srv.IP, srv.Port)
	}
	go func() { _ = s.ListenAndServe() }()
}
