package smtpserver

import (
	"net"
	"strconv"
	"time"

	"github.com/emersion/go-smtp"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/smtpattach"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
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
	addr := net.JoinHostPort(srv.IP, strconv.Itoa(srv.Port))
	s.Addr = addr
	s.Domain = "goshs"
	s.AllowInsecureAuth = true // catch-all, no real auth needed
	if srv.Domain != "" {
		logger.Infof("SMTP catch-all listening on %s (restricting to @%s)", addr, srv.Domain)
	} else {
		logger.Infof("SMTP catch-all listening on %s (open relay)", addr)
	}
	go func() { _ = s.ListenAndServe() }()
	go smtpattach.PurgeLoop(1 * time.Hour)
}
