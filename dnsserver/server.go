package dnsserver

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/miekg/dns"
	"github.com/patrickhener/goshs/logger"
	"github.com/patrickhener/goshs/webhook"
	"github.com/patrickhener/goshs/ws"
)

type DNSServer struct {
	IP      string // IP to listen on
	ReplyIP string // IP to reply DNS queries
	Port    int
	Hub     *ws.Hub
	Silent  bool
	WebHook *webhook.Webhook
}

func (d *DNSServer) handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		// Log query and push to websocket hub to be displayed in the UI
		event := ws.DNSEvent{
			Type:   "dns",
			Name:   q.Name,
			QType:  dns.TypeToString[q.Qtype],
			Source: w.RemoteAddr().String(),
		}
		eventBytes, err := json.Marshal(event)
		if err != nil {
			logger.Errorf("Error marshalling dns query event: %v", err)
			return
		}
		d.Hub.Broadcast <- eventBytes

		// If webhook is enabled, send the DNS query to the webhook endpoint
		logger.HandleWebhookSend(string(eventBytes), "dns", *d.WebHook)

		// If ReplyIP is not set, use the same IP as the DNS server
		if d.ReplyIP == "" {
			d.ReplyIP = d.IP
		}

		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
				A:   net.ParseIP(d.ReplyIP).To4(),
			})
		case dns.TypeMX:
			m.Answer = append(m.Answer, &dns.MX{
				Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 1},
				Preference: 10,
				Mx:         "mail." + q.Name,
			})
			// Add TypeAAAA,TypeTXT, TypeNS, TypeCNAME if needed, for now not applicable
		}
	}

	_ = w.WriteMsg(m)
}

func (d *DNSServer) Start() {
	addr := fmt.Sprintf("%s:%d", d.IP, d.Port)
	udpServer := &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(d.handler)}
	tcpServer := &dns.Server{Addr: addr, Net: "tcp", Handler: dns.HandlerFunc(d.handler)}
	logger.Infof("DNS server listening on udp/tcp %s:%d", d.IP, d.Port)

	go func() { _ = udpServer.ListenAndServe() }()
	go func() { _ = tcpServer.ListenAndServe() }()
}
