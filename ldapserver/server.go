package ldapserver

import (
	"fmt"
	"net"

	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
)

// LDAPServer is a minimal LDAP server for credential capture and JNDI exploitation.
type LDAPServer struct {
	IP           string
	Port         int
	Hub          *ws.Hub
	WebHook      *webhook.Webhook
	JNDIEnabled  bool   // when true, respond to any search with a JNDI entry using baseDN as class name
	JNDICodeBase string // HTTP URL where the .class file is served from
	Wordlist     string // optional path to a wordlist for NTLM hash cracking
}

func NewLDAPServer(opts *options.Options, hub *ws.Hub, wh *webhook.Webhook) *LDAPServer {
	var codeBase string
	if opts.LDAPJNDIEnabled {
		if opts.LDAPJNDIBase != "" {
			codeBase = opts.LDAPJNDIBase
		} else {
			scheme := "http"
			if opts.SSL {
				scheme = "https"
			}
			ip := opts.IP
			if ip == "0.0.0.0" || ip == "::" {
				ip = "127.0.0.1"
			}
			codeBase = fmt.Sprintf("%s://%s:%d/", scheme, ip, opts.Port)
		}
	}
	return &LDAPServer{
		IP:           opts.IP,
		Port:         opts.LDAPPort,
		Hub:          hub,
		WebHook:      wh,
		JNDIEnabled:  opts.LDAPJNDIEnabled,
		JNDICodeBase: codeBase,
		Wordlist:     opts.LDAPWordlist,
	}
}

func (s *LDAPServer) Start() {
	addr := fmt.Sprintf("%s:%d", s.IP, s.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Fatalf("LDAP server failed to listen on %s: %v", addr, err)
		return
	}
	logger.Infof("LDAP server listening on %s", addr)
	if s.JNDIEnabled {
		logger.Infof("LDAP JNDI mode enabled: codeBase=%s", s.JNDICodeBase)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Errorf("LDAP accept error: %v", err)
			continue
		}
		go newSession(conn, s).handle()
	}
}
