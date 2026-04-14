package server

import (
	"goshs.de/goshs/v2/clipboard"
	"goshs.de/goshs/v2/dnsserver"
	"goshs.de/goshs/v2/httpserver"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/sftpserver"
	"goshs.de/goshs/v2/smbserver"
	"goshs.de/goshs/v2/smtpserver"
	"goshs.de/goshs/v2/utils"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
)

func StartAll(opts *options.Options) {
	// Init clipboard and hub
	clip := clipboard.New()
	hub := ws.NewHub(clip, opts.CLI)
	go hub.Run()

	// Whitelist and Webhook
	wl, wh := registerWhitelistWebhook(opts)

	// http
	httpSrv := httpserver.NewHttpServer(opts, hub, clip, wl, *wh)
	go httpSrv.Start("web")

	// webdav
	if opts.WebDav {
		webdavSrv := httpserver.NewHttpServer(opts, hub, clip, wl, *wh)
		webdavSrv.WebdavPort = opts.WebDavPort
		go webdavSrv.Start("webdav")
	}

	if opts.SFTP {
		sftpSrv := sftpserver.NewSFTPServer(opts, wl, *wh)
		go sftpSrv.Start()
	}

	if opts.DNS {
		dnsSrv := dnsserver.NewDNSServer(opts, hub, wh)
		go dnsSrv.Start()
	}

	if opts.SMTP {
		smtpServer := smtpserver.NewSMTP(opts, hub, wh)
		go smtpServer.Start()
	}

	if opts.SMB {
		smbServer := smbserver.NewSMBServer(opts, hub, wh)
		go smbServer.Start()
	}

	// Zeroconf mDNS
	if opts.MDNS {
		err := utils.RegisterZeroconfMDNS(opts.SSL, opts.Port, opts.WebDav, opts.WebDavPort, opts.SFTP, opts.SFTPPort)
		if err != nil {
			logger.Warnf("error registering zeroconf mDNS: %+v", err)
		}
	}
}

func registerWhitelistWebhook(opts *options.Options) (wl *httpserver.Whitelist, wh *webhook.Webhook) {
	// Parse IP whitelist
	enabled := false
	if opts.Whitelist != "" {
		logger.Infof("Whitelist activated: %+v", opts.Whitelist)
		enabled = true
	}

	// Register Whitelist
	wl, err := httpserver.NewIPWhitelist(opts.Whitelist, enabled, opts.TrustedProxies)
	if err != nil {
		logger.Warnf("Error parsing IP whitelist: %+v", err)
	}

	// Register webhook
	webh := webhook.Register(opts.WebhookEnabled, opts.WebhookURL, opts.WebhookProvider, opts.WebhookEventsParsed)

	return wl, webh
}
