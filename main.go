package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/howeyc/gopass"
	"github.com/patrickhener/goshs/ca"
	"github.com/patrickhener/goshs/config"
	"github.com/patrickhener/goshs/goshsversion"
	"github.com/patrickhener/goshs/httpserver"
	"github.com/patrickhener/goshs/logger"
	"github.com/patrickhener/goshs/sftpserver"
	"github.com/patrickhener/goshs/update"
	"github.com/patrickhener/goshs/utils"
	"github.com/patrickhener/goshs/webhook"
)

var (
	port                = 8000
	ip                  = "0.0.0.0"
	cli                 = false
	webroot             = "."
	uploadFolder        = ""
	ssl                 = false
	selfsigned          = false
	letsencrypt         = false
	myKey               = ""
	myCert              = ""
	myP12               = ""
	p12NoPass           = false
	basicAuth           = ""
	certAuth            = ""
	webdav              = false
	webdavPort          = 8001
	sftp                = false
	sftpPort            = 2022
	sftpKeyfile         = ""
	sftpHostKeyfile     = ""
	uploadOnly          = false
	readOnly            = false
	noClipboard         = false
	noDelete            = false
	verbose             = false
	silent              = false
	dropuser            = ""
	leEmail             = ""
	leDomains           = ""
	leHTTPPort          = "80"
	leTLSPort           = "443"
	embedded            = false
	output              = ""
	configFile          = ""
	webhookEnable       = false
	webhookURL          = ""
	webhookEvents       = "all"
	webhookProvider     = "Discord"
	webhookEventsParsed = []string{}
	whitelist           = ""
	trustedProxies      = ""
	MDNS                = false
)

// Man page
func usage() func() {
	return func() {
		fmt.Printf(`
goshs %s
Usage: %s [options]

Web server options:
  -i,  --ip             IP or Interface to listen on            (default: 0.0.0.0)
  -p,  --port           The port to listen on                   (default: 8000)
  -d,  --dir            The web root directory                  (default: current working path)
  -w,  --webdav         Also serve using webdav protocol        (default: false)
  -wp, --webdav-port    The port to listen on for webdav        (default: 8001)
  -ro, --read-only      Read only mode, no upload possible      (default: false)
  -uo, --upload-only    Upload only mode, no download possible  (default: false)
  -uf, --upload-folder  Specify a different upload folder       (default: current working path)
  -nc, --no-clipboard   Disable the clipboard sharing           (default: false)
  -nd, --no-delete      Disable the delete option               (default: false)
  -si, --silent         Running without dir listing             (default: false)
  -c,  --cli            Enable cli (only with auth and tls)     (default: false)
  -e,  --embedded       Show embedded files in UI               (default: false)
  -o,  --output         Write output to logfile                 (default: false)

TLS options:
  -s,     --ssl           Use TLS
  -ss,    --self-signed   Use a self-signed certificate
  -sk,    --server-key    Path to server key
  -sc,    --server-cert   Path to server certificate
  -p12,   --pkcs12        Path to server p12
  -p12np, --p12-no-pass   Server p12 has empty password
  -sl,    --lets-encrypt  Use Let's Encrypt as certification service
  -sld,   --le-domains    Domain(s) to request from Let's Encrypt		(comma separated list)
  -sle,   --le-email      Email to use with Let's Encrypt
  -slh,   --le-http       Port to use for Let's Encrypt HTTP Challenge	(default: 80)
  -slt,   --le-tls        Port to use for Let's Encrypt TLS ALPN Challenge (default: 443)

SFTP server options:
  -sftp                        Activate SFTP server capabilities (default: false)
  -sp,    --sftp-port          The port SFTP listens on          (default: 2022)
  -skf,   --sftp-keyfile       Authorized_keys file for pubkey auth
  -shk,   --sftp-host-keyfile  SSH Host key file for identification

Authentication options:
  -b,  --basic-auth     Use basic authentication (user:pass - user can be empty)
  -ca, --cert-auth      Use certificate based authentication - provide ca certificate
  -H,  --hash           Hash a password for file based ACLs

Connection restriction:
  -ipw, --ip-whitelist             Comma separated list of IPs to whitelist
  -tpw, --trusted-proxy-whitelist  Comma separated list of trusted proxies

Webhook options:
  -W,  --webhook            Enable webhook support                                       (default: false)
  -Wu, --webhook-url        URL to send webhook requests to
  -We, --webhook-events     Comma separated list of events to notify
                            [all, upload, delete, download, view, webdav, sftp, verbose] (default: all)
  -Wp, --webhook-provider   Webhook provider
                            [Discord, Mattermost, Slack]                                 (default: Discord)

Misc options:
  -C  --config        Provide config file path                (default: false)
  -P  --print-config  Print sample config to STDOUT           (default: false)
  -u  --user          Drop privs to user (unix only)          (default: current user)
      --update        Update goshs to most recent version
  -m  --mdns          Disable zeroconf mDNS registration      (default: false)
  -V  --verbose       Activate verbose log output             (default: false)
  -v                  Print the current goshs version

Usage examples:
  Start with default values:    	./goshs
  Start with config file:    	        ./goshs -C /path/to/config.yaml
  Start with wevdav support:    	./goshs -w
  Start with different port:    	./goshs -p 8080
  Start with self-signed cert:  	./goshs -s -ss
  Start with let's encrypt:		./goshs -s -sl -sle your@mail.com -sld your.domain.com,your.seconddomain.com
  Start with custom cert:       	./goshs -s -sk <path to key> -sc <path to cert>
  Start with basic auth:        	./goshs -b 'secret-user:$up3r$3cur3'
  Start with basic auth bcrypt hash:   	./goshs -b 'secret-user:$2a$14$ydRJ//Ob4SctB/D7o.rvU.LmPs/vwXkeXCbtpCqzgOJDSShLgiY52'
  Start with basic auth empty user:	./goshs -b ':$up3r$3cur3'
  Start with cli enabled:           	./goshs -b 'secret-user:$up3r$3cur3' -s -ss -c

`, goshsversion.GoshsVersion, os.Args[0])
	}
}

func flags() (*bool, *bool, *bool, *bool, *bool, *bool) {
	wd, _ := os.Getwd()

	flag.StringVar(&configFile, "C", configFile, "config")
	flag.StringVar(&configFile, "config", configFile, "config")
	flag.StringVar(&ip, "i", ip, "ip")
	flag.StringVar(&ip, "ip", ip, "ip")
	flag.IntVar(&port, "p", port, "port")
	flag.IntVar(&port, "port", port, "port")
	flag.StringVar(&webroot, "d", wd, "web root")
	flag.StringVar(&webroot, "dir", wd, "web root")
	flag.BoolVar(&ssl, "s", ssl, "tls")
	flag.BoolVar(&ssl, "ssl", ssl, "tls")
	flag.BoolVar(&selfsigned, "ss", selfsigned, "self-signed")
	flag.BoolVar(&selfsigned, "self-signed", selfsigned, "self-signed")
	flag.StringVar(&myKey, "sk", myKey, "server key")
	flag.StringVar(&myKey, "server-key", myKey, "server key")
	flag.StringVar(&myCert, "sc", myCert, "server cert")
	flag.StringVar(&myCert, "server-cert", myCert, "server cert")
	flag.StringVar(&myP12, "p12", myP12, "server p12")
	flag.StringVar(&myP12, "pkcs12", myP12, "server p12")
	flag.BoolVar(&p12NoPass, "p12np", p12NoPass, "p12 no pass")
	flag.BoolVar(&p12NoPass, "p12-no-pass", p12NoPass, "p12 no pass")
	flag.StringVar(&basicAuth, "b", basicAuth, "basic auth")
	flag.StringVar(&basicAuth, "basic-auth", basicAuth, "basic auth")
	flag.StringVar(&certAuth, "ca", certAuth, "cert auth")
	flag.StringVar(&certAuth, "cert-auth", certAuth, "cert auth")
	flag.BoolVar(&webdav, "w", webdav, "enable webdav")
	flag.BoolVar(&webdav, "webdav", webdav, "enable webdav")
	flag.IntVar(&webdavPort, "wp", webdavPort, "webdav port")
	flag.IntVar(&webdavPort, "webdav-port", webdavPort, "webdav port")
	flag.BoolVar(&uploadOnly, "uo", uploadOnly, "upload only")
	flag.BoolVar(&uploadOnly, "upload-only", uploadOnly, "upload only")
	flag.BoolVar(&readOnly, "ro", readOnly, "read only")
	flag.BoolVar(&readOnly, "read-only", readOnly, "read only")
	flag.BoolVar(&noClipboard, "nc", noClipboard, "")
	flag.BoolVar(&noClipboard, "no-clipboard", noClipboard, "")
	flag.BoolVar(&noDelete, "nd", noDelete, "")
	flag.BoolVar(&noDelete, "no-delete", noDelete, "")
	flag.BoolVar(&verbose, "V", verbose, "verbose")
	flag.BoolVar(&verbose, "verbose", verbose, "verbose")
	flag.BoolVar(&silent, "si", silent, "silent")
	flag.BoolVar(&silent, "silent", silent, "silent")
	flag.StringVar(&dropuser, "u", dropuser, "user")
	flag.StringVar(&dropuser, "user", dropuser, "user")
	flag.BoolVar(&cli, "c", cli, "cli")
	flag.BoolVar(&cli, "cli", cli, "cli")
	flag.BoolVar(&letsencrypt, "sl", letsencrypt, "letsencrypt")
	flag.BoolVar(&letsencrypt, "lets-encrypt", letsencrypt, "letsencrypt")
	flag.StringVar(&leDomains, "sld", leDomains, "")
	flag.StringVar(&leDomains, "le-domains", leDomains, "")
	flag.StringVar(&leEmail, "sle", leEmail, "")
	flag.StringVar(&leEmail, "le-email", leEmail, "")
	flag.StringVar(&leHTTPPort, "slh", leHTTPPort, "")
	flag.StringVar(&leHTTPPort, "le-http", leHTTPPort, "")
	flag.StringVar(&leTLSPort, "slt", leTLSPort, "")
	flag.StringVar(&leTLSPort, "le-tls", leTLSPort, "")
	flag.BoolVar(&embedded, "e", embedded, "")
	flag.BoolVar(&embedded, "embedded", embedded, "")
	flag.StringVar(&output, "o", output, "")
	flag.StringVar(&output, "output", output, "")
	flag.BoolVar(&webhookEnable, "W", webhookEnable, "")
	flag.BoolVar(&webhookEnable, "webhook", webhookEnable, "")
	flag.StringVar(&webhookURL, "Wu", webhookURL, "")
	flag.StringVar(&webhookURL, "webhook-url", webhookURL, "")
	flag.StringVar(&webhookEvents, "We", webhookEvents, "")
	flag.StringVar(&webhookEvents, "webhook-events", webhookEvents, "")
	flag.StringVar(&webhookProvider, "Wp", webhookProvider, "")
	flag.StringVar(&webhookProvider, "webhook-provider", webhookProvider, "")
	flag.BoolVar(&sftp, "sftp", sftp, "sftp")
	flag.IntVar(&sftpPort, "sp", sftpPort, "sftp port")
	flag.IntVar(&sftpPort, "sftp-port", sftpPort, "sftp port")
	flag.StringVar(&sftpKeyfile, "skf", sftpKeyfile, "")
	flag.StringVar(&sftpKeyfile, "sftp-keyfile", sftpKeyfile, "")
	flag.StringVar(&sftpHostKeyfile, "shk", sftpHostKeyfile, "")
	flag.StringVar(&sftpHostKeyfile, "sftp-host-keyfile", sftpHostKeyfile, "")
	flag.StringVar(&whitelist, "ipw", whitelist, "")
	flag.StringVar(&whitelist, "ip-whitelist", whitelist, "")
	flag.StringVar(&trustedProxies, "tpw", trustedProxies, "")
	flag.StringVar(&trustedProxies, "trusted-proxy-whitelist", trustedProxies, "")
	flag.StringVar(&uploadFolder, "uf", uploadFolder, "")
	flag.StringVar(&uploadFolder, "upload-folder", uploadFolder, "")
	flag.BoolVar(&MDNS, "m", MDNS, "Enable zeroconf mDNS registration")
	flag.BoolVar(&MDNS, "mdns", MDNS, "Enable zeroconf mDNS registration")

	updateGoshs := flag.Bool("update", false, "update")
	hash := flag.Bool("H", false, "hash")
	hashLong := flag.Bool("hash", false, "hash")
	version := flag.Bool("v", false, "goshs version")
	printConfig := flag.Bool("P", false, "print config")
	printConfigLong := flag.Bool("print-config", false, "print config")

	flag.Usage = usage()

	flag.Parse()

	return hash, hashLong, version, updateGoshs, printConfig, printConfigLong
}

func resolveInterface() {
	// Check if interface name was provided as -i
	// If so, resolve to ip address of interface
	if !strings.Contains(ip, ".") {
		addr, err := utils.GetInterfaceIpv4Addr(ip)
		if err != nil {
			logger.Fatal(err)
			os.Exit(-1)
		}

		if addr == "" {
			logger.Fatal("IP address cannot be found for provided interface")
			os.Exit(-1)
		}

		ip = addr
	}
}

func sanityChecks() {
	// Sanity check for upload only vs read only
	if uploadOnly && readOnly {
		logger.Fatal("You can only select either 'upload only' or 'read only', not both.")
	}

	// Sanity check if cli mode is combined with auth and tls
	if cli && (!ssl || basicAuth == "") {
		if cli && (!ssl || certAuth == "") {
			logger.Fatal("With cli mode you need to enable basic/cert auth and tls for security reasons.")
		}
	}

	// Sanity check if CA mode enabled you will also need TLS enabled in some way
	if certAuth != "" && !ssl {
		logger.Fatal("To use certificate based authentication with a CA cert you will need tls in any mode (-ss, -sk/-sc, -p12, -sl)")
	}

	// Sanity check either user:pass or keyfile when using sftp
	if sftp && (basicAuth == "" && sftpKeyfile == "") {
		logger.Fatal("When using SFTP you need to either specify an authorized keyfile using -sfk or username and password using -b")
	}
}

// Flag handling
func init() {
	wd, _ := os.Getwd()

	// flags
	hash, hashLong, version, updateGoshs, printConfig, printConfigLong := flags()

	// Parse WebhookEvents to a slice
	webhookEventsParsed = strings.Split(webhookEvents, ",")

	for i, event := range webhookEventsParsed {
		webhookEventsParsed[i] = strings.TrimSpace(strings.ToLower(event))
	}

	if *updateGoshs {
		err := update.UpdateTool(goshsversion.GoshsVersion)
		if err != nil {
			logger.Fatalf("Failed to update tool: %+v", err)
		}
	}

	if *version {
		fmt.Printf("goshs version is: %+v\n", goshsversion.GoshsVersion)
		os.Exit(0)
	}

	if *hash || *hashLong {
		fmt.Printf("Enter password: ")
		password, err := gopass.GetPasswdMasked()
		if err != nil {
			logger.Fatalf("error reading password from stdin: %+v", err)
		}
		utils.GenerateHashedPassword(password)
		os.Exit(0)
	}

	if *printConfig || *printConfigLong {
		config, err := config.PrintExample()
		if err != nil {
			panic(err)
		}
		fmt.Println(config)
		os.Exit(0)
	}

	// Set uploadFolder to webroot if not set
	if uploadFolder == "" {
		uploadFolder = webroot
	}

	if configFile != "" {
		cfg, err := config.Load(configFile)
		if err != nil {
			logger.Fatalf("Failed to load config file: %+v", err)
		}

		absPath, err := filepath.Abs(configFile)
		if err != nil {
			logger.Fatalf("Failed to get absolute path of config file: %+v", err)
		}
		logger.Infof("Using config file %s", absPath)

		// Set the config values
		ip = cfg.Interface
		port = cfg.Port
		webroot = cfg.Directory
		uploadFolder = cfg.UploadFolder
		ssl = cfg.SSL
		selfsigned = cfg.SelfSigned
		myKey = cfg.PrivateKey
		myCert = cfg.Certificate
		myP12 = cfg.P12
		p12NoPass = cfg.P12NoPass
		letsencrypt = cfg.LetsEncrypt
		leDomains = cfg.LetsEncryptDomain
		leEmail = cfg.LetsEncryptEmail
		leHTTPPort = cfg.LetsEncryptHTTPPort
		leTLSPort = cfg.LetsEncryptTLSPort
		basicAuth = cfg.AuthUsername + ":" + cfg.AuthPassword
		certAuth = cfg.CertificateAuth
		webdav = cfg.Webdav
		webdavPort = cfg.WebdavPort
		uploadOnly = cfg.UploadOnly
		readOnly = cfg.ReadOnly
		noClipboard = cfg.NoClipboard
		noDelete = cfg.NoDelete
		verbose = cfg.Verbose
		silent = cfg.Silent
		dropuser = cfg.RunningUser
		cli = cfg.CLI
		embedded = cfg.Embedded
		output = cfg.Output
		webhookEnable = cfg.WebhookEnabled
		webhookURL = cfg.WebhookURL
		webhookProvider = cfg.WebhookProvider
		webhookEventsParsed = cfg.WebhookEvents
		sftp = cfg.SFTP
		sftpPort = cfg.SFTPPort
		sftpKeyfile = cfg.SFTPKeyFile
		sftpHostKeyfile = cfg.SFTPHostKeyFile
		whitelist = cfg.Whitelist
		trustedProxies = cfg.TrustedProxies

		// Abspath for webroot
		// Trim trailing / for linux/mac and \ for windows
		webroot = strings.TrimSuffix(webroot, "/")
		webroot = strings.TrimSuffix(webroot, "\\")
		if !filepath.IsAbs(webroot) {
			webroot, err = filepath.Abs(filepath.Join(wd, webroot))
			if err != nil {
				logger.Fatalf("Webroot cannot be constructed: %+v", err)
			}
		}

		// Sanity checking the config file
		if err := config.SanityChecks(webroot, absPath, cfg.AuthPassword); err != nil {
			logger.Fatal(err)
		}
	}

	// Resolve Interface
	resolveInterface()

	// Sanity checks
	sanityChecks()

	// Abspath for webroot
	var err error
	// Trim trailing / for linux/mac and \ for windows
	webroot = strings.TrimSuffix(webroot, "/")
	webroot = strings.TrimSuffix(webroot, "\\")
	if !filepath.IsAbs(webroot) {
		webroot, err = filepath.Abs(filepath.Join(wd, webroot))
		if err != nil {
			logger.Fatalf("Webroot cannot be constructed: %+v", err)
		}
	}

	if webdav {
		logger.Warn("upload/read-only/no-delete/upload-folder mode deactivated due to use of 'webdav' mode")
		uploadFolder = webroot
		uploadOnly = false
		readOnly = false
		noDelete = false
	}

	if sftp {
		logger.Warn("upload-folder mode deactivated due to use of 'sftp' mode")
		uploadFolder = webroot
	}
}

// Sanity checks if basic auth has the right format
func parseBasicAuth() (string, string) {
	auth := strings.SplitN(basicAuth, ":", 2)
	if len(auth) < 2 {
		fmt.Println("Wrong basic auth format. Please provide user:password separated by a colon")
		os.Exit(-1)
	}
	user := auth[0]
	pass := auth[1]
	return user, pass
}

func main() {
	if yes, out := update.CheckForUpdates(goshsversion.GoshsVersion); yes {
		logger.Warnf("There is a newer Version (%s) of goshs available. Run --update to update goshs.", out)
	} else {
		if out != "" {
			logger.Warnf("Failed to check for updates: %+v", out)
		} else {
			logger.Infof("You are running the newest version (%s) of goshs", goshsversion.GoshsVersion)
		}
	}

	user := ""
	pass := ""

	// check for basic auth
	if basicAuth != "" {
		user, pass = parseBasicAuth()
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// If Let's Encrypt is in play we need to fetch the key and cert, write them to disc and set their path in MyKey and MyCert
	if letsencrypt {
		ca.GetLECertificateAndKey(leEmail, strings.Split(leDomains, ","), leHTTPPort, leTLSPort)
		myCert = "cert"
		myKey = "key"
	}

	// If a logpath/-file is provided via -o/--output set the multiwriter to output both
	if output != "" {
		if !filepath.IsAbs(output) {
			// If the provided path is not an abspath then merge with CWD
			wd, _ := os.Getwd()
			output = filepath.Join(wd, output)
		}

		logFile, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			logger.Panicf("Cannot open file to write output logfile: %s - %+v", output, err)
		}

		multiWriter := io.MultiWriter(os.Stdout, logFile)
		logger.LogFile(multiWriter)
	}

	var wl *httpserver.Whitelist
	var err error

	enabled := false
	if whitelist != "" {
		logger.Infof("Whitelist activated: %+v", whitelist)
		enabled = true
	}

	wl, err = httpserver.NewIPWhitelist(whitelist, enabled, trustedProxies)
	if err != nil {
		logger.Warnf("Error parsing IP whitelist: %+v", err)
	}

	// Register webhook
	webhook := webhook.Register(webhookEnable, webhookURL, webhookProvider, webhookEventsParsed)

	// Setup the custom file server
	server := &httpserver.FileServer{
		IP:           ip,
		Port:         port,
		CLI:          cli,
		Webroot:      webroot,
		UploadFolder: uploadFolder,
		SSL:          ssl,
		SelfSigned:   selfsigned,
		LetsEncrypt:  letsencrypt,
		MyCert:       myCert,
		MyKey:        myKey,
		MyP12:        myP12,
		P12NoPass:    p12NoPass,
		User:         user,
		Pass:         pass,
		CACert:       certAuth,
		DropUser:     dropuser,
		UploadOnly:   uploadOnly,
		ReadOnly:     readOnly,
		NoClipboard:  noClipboard,
		NoDelete:     noDelete,
		Silent:       silent,
		Embedded:     embedded,
		Webhook:      *webhook,
		Verbose:      verbose,
		Whitelist:    wl,
		Version:      goshsversion.GoshsVersion,
	}

	// Zeroconf mDNS
	if MDNS {
		err = utils.RegisterZeroconfMDNS(ssl, port, webdav, webdavPort, sftp, sftpPort)
		if err != nil {
			logger.Warnf("error registering zeroconf mDNS: %+v", err)
		}
	}

	// Start web server
	go server.Start("web")

	// Start WebDAV server
	if webdav {
		server.WebdavPort = webdavPort

		go server.Start("webdav")
	}

	// Start SFTP server
	if sftp {
		s := &sftpserver.SFTPServer{
			IP:          ip,
			Port:        sftpPort,
			KeyFile:     sftpKeyfile,
			Username:    user,
			Password:    pass,
			Root:        webroot,
			ReadOnly:    readOnly,
			UploadOnly:  uploadOnly,
			HostKeyFile: sftpHostKeyfile,
			Webhook:     *webhook,
			Whitelist:   wl,
		}

		go s.Start()
	}

	<-done

	logger.Infof("Received CTRL+C, exiting...")
}
