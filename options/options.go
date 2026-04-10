package options

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/patrickhener/goshs/goshsversion"
	"github.com/patrickhener/goshs/logger"
	"github.com/patrickhener/goshs/update"
	"github.com/patrickhener/goshs/utils"
)

type Options struct {
	IP                  string   // "0.0.0.0"
	Port                int      // 8000
	Webroot             string   // "."
	SSL                 bool     // false
	SelfSigned          bool     // false
	MyKey               string   // ""
	MyCert              string   // ""
	MyP12               string   // ""
	P12NoPass           bool     // false
	CLI                 bool     // false
	UploadFolder        string   // ""
	LetsEncrypt         bool     // false
	BasicAuth           string   // ""
	Username            string   // "" will be constructed from BasicAuth
	Password            string   // "" will be constructed from BasicAuth
	CertAuth            string   // ""
	WebDav              bool     // false
	WebDavPort          int      // 8001
	SFTP                bool     // false
	SFTPPort            int      // 2022
	SFTPKeyFile         string   // ""
	SFTPHostKeyFile     string   // ""
	UploadOnly          bool     // false
	ReadOnly            bool     // false
	NoClipboard         bool     // false
	NoDelete            bool     // false
	Verbose             bool     // false
	Silent              bool     // false
	DropUser            string   // ""
	LEEmail             string   // ""
	LEDomains           string   // ""
	LEHTTPPort          string   //"80"
	LETLSPort           string   // "443"
	Embedded            bool     // false
	Output              string   // ""
	ConfigFile          string   // ""
	ConfigPath          string   // "" Will be constructed from ConfigFile
	WebhookEnabled      bool     // false
	WebhookURL          string   // ""
	WebhookEvents       string   // "all"
	WebhookProvider     string   // "Discord"
	WebhookEventsParsed []string // []string{}
	Whitelist           string   // ""
	TrustedProxies      string   // ""
	MDNS                bool     // false
	Invisible           bool     // false
	Tunnel              bool     // false
	DNS                 bool     // false
	DNSPort             int      // 8053
	DNSIP               string   // "127.0.0.1"
	SMTP                bool     // false
	SMTPPort            int      // 2525
	SMTPDomain          string   // ""
	SMB                 bool     // false
	SMBPort             int      // 445
	SMBDomain           string   // ""
	SMBShare            string   // ""
	SMBWordlist         string   // ""
}

func Parse() (*Options, bool) {
	wd, _ := os.Getwd()
	opts := &Options{}

	flag.StringVar(&opts.ConfigFile, "C", "", "config")
	flag.StringVar(&opts.IP, "i", "0.0.0.0", "ip")
	flag.StringVar(&opts.IP, "ip", "0.0.0.0", "ip")
	flag.IntVar(&opts.Port, "p", 8000, "port")
	flag.IntVar(&opts.Port, "port", 8000, "port")
	flag.StringVar(&opts.Webroot, "d", wd, "web root")
	flag.StringVar(&opts.Webroot, "dir", wd, "web root")
	flag.BoolVar(&opts.SSL, "s", false, "tls")
	flag.BoolVar(&opts.SSL, "ssl", false, "tls")
	flag.BoolVar(&opts.SelfSigned, "ss", false, "self-signed")
	flag.BoolVar(&opts.SelfSigned, "self-signed", false, "self-signed")
	flag.StringVar(&opts.MyKey, "sk", "", "server key")
	flag.StringVar(&opts.MyKey, "server-key", "", "server key")
	flag.StringVar(&opts.MyCert, "sc", "", "server cert")
	flag.StringVar(&opts.MyCert, "server-cert", "", "server cert")
	flag.StringVar(&opts.MyP12, "p12", "", "server p12")
	flag.StringVar(&opts.MyP12, "pkcs12", "", "server p12")
	flag.BoolVar(&opts.P12NoPass, "p12np", false, "p12 no pass")
	flag.BoolVar(&opts.P12NoPass, "p12-no-pass", false, "p12 no pass")
	flag.StringVar(&opts.BasicAuth, "b", "", "basic auth")
	flag.StringVar(&opts.BasicAuth, "basic-auth", "", "basic auth")
	flag.StringVar(&opts.CertAuth, "ca", "", "cert auth")
	flag.StringVar(&opts.CertAuth, "cert-auth", "", "cert auth")
	flag.BoolVar(&opts.WebDav, "w", false, "enable webdav")
	flag.BoolVar(&opts.WebDav, "webdav", false, "enable webdav")
	flag.IntVar(&opts.WebDavPort, "wp", 8001, "webdav port")
	flag.IntVar(&opts.WebDavPort, "webdav-port", 8001, "webdav port")
	flag.BoolVar(&opts.UploadOnly, "uo", false, "upload only")
	flag.BoolVar(&opts.UploadOnly, "upload-only", false, "upload only")
	flag.BoolVar(&opts.ReadOnly, "ro", false, "read only")
	flag.BoolVar(&opts.ReadOnly, "read-only", false, "read only")
	flag.BoolVar(&opts.NoClipboard, "nc", false, "")
	flag.BoolVar(&opts.NoClipboard, "no-clipboard", false, "")
	flag.BoolVar(&opts.NoDelete, "nd", false, "")
	flag.BoolVar(&opts.NoDelete, "no-delete", false, "")
	flag.BoolVar(&opts.Verbose, "V", false, "verbose")
	flag.BoolVar(&opts.Verbose, "verbose", false, "verbose")
	flag.BoolVar(&opts.Silent, "si", false, "silent")
	flag.BoolVar(&opts.Silent, "silent", false, "silent")
	flag.StringVar(&opts.DropUser, "u", "", "user")
	flag.StringVar(&opts.DropUser, "user", "", "user")
	flag.BoolVar(&opts.CLI, "c", false, "cli")
	flag.BoolVar(&opts.CLI, "cli", false, "cli")
	flag.BoolVar(&opts.LetsEncrypt, "sl", false, "letsencrypt")
	flag.BoolVar(&opts.LetsEncrypt, "lets-encrypt", false, "letsencrypt")
	flag.StringVar(&opts.LEDomains, "sld", "", "")
	flag.StringVar(&opts.LEDomains, "le-domains", "", "")
	flag.StringVar(&opts.LEEmail, "sle", "", "")
	flag.StringVar(&opts.LEEmail, "le-email", "", "")
	flag.StringVar(&opts.LEHTTPPort, "slh", "80", "")
	flag.StringVar(&opts.LEHTTPPort, "le-http", "80", "")
	flag.StringVar(&opts.LETLSPort, "slt", "443", "")
	flag.StringVar(&opts.LETLSPort, "le-tls", "443", "")
	flag.BoolVar(&opts.Embedded, "e", false, "")
	flag.BoolVar(&opts.Embedded, "embedded", false, "")
	flag.StringVar(&opts.Output, "o", "", "")
	flag.StringVar(&opts.Output, "output", "", "")
	flag.BoolVar(&opts.WebhookEnabled, "W", false, "")
	flag.BoolVar(&opts.WebhookEnabled, "webhook", false, "")
	flag.StringVar(&opts.WebhookURL, "Wu", "", "")
	flag.StringVar(&opts.WebhookURL, "webhook-url", "", "")
	flag.StringVar(&opts.WebhookEvents, "We", "all", "")
	flag.StringVar(&opts.WebhookEvents, "webhook-events", "all", "")
	flag.StringVar(&opts.WebhookProvider, "Wp", "Discord", "")
	flag.StringVar(&opts.WebhookProvider, "webhook-provider", "Discord", "")
	flag.BoolVar(&opts.SFTP, "sftp", false, "sftp")
	flag.IntVar(&opts.SFTPPort, "sp", 2022, "sftp port")
	flag.IntVar(&opts.SFTPPort, "sftp-port", 2022, "sftp port")
	flag.StringVar(&opts.SFTPKeyFile, "skf", "", "")
	flag.StringVar(&opts.SFTPKeyFile, "sftp-keyfile", "", "")
	flag.StringVar(&opts.SFTPHostKeyFile, "shk", "", "")
	flag.StringVar(&opts.SFTPHostKeyFile, "sftp-host-keyfile", "", "")
	flag.StringVar(&opts.Whitelist, "ipw", "", "")
	flag.StringVar(&opts.Whitelist, "ip-whitelist", "", "")
	flag.StringVar(&opts.TrustedProxies, "tpw", "", "")
	flag.StringVar(&opts.TrustedProxies, "trusted-proxy-whitelist", "", "")
	flag.StringVar(&opts.UploadFolder, "uf", "", "")
	flag.StringVar(&opts.UploadFolder, "upload-folder", "", "")
	flag.BoolVar(&opts.MDNS, "m", false, "Enable zeroconf mDNS registration")
	flag.BoolVar(&opts.MDNS, "mdns", false, "Enable zeroconf mDNS registration")
	flag.BoolVar(&opts.Invisible, "I", false, "Enable invisible mode")
	flag.BoolVar(&opts.Invisible, "invisible", false, "Enable invisible mode")
	flag.BoolVar(&opts.Tunnel, "t", false, "Enable tunnel")
	flag.BoolVar(&opts.Tunnel, "tunnel", false, "Enable tunnel")
	flag.BoolVar(&opts.DNS, "dns", false, "Enable DNS server")
	flag.BoolVar(&opts.DNS, "dns-server", false, "Enable DNS server")
	flag.IntVar(&opts.DNSPort, "dns-port", 8053, "DNS server port")
	flag.StringVar(&opts.DNSIP, "dns-ip", "127.0.0.1", "DNS server Reply IP")
	flag.BoolVar(&opts.SMTP, "smtp", false, "Enable SMTP server")
	flag.BoolVar(&opts.SMTP, "smtp-server", false, "Enable SMTP server")
	flag.IntVar(&opts.SMTPPort, "smtp-port", 2525, "SMTP server port")
	flag.StringVar(&opts.SMTPDomain, "smtp-domain", "", "SMTP server domain")
	flag.BoolVar(&opts.SMB, "smb", false, "Enable SMB server")
	flag.BoolVar(&opts.SMB, "smb-server", false, "Enable SMB server")
	flag.IntVar(&opts.SMBPort, "smb-port", 445, "SMB server port")
	flag.StringVar(&opts.SMBDomain, "smb-domain", "GOSHS", "SMB server domain")
	flag.StringVar(&opts.SMBShare, "smb-share", "goshs", "SMB server share")
	flag.StringVar(&opts.SMBWordlist, "smb-wordlist", "", "Wordlist file for SMB hash cracking")

	// One-shot flags
	upd := flag.Bool("update", false, "update")
	printConfig := flag.Bool("P", false, "print config")
	printConfigLong := flag.Bool("print-config", false, "print config")
	hash := flag.Bool("H", false, "hash")
	hashLong := flag.Bool("hash", false, "hash")
	version := flag.Bool("v", false, "goshs version")

	flag.Usage = usage()

	flag.Parse()

	// Check and execute one-shot functions and execute -> early exit
	oneShotFunctions(upd, hash, hashLong, version)

	// Check for print config flag
	if *printConfig || *printConfigLong {
		return opts, true
	}

	opts.WebhookEventsParsed = strings.Split(opts.WebhookEvents, ",")
	for i, event := range opts.WebhookEventsParsed {
		opts.WebhookEventsParsed[i] = strings.TrimSpace(strings.ToLower(event))
	}

	if opts.UploadFolder == "" {
		opts.UploadFolder = opts.Webroot
	}

	opts.IP = resolveInterface(opts.IP)

	return opts, false
}

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
  -I,  --invisible      Invisible mode                          (default: false)
  -c,  --cli            Enable cli (only with auth and tls)     (default: false)
  -e,  --embedded       Show embedded files in UI               (default: false)
  -o,  --output         Write output to logfile                 (default: false)
  -t,  --tunnel         Enable tunnel                           (default: false)

TLS options:
  -s,     --ssl           Use TLS
  -ss,    --self-signed   Use a self-signed certificate
  -sk,    --server-key    Path to server key
  -sc,    --server-cert   Path to server certificate
  -p12,   --pkcs12        Path to server p12
  -p12np, --p12-no-pass   Server p12 has empty password
  -sl,    --lets-encrypt  Use Let's Encrypt as certification service
  -sld,   --le-domains    Domain(s) to request from Let's Encrypt	   (comma separated list)
  -sle,   --le-email      Email to use with Let's Encrypt
  -slh,   --le-http       Port to use for Let's Encrypt HTTP Challenge	   (default: 80)
  -slt,   --le-tls        Port to use for Let's Encrypt TLS ALPN Challenge (default: 443)

SFTP server options:
  -sftp                        Activate SFTP server capabilities (default: false)
  -sp,    --sftp-port          The port SFTP listens on          (default: 2022)
  -skf,   --sftp-keyfile       Authorized_keys file for pubkey auth
  -shk,   --sftp-host-keyfile  SSH Host key file for identification

SMB server options:
  -smb                        Activate SMB server capabilities         (default: false)
  -smb-port,   --smb-port     The port SMB listens on                  (default: 445)
  -smb-domain, --smb-domain   The domain to use for SMB authentication (default: WORKGROUP)
  -smb-share,  --smb-share    The share to use for SMB authentication  (default: goshs)
  -smb-wordlist               Wordlist file for quick hash cracking    (default: none)

Authentication options:
  -b,  --basic-auth     Use basic authentication (user:pass - user can be empty)
  -ca, --cert-auth      Use certificate based authentication - provide ca certificate
  -H,  --hash           Hash a password for file based ACLs

Connection restriction:
  -ipw, --ip-whitelist             Comma separated list of IPs to whitelist
  -tpw, --trusted-proxy-whitelist  Comma separated list of trusted proxies

Collaboration options:
  -dns, --dns-server           Enable DNS server                   (default: false)
  -dns-port, --dns-port        DNS server port                     (default: 8053)
  -dns-ip, --dns-ip            DNS server Reply IP                 (default: 127.0.0.1)
  -smtp, --smtp-server         Enable SMTP server                  (default: false)
  -smtp-port, --smtp-port      SMTP server port                    (default: 2525)
  -smtp-domain, --smtp-domain  SMTP server domain                  (default: open relay)

Webhook options:
  -W,  --webhook            Enable webhook support                      (default: false)
  -Wu, --webhook-url        URL to send webhook requests to
  -We, --webhook-events     Comma separated list of events to notify
                            [all, upload, delete, download, view, webdav,
                            sftp, dns, smtp, verbose] 	  		(default: all)
  -Wp, --webhook-provider   Webhook provider
                            [Discord, Mattermost, Slack]                (default: Discord)

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

func oneShotFunctions(upd, hash, hashLong, version *bool) {
	// Check for update flag
	if *upd {
		err := update.UpdateTool(goshsversion.GoshsVersion)
		if err != nil {
			logger.Fatalf("Failed to update tool: %+v", err)
		}
	}

	// Check for hash flag
	if *hash || *hashLong {
		fmt.Printf("Enter password: ")
		password, err := gopass.GetPasswdMasked()
		if err != nil {
			logger.Fatalf("error reading password from stdin: %+v", err)
		}
		utils.GenerateHashedPassword(password)
		os.Exit(0)
	}
	//
	// Check for version flag
	if *version {
		fmt.Printf("goshs version is: %+v\n", goshsversion.GoshsVersion)
		os.Exit(0)
	}

}

func resolveInterface(ip string) string {
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

		return addr
	}
	return ip
}
