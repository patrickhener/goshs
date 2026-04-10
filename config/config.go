package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/patrickhener/goshs/logger"
	"github.com/patrickhener/goshs/options"
)

type Config struct {
	Interface           string   `json:"interface"`
	Port                int      `json:"port"`
	Directory           string   `json:"directory"`
	UploadFolder        string   `json:"upload_folder"`
	SSL                 bool     `json:"ssl"`
	SelfSigned          bool     `json:"self_signed"`
	PrivateKey          string   `json:"private_key"`
	Certificate         string   `json:"certificate"`
	P12                 string   `json:"p12"`
	P12NoPass           bool     `json:"p12_no_pass"`
	LetsEncrypt         bool     `json:"letsencrypt"`
	LetsEncryptDomain   string   `json:"letsencrypt_domain"`
	LetsEncryptEmail    string   `json:"letsencrypt_email"`
	LetsEncryptHTTPPort string   `json:"letsencrypt_http_port"`
	LetsEncryptTLSPort  string   `json:"letsencrypt_tls_port"`
	AuthUsername        string   `json:"auth_username"`
	AuthPassword        string   `json:"auth_password"`
	CertificateAuth     string   `json:"certificate_auth"`
	Webdav              bool     `json:"webdav"`
	WebdavPort          int      `json:"webdav_port"`
	UploadOnly          bool     `json:"upload_only"`
	ReadOnly            bool     `json:"read_only"`
	NoClipboard         bool     `json:"no_clipboard"`
	NoDelete            bool     `json:"no_delete"`
	Verbose             bool     `json:"verbose"`
	Silent              bool     `json:"silent"`
	Invisible           bool     `json:"invisible"`
	RunningUser         string   `json:"running_user"`
	CLI                 bool     `json:"cli"`
	Embedded            bool     `json:"embedded"`
	Output              string   `json:"output"`
	WebhookEnabled      bool     `json:"webhook_enabled"`
	WebhookURL          string   `json:"webhook_url"`
	WebhookProvider     string   `json:"webhook_provider"`
	WebhookEvents       []string `json:"webhook_events"`
	SFTP                bool     `json:"sftp"`
	SFTPPort            int      `json:"sftp_port"`
	SFTPKeyFile         string   `json:"sftp_keyfile"`
	SFTPHostKeyFile     string   `json:"sftp_host_keyfile"`
	Whitelist           string   `json:"whitelist"`
	TrustedProxies      string   `json:"trusted_proxies"`
	Tunnel              bool     `json:"tunnel"`
	DNSServer           bool     `json:"dns_server"`
	DNSPort             int      `json:"dns_port"`
	DNSIP               string   `json:"dns_ip"`
	SMTPServer          bool     `json:"smtp_server"`
	SMTPPort            int      `json:"smtp_port"`
	SMTPDomain          string   `json:"smtp_domain"`
	SMBServer           bool     `json:"smb_server"`
	SMBPort             int      `json:"smb_port"`
	SMBDomain           string   `json:"smb_domain"`
	SMBShare            string   `json:"smb_share"`
}

func LoadConfig(opts *options.Options) (*options.Options, error) {
	var cfg Config

	absPath, err := filepath.Abs(opts.ConfigFile)
	if err != nil {
		logger.Fatalf("Failed to get absolute path of config file: %+v", err)
		return opts, err
	}
	logger.Infof("Using config file %s", absPath)
	opts.ConfigPath = absPath

	cfile, err := os.ReadFile(absPath)
	if err != nil {
		return opts, err
	}

	if err = json.Unmarshal(cfile, &cfg); err != nil {
		return opts, err
	}

	// Set the config values
	opts.IP = cfg.Interface
	opts.Port = cfg.Port
	opts.Webroot = cfg.Directory
	opts.UploadFolder = cfg.UploadFolder
	opts.SSL = cfg.SSL
	opts.SelfSigned = cfg.SelfSigned
	opts.MyKey = cfg.PrivateKey
	opts.MyCert = cfg.Certificate
	opts.MyP12 = cfg.P12
	opts.P12NoPass = cfg.P12NoPass
	opts.LetsEncrypt = cfg.LetsEncrypt
	opts.LEDomains = cfg.LetsEncryptDomain
	opts.LEEmail = cfg.LetsEncryptEmail
	opts.LEHTTPPort = cfg.LetsEncryptHTTPPort
	opts.LETLSPort = cfg.LetsEncryptTLSPort
	opts.BasicAuth = cfg.AuthUsername + ":" + cfg.AuthPassword
	opts.CertAuth = cfg.CertificateAuth
	opts.WebDav = cfg.Webdav
	opts.WebDavPort = cfg.WebdavPort
	opts.UploadOnly = cfg.UploadOnly
	opts.ReadOnly = cfg.ReadOnly
	opts.NoClipboard = cfg.NoClipboard
	opts.NoDelete = cfg.NoDelete
	opts.Verbose = cfg.Verbose
	opts.Silent = cfg.Silent
	opts.DropUser = cfg.RunningUser
	opts.CLI = cfg.CLI
	opts.Embedded = cfg.Embedded
	opts.Output = cfg.Output
	opts.WebhookEnabled = cfg.WebhookEnabled
	opts.WebhookURL = cfg.WebhookURL
	opts.WebhookProvider = cfg.WebhookProvider
	opts.WebhookEventsParsed = cfg.WebhookEvents
	opts.SFTP = cfg.SFTP
	opts.SFTPPort = cfg.SFTPPort
	opts.SFTPKeyFile = cfg.SFTPKeyFile
	opts.SFTPHostKeyFile = cfg.SFTPHostKeyFile
	opts.Whitelist = cfg.Whitelist
	opts.TrustedProxies = cfg.TrustedProxies
	opts.Invisible = cfg.Invisible
	opts.Tunnel = cfg.Tunnel
	opts.DNS = cfg.DNSServer
	opts.DNSPort = cfg.DNSPort
	opts.DNSIP = cfg.DNSIP
	opts.SMTP = cfg.SMTPServer
	opts.SMTPPort = cfg.SMTPPort
	opts.SMTPDomain = cfg.SMTPDomain
	opts.SMB = cfg.SMBServer
	opts.SMBPort = cfg.SMBPort
	opts.SMBDomain = cfg.SMBDomain
	opts.SMBShare = cfg.SMBShare

	return opts, nil
}

func PrintExample() (string, error) {
	defaultConfig := Config{
		Interface:           "0.0.0.0",
		Port:                8000,
		Directory:           ".",
		UploadFolder:        ".",
		SSL:                 false,
		SelfSigned:          false,
		PrivateKey:          "",
		Certificate:         "",
		P12:                 "",
		P12NoPass:           false,
		LetsEncrypt:         false,
		LetsEncryptDomain:   "",
		LetsEncryptEmail:    "",
		LetsEncryptHTTPPort: "80",
		LetsEncryptTLSPort:  "443",
		AuthUsername:        "",
		AuthPassword:        "",
		CertificateAuth:     "",
		Webdav:              false,
		WebdavPort:          8001,
		UploadOnly:          false,
		ReadOnly:            false,
		NoClipboard:         false,
		NoDelete:            false,
		Verbose:             false,
		Silent:              false,
		Invisible:           false,
		RunningUser:         "",
		CLI:                 false,
		Embedded:            false,
		Output:              "",
		WebhookEnabled:      false,
		WebhookURL:          "",
		WebhookProvider:     "discord",
		WebhookEvents:       []string{"all"},
		SFTP:                false,
		SFTPPort:            2022,
		SFTPKeyFile:         "",
		SFTPHostKeyFile:     "",
		Whitelist:           "",
		TrustedProxies:      "",
		Tunnel:              false,
		DNSServer:           false,
		DNSPort:             8053,
		DNSIP:               "127.0.0.1",
		SMTPServer:          false,
		SMTPPort:            25,
		SMTPDomain:          "",
		SMBServer:           false,
		SMBPort:             445,
		SMBDomain:           "",
		SMBShare:            "",
	}

	b, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
