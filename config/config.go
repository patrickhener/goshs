package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/patrickhener/goshs/logger"
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
}

func Load(configpath string) (Config, error) {
	var cfg Config

	cfile, err := os.ReadFile(configpath)
	if err != nil {
		return Config{}, err
	}

	if err = json.Unmarshal(cfile, &cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
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
	}

	b, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func SanityChecks(webroot string, configpath string, AuthPassword string) error {
	if webroot == filepath.Dir(configpath) {
		logger.Warn("You are hosting your config file in the webroot of goshs. This is not recommended.")
		// Check if the process user can write the config file
		file, err := os.OpenFile(configpath, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		file.Close()
		return fmt.Errorf("%s", "The config file is accessible via goshs and is writeable by the user running goshs. This is a security issue. Read the docs at https://goshs.de/en/usage/config/index.html")
	}

	if !strings.HasPrefix(AuthPassword, "$2a$") {
		logger.Warn("The password in the config file is not hashed. This is not recommended. Use goshs -H to hash the password.")
	}

	return nil
}
