package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	Interface           string `json:"interface"`
	Port                int    `json:"port"`
	Directory           string `json:"directory"`
	SSL                 bool   `json:"ssl"`
	SelfSigned          bool   `json:"self_signed"`
	PrivateKey          string `json:"private_key"`
	Certificate         string `json:"certificate"`
	P12                 string `json:"p12"`
	LetsEncrypt         bool   `json:"letsencrypt"`
	LetsEncryptDomain   string `json:"letsencrypt_domain"`
	LetsEncryptEmail    string `json:"letsencrypt_email"`
	LetsEncryptHTTPPort string `json:"letsencrypt_http_port"`
	LetsEncryptTLSPort  string `json:"letsencrypt_tls_port"`
	AuthUsername        string `json:"auth_username"`
	AuthPassword        string `json:"auth_password"`
	CertificateAuth     string `json:"certificate_auth"`
	Webdav              bool   `json:"webdav"`
	WebdavPort          int    `json:"webdav_port"`
	UploadOnly          bool   `json:"upload_only"`
	ReadOnly            bool   `json:"read_only"`
	NoClipboard         bool   `json:"no_clipboard"`
	Verbose             bool   `json:"verbose"`
	Silent              bool   `json:"silent"`
	RunningUser         string `json:"running_user"`
	CLI                 bool   `json:"cli"`
	Embedded            bool   `json:"embedded"`
	Output              string `json:"output"`
}

func Load(configpath string) (Config, error) {
	var cfg Config

	cfile, err := os.ReadFile(configpath)
	if err != nil {
		return Config{}, err
	}

	if err = json.Unmarshal(cfile, &cfg); err != nil {
		return Config{}, nil
	}

	return cfg, nil
}

func PrintExample() {
	defaultConfig := Config{
		Interface:           "0.0.0.0",
		Port:                8000,
		Directory:           ".",
		SSL:                 false,
		SelfSigned:          false,
		PrivateKey:          "",
		Certificate:         "",
		P12:                 "",
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
		Verbose:             false,
		Silent:              false,
		RunningUser:         "",
		CLI:                 false,
		Embedded:            false,
		Output:              "",
	}

	b, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}
