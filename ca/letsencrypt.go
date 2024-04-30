package ca

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/patrickhener/goshs/logger"
)

// LetsEncryptUser is the struct of all information needed to rollout a lets encrypt certificate
type LetsEncryptUser struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
	HTTPPort     string
	TLSPort      string
	Domains      []string
	Config       *lego.Config
	Client       *lego.Client
}

// GetEmail will return the Users Email
func (u *LetsEncryptUser) GetEmail() string {
	return u.Email
}

// Get Registration will return the Registration
func (u *LetsEncryptUser) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey will return the Private Key
func (u *LetsEncryptUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func (u *LetsEncryptUser) RequestCertificate() ([]byte, []byte) {
	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Fatalf("error generating private key for lets encrypt: %+v", err)
	}

	u.Key = privateKey

	u.Config = lego.NewConfig(u)

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	u.Config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	u.Client, err = lego.NewClient(u.Config)
	if err != nil {
		logger.Fatalf("error retrieving client for communication with lets encrypt acme server: %+v", err)
	}

	err = u.Client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", u.TLSPort))
	if err != nil {
		logger.Fatalf("error setting tls alpn provider for lets encrypt: %+v", err)
	}

	err = u.Client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", u.HTTPPort))
	if err != nil {
		logger.Fatalf("error setting http provider for lets encrypt: %+v", err)
	}

	// New users will need to register
	reg, err := u.Client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		logger.Fatalf("error registering new user with lets encrypt: %+v", err)
	}
	u.Registration = reg

	request := certificate.ObtainRequest{
		Domains: u.Domains,
		Bundle:  true,
	}

	certificates, err := u.Client.Certificate.Obtain(request)
	if err != nil {
		logger.Fatalf("error registering domain(s) with lets encrypt: %+v", err)
	}

	return certificates.PrivateKey, certificates.Certificate
}

func GetLECertificateAndKey(email string, domains []string, httpPort string, tlsPort string) {
	// Get email if none provided
	if email == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Provide E-Mail to use with Let's Encrypt: ")
		resultEmail, err := reader.ReadString('\n')
		if err != nil {
			logger.Fatalf("error reading email from stdin: %+v", err)
		}
		email = strings.Trim(resultEmail, "\n")
	}

	// Get domains if none are provided
	if domains[0] == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Provide domain(s) to request with Let's Encrypt: ")
		resultDomains, err := reader.ReadString('\n')
		if err != nil {
			logger.Fatalf("error reading domains from stdin: %+v", err)
		}
		resultDomains = strings.Trim(resultDomains, "\n")
		domains = strings.Split(resultDomains, ",")
	}

	// construct letsencrypt user object
	letsencryptUser := LetsEncryptUser{
		Email:    email,
		HTTPPort: httpPort,
		TLSPort:  tlsPort,
		Domains:  domains,
	}

	key, cert := letsencryptUser.RequestCertificate()

	err := os.WriteFile("key", key, 0644)
	if err != nil {
		logger.Fatalf("error writing file 'key': %+v", err)
	}

	err = os.WriteFile("cert", cert, 0644)
	if err != nil {
		logger.Fatalf("error writing file 'cert': %+v", err)
	}
}
