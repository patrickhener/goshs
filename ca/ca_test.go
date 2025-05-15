package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/stretchr/testify/require"
)

const (
	certSha256 string = "65853DC369E138125B42FCE21DFF13CD93B5A0E3D2EB61107EF3378106759940"
	certSha1   string = "AB51F4B4D3336129576C5CA46408A6A79EA62FB2"
)

var (
	cert []byte = []byte(`BEGIN CERTIFICATE-----
MIIFPjCCAyagAwIBAgIULNlw3eSpMdJrm7aUVg/IwfHTuXMwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjMwMjI4MDk0NjUxWhcNMzMw
MjI1MDk0NjUxWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAM4GQRgDUfOWewaw37E74uf6nqiQaWLRJy+DtQxh
WAI/TOEXlSamTW0wsMoHRAkAvOBje1BmgHRhOUIuzSGmwDNjosz2zyrCONgRWfcJ
yN96EtPa/4lEvlHTiN2NdV4mDN3XcW9j2n+K5mWh3oDVz0wp+A2byDmg1EdmL/X8
hGVvTMyUFt6prprdnALdGZqblsZAaLYg++r7uEDBihVw6DWunoiq2TnxNIXTdTIo
5UeFnKCSBDWseN0+FeQ5Xq9mAQfzwk5YeY2ser4iWl0FlZdYwrj+EBYT+I4MTCWG
B7YxcsX6pWSoWhvv5V9sRtH1KkiH5RaNQ/b9v9Pl5sdRq7ofUWxxGAEq+LmOExIq
if3JWpMq6AQVrMJTylFQv2AD9S9+9T7azTIfAxifveQrbwkgIUZX2e5bB2iKhQEH
tFyNYd7eyomCHt//3iRFyq64AtfmbQRaj2UsW63/wOMLAgM5ood1pnWt/1GGsH8U
XusELZS2ov+RI/Si661B3VMZhtTY/jFLYqbM09IfeGpXriRQxiwvXCsiJvyZaRE+
NHR+F6CfZp/3935SBIKU6ljdBrLCzTRCQ8eoysOSXAcYD7MUMMQNPwK+nOWStYGc
tk+qSgU3B3xiL9/yDsdM5Ov4mArKpbXP9DYnfDw97+D+8xFPAl0VEgj7dH8b0Q+c
w7hxAgMBAAGjgYMwgYAwHQYDVR0OBBYEFEY+2jaoCj7pWl5ggiYRxIdw/YIsMB8G
A1UdIwQYMBaAFEY+2jaoCj7pWl5ggiYRxIdw/YIsMA8GA1UdEwEB/wQFMAMBAf8w
LQYDVR0RBCYwJIILZXhhbXBsZS5jb22CD3d3dy5leGFtcGxlLm5ldIcECgAAATAN
BgkqhkiG9w0BAQsFAAOCAgEAY0BOskg82Ty//ADLyiXVhwEV/lLILH0BWWWVv05i
frrUs2fA3ORkUoRaiJxAzDvEV98AjD52Ty6WYtgNscmrQxxz0gn3xUWZXdj6L5PE
C6xj4lH0M/bNW6TUWhBqaVsaUCaoEhze4ieTcUHZlF61tkscdfUf8cIwi4vyNA3v
LIzXgJxIYw+wD5K1MEtVOPX3x9oO2Ceu3dLQv7MWULVjir1Pm2/3YhfGJgttFNHu
fbFWrPRG/m1MiMniGxQb3Oa1IjPZU70elP3GGG+irojxWcFYW+MopeXelVxbC63I
z7uc7cbmmcsD2GIkv1td4pe84UYy+pCsKQ8vXykwnjcFfjkrPSxdz1tVjrz4V60e
jVekhGgIHQAm/PyLLssQDykiX6ySxurU8bCcpqaA6dBzlUEX+Ym9xr2l155U6OsP
k4HWPGqf2/xMaXq/7g9HfqPhj9tZ/x2wyZ6Mx2rMtRV+6hX1XGa4tZU0f5MziEnX
Lkf4fEY4kc28UdEZRiG+D8cK6k0N8fHkKo4M09f+PJp/4sqa2g2kj8aqEFzSu2uq
v/cKeJ20txB/Egu9OGCS3aFqQ9zV+rqkEko2agLbqY/Aks3e/jaAIwURvxNS83l4
rJ90pXPe6awWutwMfmwlzqv0UYLu0IGHZiN8uTPiQ0nkR2kps3MruAsj1K9PaNpq
rtI=
-----END CERTIFICATE-----`)
)

func TestSum(t *testing.T) {
	sha256, sha1 := Sum(cert)
	sha256Clean := strings.ReplaceAll(sha256, " ", "")
	sha1Clean := strings.ReplaceAll(sha1, " ", "")

	if sha256Clean != certSha256 || sha1Clean != certSha1 {
		t.Errorf("Certificate Fingerprint was wrong: got sha256 %s sha1 %s, want sha256 %s and sha1 %s", sha256Clean, sha1Clean, certSha256, certSha1)
	}
}

func TestParseAndSumValid(t *testing.T) {
	// Generate a private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour), // short-lived for test
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Write to temp file
	tmpfile, err := os.CreateTemp("", "cert*.pem")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(certPEM); err != nil {
		t.Fatalf("failed to write cert to file: %v", err)
	}
	tmpfile.Close()

	// Call the actual function
	sha256sum, sha1sum, err := ParseAndSum(tmpfile.Name())
	if err != nil {
		t.Fatalf("ParseAndSum returned error: %v", err)
	}

	if sha256sum == "" || sha1sum == "" {
		t.Error("Expected non-empty SHA256 and SHA1 sums")
	}

}

func TestParseAndSumInvalid(t *testing.T) {
	// Invalid PEM with wrong base64 → pem.Decode fails
	tmp1, _ := os.CreateTemp("", "bad1*.pem")
	defer os.Remove(tmp1.Name())
	tmp1.Write([]byte("not a pem cert"))
	tmp1.Close()

	_, _, err := ParseAndSum(tmp1.Name())
	require.Error(t, err)

	// Valid PEM but invalid cert DER
	tmp2, _ := os.CreateTemp("", "bad2*.pem")
	defer os.Remove(tmp2.Name())
	tmp2.Write([]byte(`-----BEGIN CERTIFICATE-----
MIIBfzCCASKgAwIBAgIRAJKPXxQlIkH3l6Cy1W9ndSUwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEAwwHZXhhbXBsZQ==
-----END CERTIFICATE-----`))
	tmp2.Close()

	_, _, err = ParseAndSum(tmp2.Name())
	require.Error(t, err)

	// File does not exist
	_, _, err = ParseAndSum("/nonexistent/path.pem")
	require.Error(t, err)
}

// helper for serial numbers
func newSerial() *big.Int {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return serial
}

func TestSetup(t *testing.T) {
	tlsConf, sha256sum, sha1sum, err := Setup()

	// Should not return error
	require.NoError(t, err)

	// TLS config should not be nil
	require.NotNil(t, tlsConf)
	require.IsType(t, &tls.Config{}, tlsConf)

	// Should include a certificate
	require.NotEmpty(t, tlsConf.Certificates)
	cert := tlsConf.Certificates[0]
	require.NotNil(t, cert.Certificate)
	require.NotEmpty(t, cert.Certificate[0]) // Raw cert bytes

	require.NotEmpty(t, sha256sum)
	require.NotEmpty(t, sha1sum)

	// Optionally, parse and inspect the cert
	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, "goshs - SimpleHTTPServer", parsedCert.Subject.CommonName)
	require.True(t, parsedCert.IsCA == false)
}

func TestLetsEncryptGetMethods(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leu := LetsEncryptUser{
		Email: "example@test.com",
		Registration: &registration.Resource{
			Body: acme.Account{
				Status:                 "active",
				Contact:                []string{"test"},
				TermsOfServiceAgreed:   true,
				Orders:                 "some",
				OnlyReturnExisting:     false,
				ExternalAccountBinding: json.RawMessage("test"),
			},
			URI: "https://example.com",
		},
		Key:      key,
		HTTPPort: "80",
		TLSPort:  "443",
		Domains:  []string{"goshs.de"},
		Config:   &lego.Config{},
		Client:   &lego.Client{},
	}

	email := leu.GetEmail()
	require.Equal(t, email, "example@test.com")

	reg := leu.GetRegistration()
	require.Equal(t, reg.URI, "https://example.com")

	k := leu.GetPrivateKey()
	require.NotEmpty(t, k)

}
