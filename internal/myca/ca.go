// Package myca ...
// Credits: Shane Utt
// https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
package myca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"strings"
	"time"
)

// Sum will give the sha256 and sha1 sum of the certificate
func Sum(cert []byte) (sha256s, sha1s string) {
	// Building sha256 sum
	var f256 [32]byte
	f256 = sha256.Sum256(cert)
	sha256s = fmt.Sprintf("%X", f256)

	b := strings.Builder{}
	b.Grow(len(sha256s) + len(sha256s)/2 + 1)

	for i := 0; i < len(sha256s); i++ {
		b.WriteByte(sha256s[i])
		if i%2 == 1 {
			b.WriteByte(' ')
		}
	}

	sha256s = b.String()

	// building sha1 sum
	var f1 [20]byte
	f1 = sha1.Sum(cert)
	sha1s = fmt.Sprintf("%X", f1)

	b = strings.Builder{}
	b.Grow(len(sha1s) + len(sha1s)/2 + 1)

	for i := 0; i < len(sha1s); i++ {
		b.WriteByte(sha1s[i])
		if i%2 == 1 {
			b.WriteByte(' ')
		}
	}

	sha1s = b.String()

	return sha256s, sha1s

}

// ParseAndSum will take the user provided cert and return the sha256 and sha1 sum
func ParseAndSum(cert string) (sha256s, sha1s string, err error) {
	certBytes, err := ioutil.ReadFile(cert)
	if err != nil {
		return "", "", err
	}

	block, _ := pem.Decode(certBytes)

	certParsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}

	sha256s, sha1s = Sum(certParsed.Raw)

	return sha256s, sha1s, nil
}

// Setup will deliver a fully initialized CA and server cert
func Setup() (serverTLSConf *tls.Config, sha256s, sha1s string, err error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:       []string{"hesec.de"},
			OrganizationalUnit: []string{"hesec.de"},
			CommonName:         "goshs - SimpleHTTPServer",
			Country:            []string{"DE"},
			Province:           []string{"BW"},
			Locality:           []string{"Althengstett"},
			StreetAddress:      []string{"Gopher-Street"},
			PostalCode:         []string{"75382"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, "", "", err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, "", "", err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:       []string{"hesec.de"},
			OrganizationalUnit: []string{"hesec.de"},
			CommonName:         "goshs - SimpleHTTPServer",
			Country:            []string{"DE"},
			Province:           []string{"BW"},
			Locality:           []string{"Althengstett"},
			StreetAddress:      []string{"Gopher-Street"},
			PostalCode:         []string{"75382"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, "", "", err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, "", "", err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, "", "", err
	}

	serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	sha256s, sha1s = Sum(certBytes)

	return
}
