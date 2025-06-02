package httpserver

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"

	"github.com/patrickhener/goshs/logger"
	"github.com/skip2/go-qrcode"
)

func removeItem(sSlice []item, item string) []item {
	index := 0

	for idx, sliceItem := range sSlice {
		if item == sliceItem.Name {
			index = idx
		}
	}

	return append(sSlice[:index], sSlice[index+1:]...)
}

func (files *FileServer) PrintEmbeddedFiles() {
	err := fs.WalkDir(embedded, ".",
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				outPath := strings.TrimPrefix(path, "embedded")
				logger.Infof("Download embedded file at: %+v?embedded", outPath)
			}
			return nil
		})
	if err != nil {
		logger.Errorf("error printing info about embedded files: %+v", err)
	}

}

func (files *FileServer) AddCertAuth(server *http.Server) {
	logger.Infof("Using certificate auth with ca certificate: %+v", files.CACert)
	caCert, err := os.ReadFile(files.CACert)
	if err != nil {
		logger.Fatalf("error reading the ca certificate for cert based client authentication: %+v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	server.TLSConfig.ClientCAs = caCertPool
	server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
}

func GenerateToken() string {
	b := make([]byte, 16)
	rand.Read(b)

	s := base64.RawURLEncoding.EncodeToString(b)
	return strings.TrimRight(s, "=")
}

func GenerateQRCode(uri string) string {
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		logger.Errorf("unable to generate QR Code for file: %s", uri)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(png)

	return fmt.Sprintf("data:image/png;base64,%s", encoded)
}
