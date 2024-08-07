package httpserver

import (
	"crypto/tls"
	"crypto/x509"
	"io/fs"
	"net/http"
	"os"
	"strings"

	"github.com/patrickhener/goshs/logger"
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
