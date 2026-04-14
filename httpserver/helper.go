package httpserver

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"goshs.de/goshs/logger"
	"github.com/skip2/go-qrcode"
)

// sanitizePath validates that requestPath stays within root after decoding and
// cleaning. It returns the absolute path on success, or an error if the path
// would escape root (path traversal).
func sanitizePath(root, requestPath string) (string, error) {
	decoded, err := url.QueryUnescape(requestPath)
	if err != nil {
		// Malformed percent-encoding — use raw value; filepath.Clean will handle it.
		decoded = requestPath
	}
	clean := filepath.Clean("/" + strings.TrimLeft(decoded, "/"))
	abs := filepath.Join(root, clean)
	rootClean := filepath.Clean(root)
	if abs != rootClean && !strings.HasPrefix(abs, rootClean+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes root: %q", requestPath)
	}
	return abs, nil
}

func removeItem(sSlice []item, name string) []item {
	for idx, sliceItem := range sSlice {
		if name == sliceItem.Name {
			return append(sSlice[:idx], sSlice[idx+1:]...)
		}
	}
	return sSlice
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
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("goshs: failed to generate token: " + err.Error())
	}
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

func denyForTokenAccess(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Query().Get("token") != "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return true
	}
	return false
}
