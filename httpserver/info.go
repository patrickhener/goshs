package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func (fs *FileServer) handleInfo(w http.ResponseWriter) {
	if !fs.Invisible && !fs.Silent {
		// Return server info as json blob
		info := map[string]string{
			"version":        fmt.Sprintf("%s", fs.Version),
			"ip":             fmt.Sprintf("%s", fs.IP),
			"port":           fmt.Sprintf("%d", fs.Port),
			"ssl":            fmt.Sprintf("%t", fs.SSL),
			"fingerprint256": fmt.Sprintf("%s", fs.Fingerprint256),
			"fingerprint1":   fmt.Sprintf("%s", fs.Fingerprint1),
			"tunnel":         fmt.Sprintf("%t", fs.Tunnel),
			"tunnel-url":     fmt.Sprintf("%s", fs.TunnelURL),
			"cli":            fmt.Sprintf("%t", fs.CLI),
			"webdav-port":    fmt.Sprintf("%d", fs.WebdavPort),
			"upload-folder":  fmt.Sprintf("%s", fs.UploadFolder),
			"self-signed":    fmt.Sprintf("%t", fs.SelfSigned),
			"lets-encrypt":   fmt.Sprintf("%t", fs.LetsEncrypt),
			"my-key":         fmt.Sprintf("%s", fs.MyKey),
			"my-cert":        fmt.Sprintf("%s", fs.MyCert),
			"my-p12":         fmt.Sprintf("%s", fs.MyP12),
			"p12-no-pass":    fmt.Sprintf("%t", fs.P12NoPass),
			"auth":           fmt.Sprintf("%t", fs.Pass != "" || fs.CACert != ""),
			"ca-cert":        fmt.Sprintf("%s", fs.CACert),
			"process-user":   fmt.Sprintf("%s", fs.DropUser),
			"upload-only":    fmt.Sprintf("%t", fs.UploadOnly),
			"read-only":      fmt.Sprintf("%t", fs.ReadOnly),
			"no-clipboard":   fmt.Sprintf("%t", fs.NoClipboard),
			"no-delete":      fmt.Sprintf("%t", fs.NoDelete),
			"embedded":       fmt.Sprintf("%t", fs.Embedded),
			"verbose":        fmt.Sprintf("%t", fs.Verbose),
			"webroot":        fmt.Sprintf("%s", fs.Webroot),
			"shared-links":   fmt.Sprintf("%d", len(fs.SharedLinks)),
		}

		json.NewEncoder(w).Encode(info)
		return
	}

	fs.handleInvisible(w)
}
