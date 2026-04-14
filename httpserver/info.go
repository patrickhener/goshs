package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"

	"goshs.de/goshs/logger"
)

func (fs *FileServer) handleInfo(w http.ResponseWriter) {
	if !fs.Invisible && !fs.Silent {
		// Return server info as json blob
		info := map[string]string{
			"version":        fs.Version,
			"ip":             fs.IP,
			"port":           fmt.Sprintf("%d", fs.Port),
			"ssl":            fmt.Sprintf("%t", fs.SSL),
			"fingerprint256": fs.Fingerprint256,
			"fingerprint1":   fs.Fingerprint1,
			"tunnel":         fmt.Sprintf("%t", fs.Tunnel),
			"tunnel-url":     fs.TunnelURL,
			"cli":            fmt.Sprintf("%t", fs.CLI),
			"webdav-port":    fmt.Sprintf("%d", fs.WebdavPort),
			"upload-folder":  fs.UploadFolder,
			"self-signed":    fmt.Sprintf("%t", fs.SelfSigned),
			"lets-encrypt":   fmt.Sprintf("%t", fs.LetsEncrypt),
			"my-key":         fs.MyKey,
			"my-cert":        fs.MyCert,
			"my-p12":         fs.MyP12,
			"p12-no-pass":    fmt.Sprintf("%t", fs.P12NoPass),
			"auth":           fmt.Sprintf("%t", fs.Pass != "" || fs.CACert != ""),
			"ca-cert":        fs.CACert,
			"process-user":   fs.DropUser,
			"upload-only":    fmt.Sprintf("%t", fs.UploadOnly),
			"read-only":      fmt.Sprintf("%t", fs.ReadOnly),
			"no-clipboard":   fmt.Sprintf("%t", fs.NoClipboard),
			"no-delete":      fmt.Sprintf("%t", fs.NoDelete),
			"embedded":       fmt.Sprintf("%t", fs.Embedded),
			"verbose":        fmt.Sprintf("%t", fs.Verbose),
			"webroot":        fs.Webroot,
			"shared-links":   fmt.Sprintf("%d", len(fs.SharedLinks)),
			"dns":            fmt.Sprintf("%t", fs.Options.DNS),
			"dns-port":       fmt.Sprintf("%d", fs.Options.DNSPort),
			"dns-ip":         fs.Options.DNSIP,
			"smtp":           fmt.Sprintf("%t", fs.Options.SMTP),
			"smtp-port":      fmt.Sprintf("%d", fs.Options.SMTPPort),
			"smtp-domain":    fs.Options.SMTPDomain,
			"smb":            fmt.Sprintf("%t", fs.Options.SMB),
			"smb-port":       fmt.Sprintf("%d", fs.Options.SMBPort),
			"smb-domain":     fs.Options.SMBDomain,
			"smb-share":      fs.Options.SMBShare,
		}

		err := json.NewEncoder(w).Encode(info)
		if err != nil {
			logger.Error(err)
		}
		return
	}

	fs.handleInvisible(w)
}
