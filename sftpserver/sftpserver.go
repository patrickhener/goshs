package sftpserver

import (
	"fmt"
	"io"
	"os"

	"github.com/gliderlabs/ssh"
	"github.com/patrickhener/goshs/logger"
	"github.com/patrickhener/goshs/webhook"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

// SFTPServer represents an SFTP server configuration
type SFTPServer struct {
	IP          string
	Port        int
	KeyFile     string
	Username    string
	Password    string
	Root        string
	ReadOnly    bool
	UploadOnly  bool
	HostKeyFile string
	Webhook     webhook.Webhook
}

// Start initializes and starts the SFTP server
func (s *SFTPServer) Start() error {
	var err error

	// Define a simple password auth handler
	sshServer := ssh.Server{
		Addr: fmt.Sprintf("%s:%d", s.IP, s.Port),
		Handler: func(s ssh.Session) {
			// Deny default ssh connections
			io.WriteString(s, "This server only supports SFTP.\n")
			s.Exit(1)
		},
	}

	if s.HostKeyFile != "" {
		privateBytes, err := os.ReadFile(s.HostKeyFile)
		if err != nil {
			return err
		}

		private, err := gossh.ParsePrivateKey(privateBytes)
		if err != nil {
			return err
		}

		sshServer.HostSigners = []ssh.Signer{private}
	}

	if s.Username != "" && s.Password != "" {
		sshServer.PasswordHandler = func(ctx ssh.Context, password string) bool {
			return ctx.User() == s.Username && password == s.Password
		}
	}

	// User authorized_keys if provided
	if s.KeyFile != "" {
		authorizedKeysMap, err = loadAuthorizedKeys(s.KeyFile)
		if err != nil {
			return err
		}
		sshServer.PublicKeyHandler = func(ctx ssh.Context, key ssh.PublicKey) bool {
			return authorizedKeysMap[string(key.Marshal())]
		}
	}

	// Add SFTP Handler
	sshServer.SubsystemHandlers = map[string]ssh.SubsystemHandler{
		"sftp": func(sess ssh.Session) {
			var server *sftp.RequestServer
			// Set handler read only or upload only or default
			if s.ReadOnly {
				roHandler := &ReadOnlyHandler{
					Root:       s.Root,
					ClientIP:   sess.RemoteAddr().String(),
					SFTPServer: s,
				}
				server = sftp.NewRequestServer(sess, roHandler.GetHandler(), sftp.WithStartDirectory(s.Root))
			} else if s.UploadOnly {
				uoHandler := &UploadOnlyHandler{
					Root:       s.Root,
					ClientIP:   sess.RemoteAddr().String(),
					SFTPServer: s,
				}
				server = sftp.NewRequestServer(sess, uoHandler.GetHandler(), sftp.WithStartDirectory(s.Root))
			} else {
				dh := &DefaultHandler{
					Root:       s.Root,
					ClientIP:   sess.RemoteAddr().String(),
					SFTPServer: s,
				}
				server = sftp.NewRequestServer(sess, dh.GetHandler(), sftp.WithStartDirectory(s.Root))
			}

			if err := server.Serve(); err == io.EOF {
				server.Close()
			} else if err != nil {
				logger.Errorf("SFTP server error: %+v", err)
			}
		},
	}

	logger.Infof("Starting SFTP server on port %s:%d", s.IP, s.Port)
	logger.Fatal(sshServer.ListenAndServe())

	return nil
}

func (s *SFTPServer) HandleWebhookSend(event string, r *sftp.Request, ip string, blocked bool) {
	var message string
	if blocked {
		switch r.Method {
		case "Rename":
			message = fmt.Sprintf("[SFTP] BLOCKED %s - [%s] - \"%s to %s\"", ip, r.Method, r.Filepath, r.Target)
		default:
			message = fmt.Sprintf("[SFTP] BLOCKED %s - [%s] - \"%s\"", ip, r.Method, r.Filepath)
		}
	} else {
		switch r.Method {
		case "Rename":
			message = fmt.Sprintf("[SFTP] %s - [%s] - \"%s to %s\"", ip, r.Method, r.Filepath, r.Target)
		default:
			message = fmt.Sprintf("[SFTP] %s - [%s] - \"%s\"", ip, r.Method, r.Filepath)
		}
	}

	logger.HandleWebhookSend(message, "sftp", s.Webhook)
}
