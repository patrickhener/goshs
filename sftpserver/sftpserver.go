package sftpserver

import (
	"fmt"
	"io"
	"os"

	"github.com/gliderlabs/ssh"
	"github.com/patrickhener/goshs/logger"
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
}

// NewSFTPServer creates a new SFTP server instance
func NewSFTPServer(ip string, port int, keyfile string, username string, password string, root string, readonly bool, uploadonly bool, hostkey string) *SFTPServer {
	return &SFTPServer{
		IP:          ip,
		Port:        port,
		KeyFile:     keyfile,
		Username:    username,
		Password:    password,
		Root:        root,
		ReadOnly:    readonly,
		UploadOnly:  uploadonly,
		HostKeyFile: hostkey,
	}
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
			var err error
			// Set handler read only or upload only or default
			if s.ReadOnly {
				roHandler := &ReadOnlyHandler{
					Root:     s.Root,
					ClientIP: sess.RemoteAddr().String(),
				}
				server = sftp.NewRequestServer(sess, roHandler.GetHandler(), sftp.WithStartDirectory(s.Root))
			} else if s.UploadOnly {
				uoHandler := &UploadOnlyHandler{
					Root:     s.Root,
					ClientIP: sess.RemoteAddr().String(),
				}
				server = sftp.NewRequestServer(sess, uoHandler.GetHandler(), sftp.WithStartDirectory(s.Root))
			} else {
				dh := &DefaultHandler{
					Root:     s.Root,
					ClientIP: sess.RemoteAddr().String(),
				}
				server = sftp.NewRequestServer(sess, dh.GetHandler(), sftp.WithStartDirectory(s.Root))
			}

			if err != nil {
				logger.Errorf("SFTP server init error: %+v", err)
				return
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
