package sftpserver

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/gliderlabs/ssh"
	"github.com/patrickhener/goshs/logger"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

var authorizedKeysMap map[string]bool

type SFTPServer struct {
	IP          string
	Port        int
	KeyFile     string
	Username    string
	Password    string
	Root        string
	ReadOnly    bool
	HostKeyFile string
}

func NewSFTPServer(ip string, port int, keyfile string, username string, password string, root string, readonly bool, hostkey string) *SFTPServer {
	return &SFTPServer{
		IP:          ip,
		Port:        port,
		KeyFile:     keyfile,
		Username:    username,
		Password:    password,
		Root:        root,
		ReadOnly:    readonly,
		HostKeyFile: hostkey,
	}
}

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
			var server *sftp.Server
			var err error

			if s.ReadOnly {
				server, err = sftp.NewServer(sess, sftp.WithServerWorkingDirectory(s.Root), sftp.ReadOnly())
			} else {
				server, err = sftp.NewServer(sess, sftp.WithServerWorkingDirectory(s.Root))
			}
			if err != nil {
				logger.Errorf("SFTP server init error: %+v", err)
				return
			}
			if err := server.Serve(); err == io.EOF {
				server.Close()
				logger.Warn("SFTP client disconnected")
			} else if err != nil {
				logger.Errorf("SFTP server error: %+v", err)
			}
		},
	}

	logger.Infof("Starting SFTP server on port %s:%d", s.IP, s.Port)
	logger.Fatal(sshServer.ListenAndServe())

	return nil
}

func loadAuthorizedKeys(path string) (map[string]bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	keys := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		key, _, _, _, err := gossh.ParseAuthorizedKey(line)
		if err != nil {
			log.Printf("Skipping invalid key: %v", err)
			continue
		}
		keys[string(key.Marshal())] = true
	}
	return keys, scanner.Err()
}
