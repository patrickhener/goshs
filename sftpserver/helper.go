package sftpserver

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/patrickhener/goshs/logger"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

var authorizedKeysMap map[string]bool

// loadAuthorizedKeys loads authorized keys from a file and returns a map of keys
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

// Sanitize client path to restrict to sftpRoot
func sanitizePath(clientPath string, sftpRoot string) (string, error) {
	cleanPath := filepath.Clean("/" + clientPath)
	if !strings.HasPrefix(cleanPath, sftpRoot) {
		return "", errors.New("access denied: outside of webroot")
	}
	return cleanPath, nil
}

// simpleListerAt is a simple implementation of sftp.ListerAt
type simpleListerAt struct {
	files []fs.FileInfo
}

// ListAt implements the sftp.ListerAt interface
func (l *simpleListerAt) ListAt(p []fs.FileInfo, off int64) (int, error) {
	if int(off) >= len(l.files) {
		return 0, io.EOF
	}

	n := copy(p, l.files[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// readFile opens a file for reading
func readFile(path string, root string, r *sftp.Request, ip string) (*os.File, error) {
	path, err := sanitizePath(path, root)
	if err != nil {
		return nil, err
	}
	logger.LogSFTPRequest(r, ip)
	return os.Open(path)
}

// listFile lists files in a directory
func listFile(path string, root string, r *sftp.Request, ip string) (*simpleListerAt, error) {
	fullPath, err := sanitizePath(path, root)
	if err != nil {
		return nil, err
	}
	switch r.Method {
	case "Stat":
		info, err := os.Stat(fullPath)
		if err != nil {
			return nil, err
		}
		logger.LogSFTPRequest(r, ip)
		return &simpleListerAt{files: []fs.FileInfo{info}}, nil
	default:
		f, err := os.Open(fullPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		infos, err := f.Readdir(0)
		if err != nil {
			return nil, err
		}

		return &simpleListerAt{files: infos}, nil
	}
}

// writeFile opens a file for writing
func writeFile(path string, root string, r *sftp.Request, ip string) (*os.File, error) {
	path, err := sanitizePath(path, root)
	if err != nil {
		return nil, err
	}
	logger.LogSFTPRequest(r, ip)
	return os.Create(path)
}

// cmdFile executes file commands like Stat, Lstat, Setstat, Rename, Rmdir, Mkdir, and Remove
func cmdFile(path string, root string, r *sftp.Request, ip string) error {
	path, err := sanitizePath(path, root)
	if err != nil {
		return err
	}

	switch r.Method {
	case "Stat":
		_, err := os.Stat(path)
		logger.LogSFTPRequest(r, ip)
		return err
	case "Lstat":
		_, err := os.Lstat(path)
		logger.LogSFTPRequest(r, ip)
		return err
	case "Setstat":
		mode := os.FileMode(r.Attributes().Mode)
		fmt.Printf("mode: %+v\n", mode)
		if mode != 0 {
			if err := os.Chmod(path, mode); err != nil {
				return fmt.Errorf("chmod failed %w", err)
			}
			return nil
		}
		logger.LogSFTPRequest(r, ip)
		return os.Chmod(path, os.FileMode(r.Attributes().Mode))
	case "Rename":
		logger.LogSFTPRequest(r, ip)
		return os.Rename(path, r.Target)
	case "Rmdir":
		logger.LogSFTPRequest(r, ip)
		return os.RemoveAll(path)
	case "Mkdir":
		logger.LogSFTPRequest(r, ip)
		return os.Mkdir(path, 0o775)
	case "Remove":
		logger.LogSFTPRequest(r, ip)
		return os.Remove(path)
	default:
		logger.LogSFTPRequest(r, ip)
		return errors.New("unsupported command")
	}
}
