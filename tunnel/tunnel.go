package tunnel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"goshs.de/goshs/v2/logger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyMismatchError is returned by Start when the server presents a host
// key that differs from the pinned key in known_hosts. Callers should treat
// this as a fatal condition (possible MITM attack).
type HostKeyMismatchError struct {
	Hostname       string
	KnownHostsFile string
}

func (e *HostKeyMismatchError) Error() string {
	return fmt.Sprintf(
		"ssh: host key mismatch for %s — possible MITM attack. "+
			"If localhost.run legitimately rotated its key, delete %s and reconnect",
		e.Hostname, e.KnownHostsFile,
	)
}

type Tunnel struct {
	PublicURL string
	client    *ssh.Client
	session   *ssh.Session
	stop      chan struct{}
}

type closeWriter interface {
	CloseWrite() error
}

func Start(localIP string, localPort int, knownHostsFile string) (*Tunnel, error) {
	hostKeyCb, err := buildTOFUCallback(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("setting up host key verification: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            "nokey",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: hostKeyCb,
		Timeout:         10 * time.Second,
		BannerCallback:  func(banner string) error { return nil },
	}

	client, err := ssh.Dial("tcp", "localhost.run:22", config)
	if err != nil {
		return nil, fmt.Errorf("connecting to localhost.run: %w", err)
	}

	// Register handler for forwarded-tcpip BEFORE sending the global
	// request — channels can arrive immediately after the request is
	// accepted, before we get to Accept() calls
	chanCh := client.HandleChannelOpen("forwarded-tcpip")
	if chanCh == nil {
		client.Close()
		return nil, fmt.Errorf("could not register forwarded-tcpip handler")
	}

	// Send the tcpip-forward global request directly instead of using
	// client.Listen() — this avoids the address matching issue entirely
	ok, _, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		BindAddr string
		BindPort uint32
	}{"localhost", 80}))
	if err != nil || !ok {
		client.Close()
		return nil, fmt.Errorf("tcpip-forward request failed: %w", err)
	}

	// Open session for URL capture
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("opening session: %w", err)
	}

	pr, pw := io.Pipe()
	session.Stdout = pw

	if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{
		ssh.ECHO: 0,
	}); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("requesting pty: %w", err)
	}

	if err := session.Shell(); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("requesting shell: %w", err)
	}

	urlCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		found := false
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !found && strings.Contains(line, "tunneled with tls termination") {
				parts := strings.Split(line, ", ")
				if len(parts) == 2 && strings.HasPrefix(parts[1], "https://") {
					urlCh <- strings.TrimSpace(parts[1])
					found = true
				}
			}
		}
		if !found {
			errCh <- fmt.Errorf("session ended before URL was found")
		}
	}()

	select {
	case url := <-urlCh:
		t := &Tunnel{
			PublicURL: url,
			client:    client,
			session:   session,
			stop:      make(chan struct{}),
		}
		go t.accept(chanCh, localIP, localPort)
		return t, nil
	case err := <-errCh:
		session.Close()
		client.Close()
		return nil, fmt.Errorf("capturing URL: %w", err)
	case <-time.After(15 * time.Second):
		session.Close()
		client.Close()
		return nil, fmt.Errorf("timed out waiting for tunnel URL")
	}
}

// accept handles incoming forwarded-tcpip new channel requests directly,
// bypassing the address matching in client.Listen()
func (t *Tunnel) accept(chanCh <-chan ssh.NewChannel, localIP string, localPort int) {
	for {
		select {
		case <-t.stop:
			return
		case newChan, ok := <-chanCh:
			if !ok {
				return
			}
			logger.Debugf("tunnel: incoming forwarded-tcpip channel")
			ch, reqs, err := newChan.Accept()
			if err != nil {
				logger.Debugf("tunnel: accepting channel failed: %v", err)
				continue
			}
			// Discard channel-level requests (window adjustments etc.)
			go ssh.DiscardRequests(reqs)
			go proxy(ch, localIP, localPort)
		}
	}
}

func buildTOFUCallback(knownHostsFile string) (ssh.HostKeyCallback, error) {
	// Create the file if it does not exist yet.
	f, err := os.OpenFile(knownHostsFile, os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", knownHostsFile, err)
	}
	f.Close()

	cb, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", knownHostsFile, err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(hostname, remote, key)
		if err == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err
		}

		if len(keyErr.Want) > 0 {
			// Host is known but presented a different key — abort.
			return &HostKeyMismatchError{Hostname: hostname, KnownHostsFile: knownHostsFile}
		}

		// Unknown host — TOFU: pin the key and warn.
		f, err := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("writing to %s: %w", knownHostsFile, err)
		}
		defer f.Close()

		line := knownhosts.Line([]string{hostname}, key)
		if _, err := fmt.Fprintln(f, line); err != nil {
			return fmt.Errorf("writing to %s: %w", knownHostsFile, err)
		}

		fingerprint := ssh.FingerprintSHA256(key)
		logger.Warnf("tunnel: pinned new host key for %s (%s) in %s", hostname, fingerprint, knownHostsFile)
		logger.Warnf("tunnel: verify with: ssh-keyscan localhost.run 2>/dev/null | ssh-keygen -l -f -")
		return nil
	}, nil
}

func (t *Tunnel) Close() {
	close(t.stop)
	t.session.Close()
	t.client.Close()
}
func proxy(remote ssh.Channel, localIP string, localPort int) {
	defer remote.Close()
	logger.Debugf("tunnel: proxy connecting to %s:%d", localIP, localPort)
	local, err := net.DialTimeout("tcp",
		net.JoinHostPort(localIP, strconv.Itoa(localPort)), 5*time.Second)
	if err != nil {
		logger.Debugf("tunnel: proxy dial failed: %v", err)
		return
	}
	defer local.Close()
	logger.Debugf("tunnel: proxy connection established, copying")

	done := make(chan struct{}, 2)

	go func() {
		n, err := io.Copy(local, remote)
		logger.Debugf("tunnel: remote→local done: %d bytes, err: %v", n, err)
		if cw, ok := local.(closeWriter); ok {
			err := cw.CloseWrite()
			if err != nil {
				logger.Debugf("tunnel: close write failed: %v", err)
			}
		}
		done <- struct{}{}
	}()

	go func() {
		n, err := io.Copy(remote, local)
		logger.Debugf("tunnel: local→remote done: %d bytes, err: %v", n, err)
		if cw, ok := remote.(closeWriter); ok {
			err := cw.CloseWrite()
			if err != nil {
				logger.Debugf("tunnel: close write failed: %v", err)
			}
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}
