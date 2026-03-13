package tunnel

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/patrickhener/goshs/logger"
	"golang.org/x/crypto/ssh"
)

type Tunnel struct {
	PublicURL string
	client    *ssh.Client
	session   *ssh.Session
	stop      chan struct{}
}

type closeWriter interface {
	CloseWrite() error
}

func Start(localIP string, localPort int) (*Tunnel, error) {
	config := &ssh.ClientConfig{
		User:            "nokey",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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

func (t *Tunnel) Close() {
	close(t.stop)
	t.session.Close()
	t.client.Close()
}
func proxy(remote ssh.Channel, localIP string, localPort int) {
	defer remote.Close()
	logger.Debugf("tunnel: proxy connecting to %s:%d", localIP, localPort)
	local, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", localIP, localPort), 5*time.Second)
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
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		n, err := io.Copy(remote, local)
		logger.Debugf("tunnel: local→remote done: %d bytes, err: %v", n, err)
		if cw, ok := remote.(closeWriter); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}
