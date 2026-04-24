//go:build unix

package catcher

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"goshs.de/goshs/v2/logger"
)

type Listener struct {
	ID   string
	IP   string
	Port int

	mgr      *Manager
	netLn    net.Listener
	sessions map[string]*Session
	mu       sync.Mutex
	active   bool
}

func newListener(mgr *Manager, ip string, port int) (*Listener, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	l := &Listener{
		ID:       generateID(),
		IP:       ip,
		Port:     port,
		mgr:      mgr,
		netLn:    ln,
		sessions: make(map[string]*Session),
		active:   true,
	}

	go l.acceptLoop()
	return l, nil
}

func (l *Listener) acceptLoop() {
	for {
		conn, err := l.netLn.Accept()
		if err != nil {
			if !l.active {
				return
			}
			logger.Errorf("listener %s: accept error: %v", l.ID, err)
			return
		}

		session := newSession(generateID(), l.ID, conn.RemoteAddr().String(), conn)

		l.mu.Lock()
		l.sessions[session.ID] = session
		l.mu.Unlock()

		l.mgr.registerSession(session)

		logger.Infof("listener %s: new session %s from %s", l.ID, session.ID, conn.RemoteAddr())
	}
}

func (l *Listener) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.active = false
	if l.netLn != nil {
		l.netLn.Close()
	}

	for _, s := range l.sessions {
		s.Close()
	}
	l.sessions = make(map[string]*Session)
}

func (l *Listener) KillSession(sessionID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	s, ok := l.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session %s not found", sessionID)
	}
	s.Close()
	delete(l.sessions, sessionID)
	return nil
}

func (l *Listener) GetSessions() []SessionInfo {
	l.mu.Lock()
	defer l.mu.Unlock()

	var infos []SessionInfo
	for _, s := range l.sessions {
		if !s.IsClosed() {
			infos = append(infos, SessionInfo{
				ID:         s.ID,
				ListenerID: s.ListenerID,
				RemoteAddr: s.RemoteAddr,
			})
		}
	}
	return infos
}

func (l *Listener) GetSession(id string) *Session {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sessions[id]
}

type ListenerInfo struct {
	ID       string        `json:"id"`
	IP       string        `json:"ip"`
	Port     int           `json:"port"`
	Sessions []SessionInfo `json:"sessions"`
}

func generateID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b) + fmt.Sprintf("%d", time.Now().UnixNano()%1000)
}
