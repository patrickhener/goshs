package catcher

import (
	"net"
	"sync"
)

type Session struct {
	ID         string
	ListenerID string
	RemoteAddr string

	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

func newSession(id, listenerID, remoteAddr string, conn net.Conn) *Session {
	return &Session{
		ID:         id,
		ListenerID: listenerID,
		RemoteAddr: remoteAddr,
		conn:       conn,
	}
}

func (s *Session) Read(buf []byte) (int, error) {
	return s.conn.Read(buf)
}

func (s *Session) Write(buf []byte) (int, error) {
	return s.conn.Write(buf)
}

func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

type SessionInfo struct {
	ID         string `json:"id"`
	ListenerID string `json:"listenerId"`
	RemoteAddr string `json:"remoteAddr"`
}
