//go:build unix

package catcher

import (
	"encoding/json"
	"sync"

	"goshs.de/goshs/v2/ws"
)

type Manager struct {
	mu        sync.RWMutex
	listeners map[string]*Listener
	sessions  map[string]*Session
	hub       *ws.Hub
}

func NewManager(hub *ws.Hub) *Manager {
	return &Manager{
		listeners: make(map[string]*Listener),
		sessions:  make(map[string]*Session),
		hub:       hub,
	}
}

func (m *Manager) StartListener(ip string, port int) (*ListenerInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ln, err := newListener(m, ip, port)
	if err != nil {
		return nil, err
	}

	m.listeners[ln.ID] = ln
	return &ListenerInfo{
		ID:   ln.ID,
		IP:   ln.IP,
		Port: ln.Port,
	}, nil
}

func (m *Manager) StopListener(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ln, ok := m.listeners[id]
	if !ok {
		return ErrNotFound
	}

	// Remove sessions belonging to this listener
	for sid, s := range m.sessions {
		if s.ListenerID == id {
			delete(m.sessions, sid)
		}
	}

	ln.Stop()
	delete(m.listeners, id)
	return nil
}

func (m *Manager) KillSession(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		return ErrNotFound
	}

	ln, ok := m.listeners[s.ListenerID]
	if ok {
		ln.KillSession(id)
	}
	delete(m.sessions, id)
	return nil
}

func (m *Manager) GetListeners() []ListenerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var infos []ListenerInfo
	for _, ln := range m.listeners {
		infos = append(infos, ListenerInfo{
			ID:       ln.ID,
			IP:       ln.IP,
			Port:     ln.Port,
			Sessions: ln.GetSessions(),
		})
	}
	return infos
}

func (m *Manager) GetSession(id string) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

func (m *Manager) registerSession(s *Session) {
	m.mu.Lock()
	m.sessions[s.ID] = s
	m.mu.Unlock()

	// Notify all browser clients via main hub
	msg, _ := json.Marshal(map[string]any{
		"type":       "catcherConnection",
		"listenerID": s.ListenerID,
		"sessionID":  s.ID,
		"remoteAddr": s.RemoteAddr,
	})
	m.hub.Broadcast <- msg
}
