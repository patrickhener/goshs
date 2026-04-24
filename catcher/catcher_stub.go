//go:build windows

package catcher

import (
	"fmt"
	"net/http"

	"goshs.de/goshs/v2/ws"
)

type Manager struct{}

func NewManager(hub *ws.Hub) *Manager { return &Manager{} }

type ListenerInfo struct {
	ID       string        `json:"id"`
	IP       string        `json:"ip"`
	Port     int           `json:"port"`
	Sessions []SessionInfo `json:"sessions"`
}

type SessionInfo struct {
	ID         string `json:"id"`
	ListenerID string `json:"listenerId"`
	RemoteAddr string `json:"remoteAddr"`
}

type Session struct{}

func (m *Manager) StartListener(ip string, port int) (*ListenerInfo, error) {
	return nil, fmt.Errorf("reverse shell catcher is not supported on Windows")
}
func (m *Manager) StopListener(id string) error                { return nil }
func (m *Manager) KillSession(id string) error                 { return nil }
func (m *Manager) GetListeners() []ListenerInfo                { return nil }
func (m *Manager) GetSession(id string) *Session               { return nil }

func ServeCatcherWS(mgr *Manager, w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not supported on Windows", http.StatusNotImplemented)
}
