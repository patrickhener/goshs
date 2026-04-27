package catcher

import (
	"bytes"
	"context"
	"net/http"

	"github.com/coder/websocket"
	"goshs.de/goshs/v2/logger"
)

// ensureCRLF converts bare \n to \r\n so xterm.js renders lines correctly.
func ensureCRLF(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
}

func ServeCatcherWS(mgr *Manager, w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "missing session parameter", http.StatusBadRequest)
		return
	}

	session := mgr.GetSession(sessionID)
	if session == nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		logger.Errorf("catcher ws: accept failed: %v", err)
		return
	}

	go catchPumpWS(conn, session)
}

func catchPumpWS(conn *websocket.Conn, session *Session) {
	ctx := context.Background()
	defer conn.Close(websocket.StatusNormalClosure, "")

	// TCP → WS: read from victim's shell, send to browser
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := session.Read(buf)
			if err != nil {
				close(done)
				return
			}
			if err := conn.Write(ctx, websocket.MessageBinary, ensureCRLF(buf[:n])); err != nil {
				return
			}
		}
	}()

	// WS → TCP: read from browser, send to victim's shell
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			break
		}

		if _, err := session.Write(data); err != nil {
			break
		}
	}

	session.Close()
	<-done
}
