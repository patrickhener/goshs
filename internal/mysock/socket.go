package mysock

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var wsupgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Acceppt Any
	CheckOrigin: func(r *http.Request) bool { return true },
}

// ServeWS will handle the socket connections
func ServeWS(hub *Hub, w http.ResponseWriter, r *http.Request) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsupgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Failed to upgrade ws: %+v", err)
			return
		}

		client := &Client{hub: hub, conn: conn, send: make(chan []byte, 1024)}
		client.hub.register <- client

		go client.writePump()
		go client.readPump()
	}
}
