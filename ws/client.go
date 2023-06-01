package ws

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/patrickhener/goshs/cli"
	"github.com/patrickhener/goshs/logger"
)

// Packet defines a packet struct
type Packet struct {
	Type    string `json:"type"`
	Content json.RawMessage
}

// SendPacket represents a response package from server to browser
type SendPacket struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 8000000
)

var newline = []byte{'\n'}

var wsupgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Acceppt Any
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub *Hub

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan []byte
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		if err := c.conn.Close(); err != nil {
			return
		}
	}()
	c.conn.SetReadLimit(maxMessageSize)
	if err := c.conn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		return
	}
	// disable G104 (CWE-703): Errors unhandled
	// #nosec G104
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		var packet Packet
		if err := c.conn.ReadJSON(&packet); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.Errorf("%v", err)
			}
			if websocket.IsCloseError(err, websocket.CloseGoingAway) {
				break
			}

			logger.Errorf("reading message: %v", err)
			break
		}

		// Switch here over possible socket events and pull in handlers
		switch packet.Type {
		case "newEntry":
			var entry string
			if err := json.Unmarshal(packet.Content, &entry); err != nil {
				logger.Errorf("Error reading json packet: %+v", err)
			}
			if err := c.hub.cb.AddEntry(entry); err != nil {
				logger.Errorf("Error creating Clipboard entry: %+v", err)
			}
			c.refreshClipboard()

		case "delEntry":
			var id string
			if err := json.Unmarshal(packet.Content, &id); err != nil {
				logger.Errorf("Error reading json packet: %+v", err)
			}
			iid, err := strconv.Atoi(id)
			if err != nil {
				logger.Errorf("Error reading json packet: %+v", err)
			}
			if err := c.hub.cb.DeleteEntry(iid); err != nil {
				logger.Errorf("Error to delete Clipboard entry with id: %s: %+v", string(packet.Content), err)
			}
			c.refreshClipboard()

		case "clearClipboard":
			if err := c.hub.cb.ClearClipboard(); err != nil {
				logger.Errorf("Error clearing clipboard: %+v", err)
			}
			c.refreshClipboard()

		case "command":
			var command string
			if err := json.Unmarshal(packet.Content, &command); err != nil {
				logger.Errorf("Error reading json packet: %+v", err)
			}
			logger.Debugf("Command was: %+v", command)
			output, err := cli.RunCMD(command)
			if err != nil {
				logger.Errorf("Error running command: %+v", err)
			}
			logger.Debugf("Output: %+v", output)
			c.updateCLI(output)

		default:
			logger.Warnf("The event sent via websocket cannot be handeled: %+v", packet.Type)
		}
	}
}

// writePump pumps messages from the hub to the websocket connection.
//
// A goroutine running writePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		if err := c.conn.Close(); err != nil {
			return
		}
	}()
	for {
		select {
		case message, ok := <-c.send:
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				return
			}
			if !ok {
				// The hub closed the channel.
				if err := c.conn.WriteMessage(websocket.CloseMessage, []byte{}); err != nil {
					return
				}
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			if _, err := w.Write(message); err != nil {
				return
			}

			// Add queued chat messages to the current websocket message.
			n := len(c.send)
			for i := 0; i < n; i++ {
				if _, err := w.Write(newline); err != nil {
					return
				}
				if _, err := w.Write(<-c.send); err != nil {
					return
				}
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				return
			}
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ServeWS will handle the socket connections
func ServeWS(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := wsupgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Errorf("Failed to upgrade ws: %+v", err)
		return
	}

	client := &Client{hub: hub, conn: conn, send: make(chan []byte, 1024)}
	client.hub.register <- client

	go client.writePump()
	go client.readPump()
}

func (c *Client) refreshClipboard() {
	sendPkg := &SendPacket{
		Type: "refreshClipboard",
	}
	broadcastMessage, err := json.Marshal(sendPkg)
	if err != nil {
		logger.Errorf("Unable to marshal json data in redirect: %+v", err)
	}

	c.hub.broadcast <- broadcastMessage
}

func (c *Client) updateCLI(output string) {
	sendPkg := &SendPacket{
		Type:    "updateCLI",
		Content: output,
	}
	broadcastMessage, err := json.Marshal(sendPkg)
	if err != nil {
		logger.Errorf("Unable to marshal json data in redirect: %+v", err)
	}

	c.hub.broadcast <- broadcastMessage
}
