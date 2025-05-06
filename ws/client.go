package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"
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
		if err := c.conn.Close(websocket.StatusNormalClosure, ""); err != nil {
			return
		}
	}()

	for {
		_, data, err := c.conn.Read(context.Background())
		if err != nil {
			break
		}
		var packet Packet
		if err := json.Unmarshal(data, &packet); err != nil {
			continue
		}

		// Switch over possible socket events
		c.dispatchReadPump(packet)
	}
}

func (c *Client) dispatchReadPump(packet Packet) {
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
		if c.hub.cliEnabled {
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
		}

	default:
		logger.Warnf("The event sent via websocket cannot be handeled: %+v", packet.Type)
	}

}

// writePump pumps messages from the hub to the websocket connection.
//
// A goroutine running writePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
func (c *Client) writePump() {
	for sendPacket := range c.send {
		c.conn.Write(context.Background(), websocket.MessageText, sendPacket)
	}
}

// ServeWS will handle the socket connections
func ServeWS(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
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
