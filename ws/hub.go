package ws

import (
	"bytes"
	"encoding/json"
	"sync"

	"goshs.de/goshs/v2/clipboard"
)

// Hub maintains the set of active clients and broadcasts messages to the
// clients.
type Hub struct {
	// Registered clients.
	clients map[*Client]bool

	// Inbound messages from the clients.
	Broadcast chan []byte

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client

	// Mutex
	mu sync.RWMutex

	// Handle clipboard
	cb *clipboard.Clipboard

	// CLI Enabled
	cliEnabled bool

	// Ring BUffers - capped storage survives client reconnect
	HTTPLog *RingBuffer
	DNSLog  *RingBuffer
	SMTPLog *RingBuffer
	SMBLog  *RingBuffer
}

// NewHub will create a new hub
func NewHub(cb *clipboard.Clipboard, cliEnabled bool) *Hub {
	return &Hub{
		Broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
		cb:         cb,
		cliEnabled: cliEnabled,
		HTTPLog:    NewRingBuffer(1000),
		DNSLog:     NewRingBuffer(1000),
		SMTPLog:    NewRingBuffer(1000),
		SMBLog:     NewRingBuffer(1000),
	}
}

// Run runs the hub
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			// Send existing history to new client
			go h.sendCatchup(client)

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case message := <-h.Broadcast:
			// Store in the appropriate ring buffer based on the type field
			h.classifyAndStore(message)
			// Fan out to all clients; collect slow/closed clients under the read lock
			var stale []*Client
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					stale = append(stale, client)
				}
			}
			h.mu.RUnlock()
			// Remove stale clients under a write lock
			if len(stale) > 0 {
				h.mu.Lock()
				for _, client := range stale {
					if _, ok := h.clients[client]; ok {
						delete(h.clients, client)
						close(client.send)
					}
				}
				h.mu.Unlock()
			}
		}
	}
}

// classifyAndStore peeks at the "type" field of the JSON message
// and stores it in the correct ring buffer.
func (h *Hub) classifyAndStore(msg []byte) {
	var peek struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(msg, &peek); err != nil {
		return
	}
	switch peek.Type {
	case "http":
		h.HTTPLog.Add(msg)
	case "dns":
		h.DNSLog.Add(msg)
	case "smtp":
		h.SMTPLog.Add(msg)
	case "smb":
		h.SMBLog.Add(msg)
	}
}

// sendCatchup serialises up to 200 entries from each buffer and sends
// them as a single "catchup" message to a newly connected client.
func (h *Hub) sendCatchup(client *Client) {
	httpEntries := h.HTTPLog.Last(200)
	dnsEntries := h.DNSLog.Last(200)
	smtpEntries := h.SMTPLog.Last(200)
	smbEntries := h.SMBLog.Last(200)

	// Marshal each slice of raw JSON messages into a JSON array
	marshal := func(entries [][]byte) json.RawMessage {
		if len(entries) == 0 {
			return json.RawMessage("[]")
		}
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, e := range entries {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.Write(e)
		}
		buf.WriteByte(']')
		return buf.Bytes()
	}

	payload := map[string]any{
		"type": "catchup",
		"http": marshal(httpEntries),
		"dns":  marshal(dnsEntries),
		"smtp": marshal(smtpEntries),
		"smb":  marshal(smbEntries),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	select {
	case client.send <- data:
	default:
	}
}
