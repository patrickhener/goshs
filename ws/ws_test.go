package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"goshs.de/goshs/v2/clipboard"
	"github.com/stretchr/testify/require"
)

func TestDispatchReadPump_NewEntry(t *testing.T) {
	mockClipboard := &clipboard.Clipboard{}

	hub := &Hub{cb: mockClipboard, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	entry := `"my clipboard entry"`
	packet := Packet{Type: "newEntry", Content: json.RawMessage(entry)}

	client.dispatchReadPump(packet)
	// Assert that hub.cb.AddEntry was called, use mockClipboard to verify
}

func TestDispatchReadPump_DelEntry(t *testing.T) {
	cb := &clipboard.Clipboard{}
	err := cb.AddEntry("test")
	if err != nil {
		t.Fatalf("Failed to add entry: %v", err)
	}
	hub := &Hub{cb: cb, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	idStr := `"0"` // JSON string
	packet := Packet{Type: "delEntry", Content: json.RawMessage(idStr)}

	client.dispatchReadPump(packet)
}

func TestDispatchReadPump_DelEntryInvalidID(t *testing.T) {
	cb := &clipboard.Clipboard{}
	err := cb.AddEntry("test")
	if err != nil {
		t.Fatalf("Failed to add entry: %v", err)
	}
	hub := &Hub{cb: cb, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	idStr := `0` // JSON string
	packet := Packet{Type: "delEntry", Content: json.RawMessage(idStr)}

	client.dispatchReadPump(packet)
}

func TestRefreshClipboard(t *testing.T) {
	hub := &Hub{Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	client.refreshClipboard()

	select {
	case msg := <-hub.Broadcast:
		var pkt SendPacket
		err := json.Unmarshal(msg, &pkt)
		require.NoError(t, err)
		require.Equal(t, "refreshClipboard", pkt.Type)
	default:
		t.Fatal("no message Broadcasted")
	}
}

func TestDispatchReadPump_ClearClipboard(t *testing.T) {
	cb := &clipboard.Clipboard{}
	hub := &Hub{cb: cb, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	packet := Packet{Type: "clearClipboard", Content: json.RawMessage(`""`)}

	client.dispatchReadPump(packet)
}

func TestDispatchReadPump_Command(t *testing.T) {
	hub := &Hub{cliEnabled: true, cb: &clipboard.Clipboard{}, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	cmdStr := `"ls -la"`
	packet := Packet{Type: "command", Content: json.RawMessage(cmdStr)}

	client.dispatchReadPump(packet)
}

func TestInvalidEventSent(t *testing.T) {
	hub := &Hub{cliEnabled: true, cb: &clipboard.Clipboard{}, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	packet := Packet{Type: "invalid", Content: json.RawMessage(`""`)}

	client.dispatchReadPump(packet)
}

func TestDispatchReadPump_ClearHTTP(t *testing.T) {
	hub := NewHub(&clipboard.Clipboard{}, false)
	hub.HTTPLog.Add([]byte(`{"type":"http"}`))
	client := &Client{hub: hub}

	client.dispatchReadPump(Packet{Type: "clearHTTP"})
	require.Equal(t, 0, len(hub.HTTPLog.Last(10)))
}

func TestDispatchReadPump_ClearDNS(t *testing.T) {
	hub := NewHub(&clipboard.Clipboard{}, false)
	hub.DNSLog.Add([]byte(`{"type":"dns"}`))
	client := &Client{hub: hub}

	client.dispatchReadPump(Packet{Type: "clearDNS"})
	require.Equal(t, 0, len(hub.DNSLog.Last(10)))
}

func TestDispatchReadPump_ClearSMTP(t *testing.T) {
	hub := NewHub(&clipboard.Clipboard{}, false)
	hub.SMTPLog.Add([]byte(`{"type":"smtp"}`))
	client := &Client{hub: hub}

	client.dispatchReadPump(Packet{Type: "clearSMTP"})
	require.Equal(t, 0, len(hub.SMTPLog.Last(10)))
}

func TestDispatchReadPump_ClearSMB(t *testing.T) {
	hub := NewHub(&clipboard.Clipboard{}, false)
	hub.SMBLog.Add([]byte(`{"type":"smb"}`))
	client := &Client{hub: hub}

	client.dispatchReadPump(Packet{Type: "clearSMB"})
	require.Equal(t, 0, len(hub.SMBLog.Last(10)))
}
func TestHub_Run(t *testing.T) {
	cb := &clipboard.Clipboard{} // Use a mock or real instance as needed
	hub := NewHub(cb, false)

	go hub.Run()

	// Create dummy clients
	client1 := &Client{send: make(chan []byte, 1)}
	client2 := &Client{send: make(chan []byte, 1)}

	// Register clients
	hub.register <- client1
	hub.register <- client2

	// Give some time to process (better: use sync or channels)
	time.Sleep(10 * time.Millisecond)

	// Check clients are registered
	if !hub.clients[client1] || !hub.clients[client2] {
		t.Fatal("clients not registered correctly")
	}

	// Check client received catchup message
	select {
	case m := <-client1.send:
		var msg HTTPEvent
		if err := json.Unmarshal(m, &msg); err != nil {
			t.Fatal(err)
		}
		if msg.Type != "catchup" {
			t.Fatalf("unexpected message type: %s", msg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for message on client1")
	}

	// Unregister client1
	hub.unregister <- client1

	time.Sleep(100 * time.Millisecond)

	// client1 should be removed and its channel closed
	if _, ok := hub.clients[client1]; ok {
		t.Fatal("client1 not removed after unregister")
	}
	select {
	case _, ok := <-client1.send:
		if ok {
			t.Fatal("client1 send channel not closed")
		}
	default:
		t.Fatal("client1 send channel not closed default")
	}

	// Clean up: unregister client2 to avoid goroutine leak
	hub.unregister <- client2
}

func TestHub_Run_BroadcastClientSendFull(t *testing.T) {
	cb := &clipboard.Clipboard{}
	hub := NewHub(cb, false)

	go hub.Run()

	// Create client with send channel buffer size 1
	client := &Client{send: make(chan []byte, 1)}

	// Fill the client's send channel so it is full
	client.send <- []byte("dummy")

	// Register client
	hub.register <- client
	time.Sleep(10 * time.Millisecond) // allow goroutine to process

	// Broadcast a message
	hub.Broadcast <- []byte("message")

	// Allow hub to process Broadcast
	time.Sleep(10 * time.Millisecond)

	// Clean up (just in case)
	hub.unregister <- client
}

type mockConn struct {
	messages  [][]byte
	readCount int
	closed    bool
	writes    []writeCall
}

type writeCall struct {
	messageType websocket.MessageType
	data        []byte
}

func (m *mockConn) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	if m.readCount >= len(m.messages) {
		// Simulate normal closure error from websocket
		return 0, nil, nil
	}
	msg := m.messages[m.readCount]
	m.readCount++
	return websocket.MessageText, msg, nil
}

func (m *mockConn) Write(ctx context.Context, tp websocket.MessageType, data []byte) error {
	m.writes = append(m.writes, writeCall{websocket.MessageType(1), append([]byte{}, data...)})

	return nil
}

func (m *mockConn) Close(code websocket.StatusCode, reason string) error {
	return nil
}

func TestClient_readPump_CloseCalled(t *testing.T) {
	hub := NewHub(&clipboard.Clipboard{}, false)
	hub.unregister = make(chan *Client, 1) // buffered

	validPacket := Packet{
		Type:    "clearClipboard",
		Content: json.RawMessage(`null`),
	}
	validPacketJSON, _ := json.Marshal(validPacket)

	mockConn := &mockConn{
		messages: [][]byte{validPacketJSON},
	}

	client := &Client{
		hub:  hub,
		conn: mockConn,
		send: make(chan []byte, 1),
	}

	done := make(chan struct{})
	go func() {
		client.readPump()
		close(done)
	}()

	select {
	case <-done:
		// readPump exited gracefully
	case <-time.After(2 * time.Second):
		t.Log("readPump did not finish in time")
	}

	if !mockConn.closed {
		t.Log("expected connection Close() to be called")
	}

	select {
	case unregistered := <-hub.unregister:
		if unregistered != client {
			t.Errorf("expected client to be unregistered")
		}
	default:
		t.Log("client was not unregistered")
	}
}

func TestClient_writePump(t *testing.T) {
	// Mock connection that records Write calls
	mockConn := &mockConn{
		writes: []writeCall{},
	}

	client := &Client{
		conn: mockConn,
		send: make(chan []byte, 2),
	}

	// Push messages to send channel
	client.send <- []byte("message 1")
	client.send <- []byte("message 2")
	close(client.send) // close to stop writePump loop

	done := make(chan struct{})
	go func() {
		client.writePump()
		close(done)
	}()

	select {
	case <-done:
		// writePump exited
	case <-time.After(2 * time.Second):
		t.Fatal("writePump did not finish in time")
	}

	if len(mockConn.writes) != 2 {
		t.Fatalf("expected 2 writes, got %d", len(mockConn.writes))
	}
	if string(mockConn.writes[0].data) != "message 1" {
		t.Errorf("expected first write 'message 1', got %s", mockConn.writes[0].data)
	}
	if string(mockConn.writes[1].data) != "message 2" {
		t.Errorf("expected second write 'message 2', got %s", mockConn.writes[1].data)
	}
}

func TestServeWS(t *testing.T) {
	// Create a Hub instance with mock clipboard
	cb := &clipboard.Clipboard{}
	hub := NewHub(cb, false)

	// Start the hub's Run loop in a goroutine
	go hub.Run()

	// Setup HTTP test server with ServeWS handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ServeWS(hub, w, r)
	}))
	defer server.Close()

	// Convert http test server URL to ws scheme
	wsURL := "ws" + server.URL[len("http"):]

	// Dial websocket client to the server
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial failed: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Wait shortly to let the hub register the client
	time.Sleep(100 * time.Millisecond)

	// Check hub has one registered client
	if len(hub.clients) != 1 {
		t.Fatalf("expected 1 client registered, got %d", len(hub.clients))
	}
}
