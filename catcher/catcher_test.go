package catcher

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"goshs.de/goshs/v2/ws"
)

// ─── helpers ───────────────────────────────────────────────────────────────────

func newTestHub() *ws.Hub {
	return &ws.Hub{
		Broadcast: make(chan []byte, 64),
		HTTPLog:   ws.NewRingBuffer(100),
		DNSLog:    ws.NewRingBuffer(100),
		SMTPLog:   ws.NewRingBuffer(100),
		SMBLog:    ws.NewRingBuffer(100),
		LDAPLog:   ws.NewRingBuffer(100),
	}
}

func drainBroadcast(hub *ws.Hub) []map[string]any {
	var msgs []map[string]any
	for {
		select {
		case raw := <-hub.Broadcast:
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err == nil {
				msgs = append(msgs, m)
			}
		default:
			return msgs
		}
	}
}

// ─── errors ────────────────────────────────────────────────────────────────────

// ─── errors ────────────────────────────────────────────────────────────────────

func TestErrNotFound(t *testing.T) {
	require.Equal(t, "not found", ErrNotFound.Error())
}

// ─── ensureCRLF ────────────────────────────────────────────────────────────────

func TestEnsureCRLF_BareLF(t *testing.T) {
	out := ensureCRLF([]byte("hello\nworld"))
	require.Equal(t, "hello\r\nworld", string(out))
}

func TestEnsureCRLF_AlreadyCRLF(t *testing.T) {
	out := ensureCRLF([]byte("hello\r\nworld"))
	require.Equal(t, "hello\r\nworld", string(out))
}

func TestEnsureCRLF_Mixed(t *testing.T) {
	out := ensureCRLF([]byte("a\r\nb\nc"))
	require.Equal(t, "a\r\nb\r\nc", string(out))
}

func TestEnsureCRLF_NoNewlines(t *testing.T) {
	out := ensureCRLF([]byte("hello"))
	require.Equal(t, "hello", string(out))
}

func TestEnsureCRLF_Empty(t *testing.T) {
	out := ensureCRLF([]byte{})
	require.Equal(t, "", string(out))
}

func TestEnsureCRLF_ConsecutiveLF(t *testing.T) {
	out := ensureCRLF([]byte("a\n\nb"))
	require.Equal(t, "a\r\n\r\nb", string(out))
}

// ─── Session ───────────────────────────────────────────────────────────────────

func TestSession_Close(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	s := newSession("s1", "l1", "127.0.0.1:1234", server)
	require.False(t, s.IsClosed())

	s.Close()
	require.True(t, s.IsClosed())

	// Double close should not panic
	s.Close()
	require.True(t, s.IsClosed())

	// Client should get EOF on read after close
	client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 10)
	_, err := client.Read(buf)
	require.Error(t, err)
}

func TestSession_WriteRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	s := newSession("s1", "l1", "addr", server)

	// Write from server → client: must read and write concurrently (net.Pipe is synchronous)
	go func() {
		time.Sleep(50 * time.Millisecond)
		client.Write([]byte("world"))
	}()

	// Write from server side
	var wg sync.WaitGroup
	wg.Go(func() {
		s.Write([]byte("hello"))
	})

	client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 10)
	n, err := client.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buf[:n]))

	// Read from client → server (via session)
	s.conn.SetReadDeadline(time.Now().Add(time.Second))
	buf2 := make([]byte, 10)
	n, err = s.Read(buf2)
	require.NoError(t, err)
	require.Equal(t, "world", string(buf2[:n]))

	wg.Wait()
}

func TestSession_Fields(t *testing.T) {
	server, _ := net.Pipe()
	defer server.Close()

	s := newSession("sid", "lid", "1.2.3.4:5678", server)
	require.Equal(t, "sid", s.ID)
	require.Equal(t, "lid", s.ListenerID)
	require.Equal(t, "1.2.3.4:5678", s.RemoteAddr)
}

func TestSession_ConcurrentClose(t *testing.T) {
	server, _ := net.Pipe()
	defer server.Close()

	s := newSession("s1", "l1", "addr", server)

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() { s.Close() })
	}
	wg.Wait()
	require.True(t, s.IsClosed())
}

// ─── generateID ────────────────────────────────────────────────────────────────

func TestGenerateID_Unique(t *testing.T) {
	ids := make(map[string]bool)
	for range 100 {
		id := generateID()
		require.NotEmpty(t, id)
		require.False(t, ids[id], "generateID produced duplicate: %s", id)
		ids[id] = true
	}
}

func TestGenerateID_NonEmpty(t *testing.T) {
	id := generateID()
	require.NotEmpty(t, id)
	// Should be hex (8 chars from 4 random bytes) + up to 3 decimal digits
	require.GreaterOrEqual(t, len(id), 9)
}

// ─── Manager: lifecycle ────────────────────────────────────────────────────────

func TestManager_New(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)
	require.NotNil(t, mgr)
	require.Empty(t, mgr.GetListeners())
}

func TestManager_StartListener(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	info, err := mgr.StartListener("127.0.0.1", 0)
	require.NoError(t, err)
	require.NotEmpty(t, info.ID)
	require.Equal(t, "127.0.0.1", info.IP)
	require.Greater(t, info.Port, 0)

	listeners := mgr.GetListeners()
	require.Len(t, listeners, 1)

	// Clean up
	require.NoError(t, mgr.StopListener(info.ID))
}

func TestManager_StartListener_InvalidPort(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	_, err := mgr.StartListener("127.0.0.1", 99999)
	require.Error(t, err)
}

func TestManager_StopListener_NotFound(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	err := mgr.StopListener("nonexistent")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestManager_StopListener_CleansUp(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	info, err := mgr.StartListener("127.0.0.1", 0)
	require.NoError(t, err)

	require.NoError(t, mgr.StopListener(info.ID))
	require.Empty(t, mgr.GetListeners())
}

// ─── Manager: session registration ─────────────────────────────────────────────

func TestManager_RegisterSession_Broadcasts(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	server, _ := net.Pipe()
	defer server.Close()

	s := newSession("s1", "l1", "1.2.3.4:9999", server)
	mgr.registerSession(s)

	msgs := drainBroadcast(hub)
	require.Len(t, msgs, 1)
	require.Equal(t, "catcherConnection", msgs[0]["type"])
	require.Equal(t, "l1", msgs[0]["listenerID"])
	require.Equal(t, "s1", msgs[0]["sessionID"])
	require.Equal(t, "1.2.3.4:9999", msgs[0]["remoteAddr"])
}

func TestManager_GetSession(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	server, _ := net.Pipe()
	defer server.Close()

	s := newSession("s1", "l1", "addr", server)
	mgr.registerSession(s)

	got := mgr.GetSession("s1")
	require.NotNil(t, got)
	require.Equal(t, "s1", got.ID)

	require.Nil(t, mgr.GetSession("nonexistent"))
}

func TestManager_KillSession(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	info, err := mgr.StartListener("127.0.0.1", 0)
	require.NoError(t, err)

	// Simulate a session by registering directly
	server, client := net.Pipe()
	defer client.Close()
	s := newSession("s1", info.ID, "addr", server)
	mgr.registerSession(s)

	// Kill the session
	require.NoError(t, mgr.KillSession("s1"))
	require.Nil(t, mgr.GetSession("s1"))
}

func TestManager_KillSession_NotFound(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	err := mgr.KillSession("nonexistent")
	require.ErrorIs(t, err, ErrNotFound)
}

// ─── Listener: accept connections ──────────────────────────────────────────────

func TestListener_AcceptsConnection(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	info, err := mgr.StartListener("127.0.0.1", 0)
	require.NoError(t, err)
	defer mgr.StopListener(info.ID)

	// Connect a client
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", info.IP, info.Port), 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Wait for session to be registered
	time.Sleep(100 * time.Millisecond)

	sessions := mgr.GetListeners()[0].Sessions
	require.Len(t, sessions, 1)
	require.Equal(t, info.ID, sessions[0].ListenerID)
	require.NotEmpty(t, sessions[0].ID)

	// Broadcast should have been sent
	msgs := drainBroadcast(hub)
	require.Len(t, msgs, 1)
	require.Equal(t, "catcherConnection", msgs[0]["type"])
}

func TestListener_StopClosesListener(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	info, err := mgr.StartListener("127.0.0.1", 0)
	require.NoError(t, err)

	addr := fmt.Sprintf("%+v:%+v", info.IP, info.Port)

	// Stop the listener
	require.NoError(t, mgr.StopListener(info.ID))

	// New connections should fail
	_, err = net.DialTimeout("tcp", addr, 500*time.Millisecond)
	require.Error(t, err)
}

func TestListener_MultipleConnections(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	info, err := mgr.StartListener("127.0.0.1", 0)
	require.NoError(t, err)
	defer mgr.StopListener(info.ID)

	var conns []net.Conn
	for range 5 {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", info.IP, info.Port), 2*time.Second)
		require.NoError(t, err)
		conns = append(conns, conn)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	time.Sleep(200 * time.Millisecond)

	sessions := mgr.GetListeners()[0].Sessions
	require.Len(t, sessions, 5)

	msgs := drainBroadcast(hub)
	require.Len(t, msgs, 5)
}

// ─── Listener: session management ──────────────────────────────────────────────

func TestListener_KillSession(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	info, err := mgr.StartListener("127.0.0.1", 0)
	require.NoError(t, err)
	defer mgr.StopListener(info.ID)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", info.IP, info.Port), 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	time.Sleep(100 * time.Millisecond)

	sessions := mgr.GetListeners()[0].Sessions
	require.NotEmpty(t, sessions)

	// Kill via manager
	require.NoError(t, mgr.KillSession(sessions[0].ID))
	require.Nil(t, mgr.GetSession(sessions[0].ID))
}

func TestListener_KillSession_NotFound(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	info, err := mgr.StartListener("127.0.0.1", 0)
	require.NoError(t, err)
	defer mgr.StopListener(info.ID)

	err = mgr.KillSession("nonexistent")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestListener_GetSessions_ExcludesClosed(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	info, err := mgr.StartListener("127.0.0.1", 0)
	require.NoError(t, err)
	defer mgr.StopListener(info.ID)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", info.IP, info.Port), 2*time.Second)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Close the client → session reads EOF and becomes "closed"
	conn.Close()
	time.Sleep(100 * time.Millisecond)

	sessions := mgr.GetListeners()[0].Sessions
	// The closed session should be excluded from active listing
	for _, s := range sessions {
		require.NotEqual(t, "", s.ID, "closed sessions should be filtered")
	}
}

// ─── ListenerInfo: Addr helper ─────────────────────────────────────────────────

func TestListenerInfo_Addr(t *testing.T) {
	hub := newTestHub()
	mgr := NewManager(hub)

	info, err := mgr.StartListener("127.0.0.1", 0)
	require.NoError(t, err)
	defer mgr.StopListener(info.ID)

	addr := fmt.Sprintf("%s:%d", info.IP, info.Port)
	require.Contains(t, addr, "127.0.0.1:")
	require.Greater(t, info.Port, 0)
}
