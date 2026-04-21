package ws

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// ─── classifyAndStore ─────────────────────────────────────────────────────────

func newTestHub() *Hub {
	return &Hub{
		HTTPLog: NewRingBuffer(100),
		DNSLog:  NewRingBuffer(100),
		SMTPLog: NewRingBuffer(100),
		SMBLog:  NewRingBuffer(100),
	}
}

func TestClassifyAndStore_HTTP(t *testing.T) {
	h := newTestHub()
	msg := []byte(`{"type":"http","path":"/"}`)
	h.classifyAndStore(msg)
	require.Equal(t, 1, len(h.HTTPLog.Last(10)))
	require.Equal(t, 0, len(h.DNSLog.Last(10)))
}

func TestClassifyAndStore_DNS(t *testing.T) {
	h := newTestHub()
	msg := []byte(`{"type":"dns","query":"example.com"}`)
	h.classifyAndStore(msg)
	require.Equal(t, 1, len(h.DNSLog.Last(10)))
	require.Equal(t, 0, len(h.HTTPLog.Last(10)))
}

func TestClassifyAndStore_SMTP(t *testing.T) {
	h := newTestHub()
	msg := []byte(`{"type":"smtp","from":"a@b.com"}`)
	h.classifyAndStore(msg)
	require.Equal(t, 1, len(h.SMTPLog.Last(10)))
}

func TestClassifyAndStore_SMB(t *testing.T) {
	h := newTestHub()
	msg := []byte(`{"type":"smb","file":"test.txt"}`)
	h.classifyAndStore(msg)
	require.Equal(t, 1, len(h.SMBLog.Last(10)))
}

func TestClassifyAndStore_Unknown(t *testing.T) {
	h := newTestHub()
	msg := []byte(`{"type":"unknown","x":"y"}`)
	h.classifyAndStore(msg)
	require.Equal(t, 0, len(h.HTTPLog.Last(10)))
	require.Equal(t, 0, len(h.DNSLog.Last(10)))
	require.Equal(t, 0, len(h.SMTPLog.Last(10)))
	require.Equal(t, 0, len(h.SMBLog.Last(10)))
}

func TestClassifyAndStore_InvalidJSON(t *testing.T) {
	h := newTestHub()
	h.classifyAndStore([]byte(`not json`))
	// Nothing added, no panic
	require.Equal(t, 0, len(h.HTTPLog.Last(10)))
}

func TestClassifyAndStore_MultipleEntries(t *testing.T) {
	h := newTestHub()
	for i := 0; i < 5; i++ {
		h.classifyAndStore([]byte(`{"type":"http"}`))
	}
	require.Equal(t, 5, len(h.HTTPLog.Last(10)))
}

// ─── sendCatchup ─────────────────────────────────────────────────────────────

func TestSendCatchup_EmptyBuffers(t *testing.T) {
	h := newTestHub()
	client := &Client{send: make(chan []byte, 1)}

	h.sendCatchup(client)

	select {
	case msg := <-client.send:
		var payload map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(msg, &payload))
		require.Equal(t, `"catchup"`, string(payload["type"]))
		require.Equal(t, "[]", string(payload["http"]))
		require.Equal(t, "[]", string(payload["dns"]))
		require.Equal(t, "[]", string(payload["smtp"]))
		require.Equal(t, "[]", string(payload["smb"]))
	default:
		t.Fatal("sendCatchup did not send any message")
	}
}

func TestSendCatchup_WithEntries(t *testing.T) {
	h := newTestHub()
	h.HTTPLog.Add([]byte(`{"type":"http","path":"/a"}`))
	h.HTTPLog.Add([]byte(`{"type":"http","path":"/b"}`))
	h.DNSLog.Add([]byte(`{"type":"dns","query":"foo.com"}`))

	client := &Client{send: make(chan []byte, 1)}
	h.sendCatchup(client)

	msg := <-client.send
	var payload map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(msg, &payload))

	var httpEntries []json.RawMessage
	require.NoError(t, json.Unmarshal(payload["http"], &httpEntries))
	require.Equal(t, 2, len(httpEntries))

	var dnsEntries []json.RawMessage
	require.NoError(t, json.Unmarshal(payload["dns"], &dnsEntries))
	require.Equal(t, 1, len(dnsEntries))
}

func TestSendCatchup_FullChannelDrops(t *testing.T) {
	h := newTestHub()
	// Non-buffered channel — send should not block, falls through the default
	client := &Client{send: make(chan []byte)}
	require.NotPanics(t, func() { h.sendCatchup(client) })
}
