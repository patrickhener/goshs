package smbserver

import (
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/md4"
)

// ─── NTLMDowngradeLevel.String() ─────────────────────────────────────────────

func TestNTLMDowngradeLevelString(t *testing.T) {
	require.Equal(t, "NTLMv1", DowngradeNTLMv1.String())
	require.Equal(t, "NTLMv1+ESS", DowngradeNTLMv1ESS.String())
	require.Equal(t, "NTLMv2", DowngradeNTLMv2.String())
	require.Equal(t, "NTLMv2", NTLMDowngradeLevel(99).String()) // unknown → default
}

// ─── protocolDowngradeLevel ───────────────────────────────────────────────────

func TestProtocolDowngradeLevel(t *testing.T) {
	require.Equal(t, DowngradeNTLMv1, protocolDowngradeLevel(ProtoNTLMv1))
	require.Equal(t, DowngradeNTLMv1ESS, protocolDowngradeLevel(ProtoNTLMv1ESS))
	require.Equal(t, DowngradeNTLMv2, protocolDowngradeLevel(ProtoNTLMv2))
}

// ─── isAllZeros ───────────────────────────────────────────────────────────────

func TestIsAllZeros(t *testing.T) {
	require.True(t, isAllZeros([]byte{0, 0, 0, 0}))
	require.False(t, isAllZeros([]byte{0, 0, 1, 0}))
	require.True(t, isAllZeros([]byte{}))
}

// ─── ExtractNTLM ──────────────────────────────────────────────────────────────

func TestExtractNTLM_Bare(t *testing.T) {
	bare := make([]byte, 16)
	copy(bare, "NTLMSSP\x00")
	bare[8] = 0x01 // type byte
	result := ExtractNTLM(bare)
	require.Equal(t, bare, result)
}

func TestExtractNTLM_Embedded(t *testing.T) {
	// Prepend some SPNEGO wrapper bytes then embed the NTLMSSP token
	ntlm := make([]byte, 16)
	copy(ntlm, "NTLMSSP\x00")
	wrapped := append([]byte{0xa1, 0x12, 0x30, 0x10}, ntlm...)
	result := ExtractNTLM(wrapped)
	require.NotNil(t, result)
	require.True(t, strings.HasPrefix(string(result), "NTLMSSP\x00"))
}

func TestExtractNTLM_NotFound(t *testing.T) {
	result := ExtractNTLM([]byte{0x01, 0x02, 0x03})
	require.Nil(t, result)
}

// ─── NewChallenge ─────────────────────────────────────────────────────────────

func TestNewChallenge_GeneratesRandomChallenge(t *testing.T) {
	c1, err := NewChallenge("TESTDOMAIN")
	require.NoError(t, err)
	c2, err := NewChallenge("TESTDOMAIN")
	require.NoError(t, err)
	require.NotEqual(t, c1.ServerChallenge, c2.ServerChallenge)
}

// ─── BuildChallengeMessage ────────────────────────────────────────────────────

func TestBuildChallengeMessage_Structure(t *testing.T) {
	c, err := NewChallenge("WORKGROUP")
	require.NoError(t, err)
	c.DowngradeLevel = DowngradeNTLMv2

	msg := c.BuildChallengeMessage()
	require.GreaterOrEqual(t, len(msg), 64)

	// NTLMSSP signature
	require.Equal(t, "NTLMSSP\x00", string(msg[0:8]))

	// Message type = 2 (CHALLENGE)
	msgType := binary.LittleEndian.Uint32(msg[8:12])
	require.Equal(t, uint32(NTLMSSP_CHALLENGE), msgType)

	// Server challenge is at bytes 24–31
	var sc [8]byte
	copy(sc[:], msg[24:32])
	require.Equal(t, c.ServerChallenge, sc)
}

func TestBuildChallengeMessage_AllDowngradeLevels(t *testing.T) {
	for _, level := range []NTLMDowngradeLevel{DowngradeNTLMv1, DowngradeNTLMv1ESS, DowngradeNTLMv2} {
		c, _ := NewChallenge("CORP")
		c.DowngradeLevel = level
		msg := c.BuildChallengeMessage()
		require.NotEmpty(t, msg, "level %v should produce non-empty challenge", level)
	}
}

// ─── ParseAuthMessage ─────────────────────────────────────────────────────────

func TestParseAuthMessage_TooShort(t *testing.T) {
	c, _ := NewChallenge("DOM")
	_, err := c.ParseAuthMessage(make([]byte, 10))
	require.Error(t, err)
}

func TestParseAuthMessage_BadSignature(t *testing.T) {
	c, _ := NewChallenge("DOM")
	msg := make([]byte, 72)
	copy(msg, "BADDATA\x00")
	_, err := c.ParseAuthMessage(msg)
	require.Error(t, err)
}

func TestParseAuthMessage_WrongMessageType(t *testing.T) {
	c, _ := NewChallenge("DOM")
	msg := make([]byte, 72)
	copy(msg, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:], NTLMSSP_NEGOTIATE) // type 1, not type 3
	_, err := c.ParseAuthMessage(msg)
	require.Error(t, err)
}

func TestParseAuthMessage_NullSession(t *testing.T) {
	// Null session: LmResponse and NtResponse both empty (len=0)
	c, _ := NewChallenge("DOM")
	msg := buildAuthMessage("", "", "", nil, nil, nil)
	captured, err := c.ParseAuthMessage(msg)
	require.NoError(t, err)
	require.Equal(t, "", captured.Username)
}

// ─── NTLMv2Verify ────────────────────────────────────────────────────────────

func computeNTLMv2Hash(password, username, domain string, serverChallenge [8]byte, blob []byte) []byte {
	// NT hash = MD4(UTF-16LE(password))
	pwUTF16 := utf16.Encode([]rune(password))
	pwBytes := make([]byte, len(pwUTF16)*2)
	for i, v := range pwUTF16 {
		binary.LittleEndian.PutUint16(pwBytes[i*2:], v)
	}
	h := md4.New()
	h.Write(pwBytes)
	ntlmHash := h.Sum(nil)

	// NTLMv2 Hash = HMAC_MD5(NTLMHash, UPPER(username+domain) in UTF-16LE)
	identity := strings.ToUpper(username) + domain
	identityRunes := utf16.Encode([]rune(identity))
	identityBuf := make([]byte, len(identityRunes)*2)
	for i, v := range identityRunes {
		binary.LittleEndian.PutUint16(identityBuf[i*2:], v)
	}
	mac := hmac.New(md5.New, ntlmHash)
	mac.Write(identityBuf)
	ntlmV2Hash := mac.Sum(nil)

	// NTProofStr = HMAC_MD5(NTLMv2Hash, ServerChallenge || Blob)
	proofInput := append(serverChallenge[:], blob...)
	mac2 := hmac.New(md5.New, ntlmV2Hash)
	mac2.Write(proofInput)
	return mac2.Sum(nil)
}

func TestNTLMv2Verify_CorrectPassword(t *testing.T) {
	var sc [8]byte
	copy(sc[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	blob := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
	ntProofStr := computeNTLMv2Hash("Password123", "User", "DOMAIN", sc, blob)

	captured := &CapturedHash{
		Username:        "User",
		Domain:          "DOMAIN",
		Protocol:        ProtoNTLMv2,
		ServerChallenge: sc,
		NTProofStr:      ntProofStr,
		Blob:            blob,
	}

	require.True(t, NTLMv2Verify(captured, "Password123"))
}

func TestNTLMv2Verify_WrongPassword(t *testing.T) {
	var sc [8]byte
	copy(sc[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	blob := []byte{0x10, 0x11, 0x12, 0x13}
	ntProofStr := computeNTLMv2Hash("Password123", "User", "DOMAIN", sc, blob)

	captured := &CapturedHash{
		Username:        "User",
		Domain:          "DOMAIN",
		Protocol:        ProtoNTLMv2,
		ServerChallenge: sc,
		NTProofStr:      ntProofStr,
		Blob:            blob,
	}

	require.False(t, NTLMv2Verify(captured, "WrongPassword"))
}

func TestNTLMv2Verify_EmptyPassword(t *testing.T) {
	var sc [8]byte
	blob := []byte{0x01, 0x02, 0x03, 0x04}
	ntProofStr := computeNTLMv2Hash("", "User", "DOMAIN", sc, blob)

	captured := &CapturedHash{
		Username:        "User",
		Domain:          "DOMAIN",
		Protocol:        ProtoNTLMv2,
		ServerChallenge: sc,
		NTProofStr:      ntProofStr,
		Blob:            blob,
	}

	require.True(t, NTLMv2Verify(captured, ""))
	require.False(t, NTLMv2Verify(captured, "notblank"))
}

// ─── NTLMv1Verify ────────────────────────────────────────────────────────────

// computeNTLMv1Response computes a 24-byte NTLMv1 NT response for the given
// password and 8-byte challenge, allowing us to build test vectors.
func computeNTLMv1Response(password string, challenge []byte) []byte {
	ntHash := ntHashFromPassword(password)
	key := make([]byte, 21)
	copy(key, ntHash)

	expected := make([]byte, 24)
	for i, off := range []int{0, 7, 14} {
		block, _ := des.NewCipher(expandDESKey(key[off : off+7]))
		block.Encrypt(expected[i*8:i*8+8], challenge)
	}
	return expected
}

func TestNTLMv1Verify_CorrectPassword(t *testing.T) {
	var sc [8]byte
	copy(sc[:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22})
	ntResp := computeNTLMv1Response("secret", sc[:])

	captured := &CapturedHash{
		Protocol:        ProtoNTLMv1,
		ServerChallenge: sc,
		NTResponse:      ntResp,
		LMResponse:      make([]byte, 24), // placeholder
	}

	require.True(t, NTLMv1Verify(captured, "secret"))
}

func TestNTLMv1Verify_WrongPassword(t *testing.T) {
	var sc [8]byte
	copy(sc[:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22})
	ntResp := computeNTLMv1Response("secret", sc[:])

	captured := &CapturedHash{
		Protocol:        ProtoNTLMv1,
		ServerChallenge: sc,
		NTResponse:      ntResp,
		LMResponse:      make([]byte, 24),
	}

	require.False(t, NTLMv1Verify(captured, "wrongpass"))
}

// ─── SPNEGO helpers ───────────────────────────────────────────────────────────

func TestInitialSPNEGO_NotEmpty(t *testing.T) {
	blob := InitialSPNEGO()
	require.NotEmpty(t, blob)
	// Must start with Application[0] tag 0x60
	require.Equal(t, byte(0x60), blob[0])
}

func TestChallengeToken_NotEmpty(t *testing.T) {
	ntlmMsg := make([]byte, 40)
	copy(ntlmMsg, "NTLMSSP\x00")
	token := ChallengeToken(ntlmMsg)
	require.NotEmpty(t, token)
	// Must start with [1] context tag
	require.Equal(t, byte(0xa1), token[0])
}

func TestFinalToken_NotEmpty(t *testing.T) {
	token := FinalToken()
	require.NotEmpty(t, token)
	require.Equal(t, byte(0xa1), token[0])
}

func TestNegTokenRespSelectNTLM_NotEmpty(t *testing.T) {
	token := NegTokenRespSelectNTLM()
	require.NotEmpty(t, token)
}

// ─── SignSMB2Response ─────────────────────────────────────────────────────────

func TestSignSMB2Response_SetsFlagAndSignature(t *testing.T) {
	msg := make([]byte, 64)
	signingKey := make([]byte, 16)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}

	SignSMB2Response(signingKey, msg)

	// SMB2_FLAGS_SIGNED (0x08) should be set in bytes 16–19
	flags := binary.LittleEndian.Uint32(msg[16:])
	require.NotZero(t, flags&0x00000008)

	// Signature at bytes 48–63 should be non-zero
	sig := msg[48:64]
	nonZero := false
	for _, b := range sig {
		if b != 0 {
			nonZero = true
			break
		}
	}
	require.True(t, nonZero)
}

func TestSignSMB2Response_TooShort_NoOp(t *testing.T) {
	msg := make([]byte, 32) // too short
	SignSMB2Response(make([]byte, 16), msg)
	// Should not panic and message should be unchanged (all zeros)
	for _, b := range msg {
		require.Equal(t, byte(0), b)
	}
}

// ─── buildAuthMessage helper ─────────────────────────────────────────────────

// buildAuthMessage constructs a minimal NTLMSSP Type 3 (AUTHENTICATE) message
// with the given fields. Pass nil slices for empty fields.
func buildAuthMessage(username, domain, workstation string, lmResp, ntResp, encKey []byte) []byte {
	// NTLMSSP Type 3 fixed header is 72 bytes + variable data
	encodeField := func(s string) []byte {
		if s == "" {
			return nil
		}
		runes := utf16.Encode([]rune(s))
		buf := make([]byte, len(runes)*2)
		for i, r := range runes {
			binary.LittleEndian.PutUint16(buf[i*2:], r)
		}
		return buf
	}

	lmBytes := lmResp
	ntBytes := ntResp
	domainBytes := encodeField(domain)
	userBytes := encodeField(username)
	wsBytes := encodeField(workstation)
	keyBytes := encKey

	// Calculate offsets
	baseOff := uint32(72)
	lmOff := baseOff
	ntOff := lmOff + uint32(len(lmBytes))
	domOff := ntOff + uint32(len(ntBytes))
	userOff := domOff + uint32(len(domainBytes))
	wsOff := userOff + uint32(len(userBytes))
	keyOff := wsOff + uint32(len(wsBytes))
	total := int(keyOff) + len(keyBytes)

	msg := make([]byte, total)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], NTLMSSP_AUTH)

	setField := func(off int, data []byte, start uint32) {
		binary.LittleEndian.PutUint16(msg[off:], uint16(len(data)))
		binary.LittleEndian.PutUint16(msg[off+2:], uint16(len(data)))
		binary.LittleEndian.PutUint32(msg[off+4:], start)
		if len(data) > 0 {
			copy(msg[start:], data)
		}
	}

	setField(12, lmBytes, lmOff)
	setField(20, ntBytes, ntOff)
	setField(28, domainBytes, domOff)
	setField(36, userBytes, userOff)
	setField(44, wsBytes, wsOff)
	setField(52, keyBytes, keyOff)

	return msg
}

// ─── asn1Len ──────────────────────────────────────────────────────────────────

func TestAsn1Len_Short(t *testing.T) {
	// n < 128 → single byte
	require.Equal(t, []byte{0x00}, asn1Len(0))
	require.Equal(t, []byte{0x7F}, asn1Len(127))
}

func TestAsn1Len_OneByte(t *testing.T) {
	// 128 ≤ n < 256 → 0x81 length
	require.Equal(t, []byte{0x81, 0x80}, asn1Len(128))
	require.Equal(t, []byte{0x81, 0xFF}, asn1Len(255))
}

func TestAsn1Len_TwoBytes(t *testing.T) {
	// n ≥ 256 → 0x82 high low
	require.Equal(t, []byte{0x82, 0x01, 0x00}, asn1Len(256))
	require.Equal(t, []byte{0x82, 0x02, 0x00}, asn1Len(512))
}

// ─── DeriveNTLMv2SigningKey ───────────────────────────────────────────────────

func TestDeriveNTLMv2SigningKey_NoKeyExchange(t *testing.T) {
	// Without an EncryptedRandomSessionKey the function returns the KeyExchangeKey.
	// Two calls with the same inputs must produce the same output.
	ntProofStr := make([]byte, 16)
	for i := range ntProofStr {
		ntProofStr[i] = byte(i)
	}

	key1, err := DeriveNTLMv2SigningKey("password", "user", "DOMAIN", ntProofStr, nil)
	require.NoError(t, err)

	key2, err := DeriveNTLMv2SigningKey("password", "user", "DOMAIN", ntProofStr, nil)
	require.NoError(t, err)

	require.Equal(t, key1, key2)
	require.Equal(t, 16, len(key1))
}

func TestDeriveNTLMv2SigningKey_WithKeyExchange(t *testing.T) {
	// With a 16-byte EncryptedRandomSessionKey the function RC4-decrypts it.
	ntProofStr := make([]byte, 16)
	encKey := make([]byte, 16)
	for i := range encKey {
		encKey[i] = byte(i + 1)
	}

	key, err := DeriveNTLMv2SigningKey("password", "user", "DOMAIN", ntProofStr, encKey)
	require.NoError(t, err)
	require.Equal(t, 16, len(key))
}

func TestDeriveNTLMv2SigningKey_EmptyDomain(t *testing.T) {
	ntProofStr := make([]byte, 16)
	key, err := DeriveNTLMv2SigningKey("password", "user", "", ntProofStr, nil)
	require.NoError(t, err)
	require.Equal(t, 16, len(key))
}

// ─── DeriveNTLMv1SigningKey ───────────────────────────────────────────────────

func TestDeriveNTLMv1SigningKey_NoKeyExchange(t *testing.T) {
	captured := &CapturedHash{
		Protocol: ProtoNTLMv1,
	}
	key, err := DeriveNTLMv1SigningKey("password", captured)
	require.NoError(t, err)
	require.Equal(t, 16, len(key))
}

func TestDeriveNTLMv1SigningKey_ESS(t *testing.T) {
	captured := &CapturedHash{
		Protocol:   ProtoNTLMv1ESS,
		LMResponse: make([]byte, 8),
	}
	for i := range captured.LMResponse {
		captured.LMResponse[i] = byte(i)
	}
	key, err := DeriveNTLMv1SigningKey("password", captured)
	require.NoError(t, err)
	require.Equal(t, 16, len(key))
}

func TestDeriveNTLMv1SigningKey_WithKeyExchange(t *testing.T) {
	encKey := make([]byte, 16)
	for i := range encKey {
		encKey[i] = byte(i + 0x10)
	}
	captured := &CapturedHash{
		Protocol:                  ProtoNTLMv1,
		EncryptedRandomSessionKey: encKey,
	}
	key, err := DeriveNTLMv1SigningKey("password", captured)
	require.NoError(t, err)
	require.Equal(t, 16, len(key))
}

func TestDeriveNTLMv1SigningKey_Deterministic(t *testing.T) {
	captured := &CapturedHash{Protocol: ProtoNTLMv1}
	k1, err := DeriveNTLMv1SigningKey("pass", captured)
	require.NoError(t, err)
	k2, err := DeriveNTLMv1SigningKey("pass", captured)
	require.NoError(t, err)
	require.Equal(t, k1, k2)
}

// ─── ParseAuthMessage additional branches ────────────────────────────────────

func TestParseAuthMessage_NotAuthType(t *testing.T) {
	c := &NTLMChallenge{}
	msg := make([]byte, 72)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], NTLMSSP_NEGOTIATE) // wrong type
	_, err := c.ParseAuthMessage(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an authenticate")
}

func TestParseAuthMessage_AnonymousSession(t *testing.T) {
	c := &NTLMChallenge{}
	// nil lmResp and ntResp → anonymous
	msg := buildAuthMessage("", "DOMAIN", "", nil, nil, nil)
	hash, err := c.ParseAuthMessage(msg)
	require.NoError(t, err)
	require.NotNil(t, hash)
	require.Equal(t, "", hash.Username)
}

func TestParseAuthMessage_NTLMv1(t *testing.T) {
	c := &NTLMChallenge{}
	ntResp := make([]byte, 24)
	lmResp := make([]byte, 24) // last 16 bytes are not all zeros → NTLMv1 (not ESS)
	for i := range lmResp {
		lmResp[i] = byte(i + 1)
	}
	msg := buildAuthMessage("user", "DOMAIN", "WS", lmResp, ntResp, nil)
	hash, err := c.ParseAuthMessage(msg)
	require.NoError(t, err)
	require.Equal(t, ProtoNTLMv1, hash.Protocol)
	require.Equal(t, "5500", hash.HashcatMode)
}

func TestParseAuthMessage_NTLMv1ESS(t *testing.T) {
	c := &NTLMChallenge{}
	ntResp := make([]byte, 24)
	// ESS: lmResp[0:8] = client nonce, lmResp[8:24] = all zeros
	lmResp := make([]byte, 24)
	for i := range 8 {
		lmResp[i] = byte(i + 1) // client nonce
	}
	// lmResp[8:24] stays zero
	msg := buildAuthMessage("user", "DOMAIN", "WS", lmResp, ntResp, nil)
	hash, err := c.ParseAuthMessage(msg)
	require.NoError(t, err)
	require.Equal(t, ProtoNTLMv1ESS, hash.Protocol)
}

func TestParseAuthMessage_NTLMv2(t *testing.T) {
	c := &NTLMChallenge{}
	// NT response ≥ 16 bytes (but not 24) → NTLMv2
	ntResp := make([]byte, 40) // 16-byte NTProofStr + 24-byte blob
	for i := range ntResp {
		ntResp[i] = byte(i)
	}
	msg := buildAuthMessage("user", "DOMAIN", "WS", nil, ntResp, nil)
	hash, err := c.ParseAuthMessage(msg)
	require.NoError(t, err)
	require.Equal(t, ProtoNTLMv2, hash.Protocol)
	require.Equal(t, "5600", hash.HashcatMode)
}

func TestParseAuthMessage_NTRespTooShort(t *testing.T) {
	c := &NTLMChallenge{}
	// NT response < 16 and != 0 and != 24 → error
	ntResp := make([]byte, 8)
	msg := buildAuthMessage("user", "DOMAIN", "WS", nil, ntResp, nil)
	_, err := c.ParseAuthMessage(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not 24")
}

// ─── NTLMv1Verify ESS path ───────────────────────────────────────────────────

func TestNTLMv1Verify_ESS_WrongPassword(t *testing.T) {
	// Build a captured NTLMv1+ESS hash with a known password, verify wrong pass fails.
	password := "Password"
	ntHash := ntHashFromPassword(password)

	key := make([]byte, 21)
	copy(key, ntHash)

	serverChallenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	clientNonce := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	// Effective challenge = MD5(server || client)[:8]
	h := md5.New()
	h.Write(serverChallenge[:])
	h.Write(clientNonce)
	effChallenge := h.Sum(nil)[:8]

	expected := make([]byte, 24)
	for i, off := range []int{0, 7, 14} {
		keyPart := expandDESKey(key[off : off+7])
		block, _ := des.NewCipher(keyPart)
		block.Encrypt(expected[i*8:i*8+8], effChallenge)
	}

	// LMResponse = clientNonce + 16 zero bytes (ESS format)
	lmResp := make([]byte, 24)
	copy(lmResp[:8], clientNonce)

	captured := &CapturedHash{
		Protocol:        ProtoNTLMv1ESS,
		ServerChallenge: serverChallenge,
		LMResponse:      lmResp,
		NTResponse:      expected,
	}

	require.True(t, NTLMv1Verify(captured, password))
	require.False(t, NTLMv1Verify(captured, "wrongpassword"))
}
