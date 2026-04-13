package smbserver

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/md4"
)

// makeNTLMv2Hash builds a valid CapturedHash for a known password so
// that verifyCandidate / TryCrackDefault can find it.
func makeNTLMv2CapturedHash(password, username, domain string) *CapturedHash {
	var sc [8]byte
	// Fixed server challenge so the test is deterministic.
	copy(sc[:], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	blob := []byte{0xca, 0xfe, 0xba, 0xbe}

	ntProofStr := computeNTLMv2Proof(password, username, domain, sc, blob)

	return &CapturedHash{
		Username:        username,
		Domain:          domain,
		Protocol:        ProtoNTLMv2,
		ServerChallenge: sc,
		NTProofStr:      ntProofStr,
		Blob:            blob,
	}
}

// computeNTLMv2Proof is a local helper that reproduces the NTLMv2 proof
// so we can create valid test vectors without calling NTLMv2Verify.
func computeNTLMv2Proof(password, username, domain string, sc [8]byte, blob []byte) []byte {
	pwUTF16 := utf16.Encode([]rune(password))
	pwBytes := make([]byte, len(pwUTF16)*2)
	for i, v := range pwUTF16 {
		binary.LittleEndian.PutUint16(pwBytes[i*2:], v)
	}
	h := md4.New()
	h.Write(pwBytes)
	ntHash := h.Sum(nil)

	identity := strings.ToUpper(username) + domain
	identRunes := utf16.Encode([]rune(identity))
	identBuf := make([]byte, len(identRunes)*2)
	for i, v := range identRunes {
		binary.LittleEndian.PutUint16(identBuf[i*2:], v)
	}
	v2Hash := hmacMD5bytes(ntHash, identBuf)
	return hmacMD5bytes(v2Hash, append(sc[:], blob...))
}

// ─── buildDefaultWordlist ─────────────────────────────────────────────────────

func TestBuildDefaultWordlist_ContainsCommonPasswords(t *testing.T) {
	wl := buildDefaultWordlist("", "")
	wlStr := strings.Join(wl, "\n")

	commons := []string{"password", "Password123", "P@ssw0rd", "admin123", "qwerty", "123456789"}
	for _, pw := range commons {
		require.Contains(t, wlStr, pw, "wordlist should contain common password %q", pw)
	}
}

func TestBuildDefaultWordlist_ContainsUsernameVariants(t *testing.T) {
	wl := buildDefaultWordlist("alice", "CORP")
	wlStr := strings.Join(wl, "\n")

	// Username variants
	require.Contains(t, wlStr, "alice")
	require.Contains(t, wlStr, "Alice")
	require.Contains(t, wlStr, "ALICE")
	require.Contains(t, wlStr, "alice1")
	require.Contains(t, wlStr, "alice123")
}

func TestBuildDefaultWordlist_ContainsDomainVariants(t *testing.T) {
	wl := buildDefaultWordlist("user", "corp")
	wlStr := strings.Join(wl, "\n")

	require.Contains(t, wlStr, "corp")
	require.Contains(t, wlStr, "Corp")
	require.Contains(t, wlStr, "corp1")
	require.Contains(t, wlStr, "corp123")
}

func TestBuildDefaultWordlist_ContainsEmptyPassword(t *testing.T) {
	wl := buildDefaultWordlist("", "")
	require.Contains(t, wl, "")
}

func TestBuildDefaultWordlist_EmptyUsernameAndDomain(t *testing.T) {
	wl := buildDefaultWordlist("", "")
	require.NotEmpty(t, wl)
}

// ─── TryCrackDefault ─────────────────────────────────────────────────────────

func TestTryCrackDefault_WeakPasswordFound(t *testing.T) {
	// "password" is in the default wordlist
	captured := makeNTLMv2CapturedHash("password", "testuser", "TESTDOMAIN")
	pw, ok := TryCrackDefault(captured)
	require.True(t, ok)
	require.Equal(t, "password", pw)
}

func TestTryCrackDefault_UsernameAsPassword(t *testing.T) {
	// "alice" as password — in the username-based dynamic list
	captured := makeNTLMv2CapturedHash("alice", "alice", "DOMAIN")
	pw, ok := TryCrackDefault(captured)
	require.True(t, ok)
	require.Equal(t, "alice", pw)
}

func TestTryCrackDefault_StrongPasswordNotFound(t *testing.T) {
	// A password that will never appear in the default wordlist
	captured := makeNTLMv2CapturedHash("xK9!mZ#qW3@vL7pN", "user", "CORP")
	_, ok := TryCrackDefault(captured)
	require.False(t, ok)
}

func TestTryCrackDefault_EmptyPassword(t *testing.T) {
	captured := makeNTLMv2CapturedHash("", "user", "CORP")
	pw, ok := TryCrackDefault(captured)
	require.True(t, ok)
	require.Equal(t, "", pw)
}

// ─── TryCrackFile ─────────────────────────────────────────────────────────────

func TestTryCrackFile_PasswordInWordlist(t *testing.T) {
	wordlist := "notthis\nnotthiseither\nSuperSecret99!\nalsowrong\n"
	f, err := os.CreateTemp(t.TempDir(), "wordlist-*.txt")
	require.NoError(t, err)
	_, err = f.WriteString(wordlist)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	captured := makeNTLMv2CapturedHash("SuperSecret99!", "admin", "DOM")
	pw, ok := TryCrackFile(captured, f.Name())
	require.True(t, ok)
	require.Equal(t, "SuperSecret99!", pw)
}

func TestTryCrackFile_PasswordNotInWordlist(t *testing.T) {
	wordlist := "wrong1\nwrong2\nwrong3\n"
	f, err := os.CreateTemp(t.TempDir(), "wordlist-*.txt")
	require.NoError(t, err)
	_, err = f.WriteString(wordlist)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	captured := makeNTLMv2CapturedHash("NotInList!XYZ", "admin", "DOM")
	_, ok := TryCrackFile(captured, f.Name())
	require.False(t, ok)
}

func TestTryCrackFile_FileNotFound(t *testing.T) {
	captured := makeNTLMv2CapturedHash("pass", "user", "dom")
	_, ok := TryCrackFile(captured, "/nonexistent/path/wordlist.txt")
	require.False(t, ok)
}

// ─── verifyCandidate (NTLMv1) ─────────────────────────────────────────────────

func TestVerifyCandidate_NTLMv1(t *testing.T) {
	var sc [8]byte
	copy(sc[:], []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})
	ntResp := computeNTLMv1Response("letmein", sc[:])

	captured := &CapturedHash{
		Protocol:        ProtoNTLMv1,
		ServerChallenge: sc,
		NTResponse:      ntResp,
		LMResponse:      make([]byte, 24),
	}

	require.True(t, verifyCandidate(captured, "letmein"))
	require.False(t, verifyCandidate(captured, "wrongpass"))
}

// computeNTLMv1Response is defined in ntlm_test.go (same package).
