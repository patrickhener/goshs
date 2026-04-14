package smtpserver

import (
	"bytes"
	"encoding/base64"
	"net/textproto"
	"strings"
	"testing"

	"goshs.de/goshs/ws"
	"github.com/stretchr/testify/require"
)

// ─── Rcpt / domain filtering ──────────────────────────────────────────────────

func TestRcpt_NoDomainRestriction_AcceptsAll(t *testing.T) {
	s := &Session{domain: ""}
	err := s.Rcpt("anyone@example.com", nil)
	require.NoError(t, err)
	require.Equal(t, []string{"anyone@example.com"}, s.to)
}

func TestRcpt_DomainRestriction_AcceptsMatchingDomain(t *testing.T) {
	s := &Session{domain: "corp.local"}
	err := s.Rcpt("user@corp.local", nil)
	require.NoError(t, err)
}

func TestRcpt_DomainRestriction_RejectsOtherDomain(t *testing.T) {
	s := &Session{domain: "corp.local"}
	err := s.Rcpt("user@external.com", nil)
	require.Error(t, err)
}

func TestRcpt_DomainRestriction_CaseInsensitive(t *testing.T) {
	s := &Session{domain: "CORP.LOCAL"}
	err := s.Rcpt("user@corp.local", nil)
	require.NoError(t, err)
}

func TestRcpt_DomainRestriction_InvalidAddress(t *testing.T) {
	s := &Session{domain: "corp.local"}
	err := s.Rcpt("invalidemail", nil)
	require.Error(t, err)
}

func TestRcpt_MultipleRecipients(t *testing.T) {
	s := &Session{domain: ""}
	require.NoError(t, s.Rcpt("alice@example.com", nil))
	require.NoError(t, s.Rcpt("bob@example.com", nil))
	require.Equal(t, []string{"alice@example.com", "bob@example.com"}, s.to)
}

func TestReset(t *testing.T) {
	s := &Session{to: []string{"a@b.com"}}
	s.Reset()
	require.Empty(t, s.to)
}

// ─── parseAddressList ─────────────────────────────────────────────────────────

func TestParseAddressList_SingleAddress(t *testing.T) {
	result := parseAddressList("alice@example.com")
	require.Equal(t, []string{"alice@example.com"}, result)
}

func TestParseAddressList_MultipleAddresses(t *testing.T) {
	result := parseAddressList("alice@example.com, bob@example.com")
	require.ElementsMatch(t, []string{"alice@example.com", "bob@example.com"}, result)
}

func TestParseAddressList_Empty(t *testing.T) {
	result := parseAddressList("")
	require.Nil(t, result)
}

func TestParseAddressList_WithDisplayName(t *testing.T) {
	result := parseAddressList("Alice <alice@example.com>")
	require.Equal(t, []string{"alice@example.com"}, result)
}

func TestParseAddressList_Malformed_ReturnedAsIs(t *testing.T) {
	// Malformed address falls back to returning the raw string.
	result := parseAddressList("not-an-email")
	require.Equal(t, []string{"not-an-email"}, result)
}

// ─── deriveFilename ───────────────────────────────────────────────────────────

func TestDeriveFilename_KnownTypes(t *testing.T) {
	tests := []struct {
		mime string
		want string
	}{
		{"image/jpeg", "attachment.jpg"},
		{"image/png", "attachment.png"},
		{"application/pdf", "attachment.pdf"},
		{"application/zip", "attachment.zip"},
		{"text/plain", "attachment.txt"},
		{"video/mp4", "attachment.mpg4"},
	}
	for _, tc := range tests {
		got := deriveFilename(tc.mime)
		require.Equal(t, tc.want, got, "mimeType=%q", tc.mime)
	}
}

func TestDeriveFilename_UnknownFallback(t *testing.T) {
	got := deriveFilename("application/x-unknown-totally-custom")
	require.NotEmpty(t, got)
	require.True(t, strings.HasPrefix(got, "attachment"))
}

func TestDeriveFilename_EmptyMIME(t *testing.T) {
	got := deriveFilename("")
	require.Equal(t, "attachment.bin", got)
}

// ─── decodeCTE ────────────────────────────────────────────────────────────────

func TestDecodeCTE_Identity(t *testing.T) {
	data := []byte("hello world")
	r := decodeCTE("", bytes.NewReader(data))
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	require.Equal(t, data, buf.Bytes())
}

func TestDecodeCTE_Base64(t *testing.T) {
	original := []byte("hello world")
	encoded := base64.StdEncoding.EncodeToString(original)
	r := decodeCTE("base64", strings.NewReader(encoded))
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	require.Equal(t, original, buf.Bytes())
}

func TestDecodeCTE_QuotedPrintable(t *testing.T) {
	// "héllo" in quoted-printable is "h=C3=A9llo"
	encoded := "h=C3=A9llo"
	r := decodeCTE("quoted-printable", strings.NewReader(encoded))
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	require.Equal(t, "héllo", buf.String())
}

// ─── min512 ───────────────────────────────────────────────────────────────────

func TestMin512_ShortData(t *testing.T) {
	data := make([]byte, 100)
	require.Equal(t, 100, min512(data))
}

func TestMin512_ExactlyFull(t *testing.T) {
	data := make([]byte, 512)
	require.Equal(t, 512, min512(data))
}

func TestMin512_LongerData(t *testing.T) {
	data := make([]byte, 1024)
	require.Equal(t, 512, min512(data))
}

// ─── walkPart ─────────────────────────────────────────────────────────────────

func makeHeader(contentType string) textproto.MIMEHeader {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", contentType)
	return h
}

func TestWalkPart_PlainText(t *testing.T) {
	var plain, html string
	var attachments []interface{}

	header := makeHeader("text/plain")
	body := strings.NewReader("Hello, world!")

	walkPart(header, body, &plain, &html, (*[]ws.SMTPAttachment)(nil))

	// Use a different approach since ws.SMTPAttachment is private — just test via string outputs
	_ = attachments
	require.Equal(t, "Hello, world!", plain)
	require.Empty(t, html)
}

func TestWalkPart_HTMLContent(t *testing.T) {
	var plain, html string
	var atts []ws.SMTPAttachment

	header := makeHeader("text/html")
	body := strings.NewReader("<b>Hello</b>")

	walkPart(header, body, &plain, &html, &atts)

	require.Empty(t, plain)
	require.Equal(t, "<b>Hello</b>", html)
}

func TestWalkPart_MultipartMixed(t *testing.T) {
	var plain, html string
	var atts []ws.SMTPAttachment

	// Build a simple multipart/mixed message
	rawMultipart := "--boundary\r\nContent-Type: text/plain\r\n\r\nPlain part\r\n--boundary\r\nContent-Type: text/html\r\n\r\n<p>HTML part</p>\r\n--boundary--\r\n"

	header := makeHeader(`multipart/mixed; boundary="boundary"`)
	body := strings.NewReader(rawMultipart)

	walkPart(header, body, &plain, &html, &atts)

	require.Equal(t, "Plain part", plain)
	require.Equal(t, "<p>HTML part</p>", html)
}

func TestWalkPart_Attachment(t *testing.T) {
	var plain, html string
	var atts []ws.SMTPAttachment

	// Build multipart with an attachment
	raw := "--b\r\nContent-Type: text/plain\r\n\r\nBody text\r\n--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"doc.pdf\"\r\n\r\n%PDF-1.4 binary data\r\n--b--\r\n"
	header := makeHeader(`multipart/mixed; boundary="b"`)

	walkPart(header, strings.NewReader(raw), &plain, &html, &atts)

	require.Equal(t, "Body text", plain)
	require.Len(t, atts, 1)
	require.Equal(t, "doc.pdf", atts[0].Filename)
}
