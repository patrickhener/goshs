package smtpserver

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/smtpattach"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
)

type Session struct {
	hub     *ws.Hub
	webhook *webhook.Webhook
	conn    *smtp.Conn
	from    string
	to      []string
	domain  string
}

func (s *Session) AuthPlain(user, pass string) error { return nil } // accept all

func (s *Session) Mail(from string, _ *smtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *Session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.domain != "" {
		// extract the domain part after @
		atIdx := strings.LastIndex(to, "@")
		if atIdx == -1 {
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "Invalid recipient address"}
		}
		rcptDomain := strings.ToLower(to[atIdx+1:])
		if rcptDomain != strings.ToLower(s.domain) {
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 2}, Message: "Relay denied: recipient domain not accepted"}
		}
	}
	s.to = append(s.to, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	raw, _ := io.ReadAll(r)
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return err
	}

	var (
		plainBody   string
		htmlBody    string
		attachments []ws.SMTPAttachment
	)

	// Convert mail.Header to textproto.MIMEHeader (same underlying type)
	topHeader := textproto.MIMEHeader(msg.Header)
	walkPart(topHeader, msg.Body, &plainBody, &htmlBody, &attachments)

	// Collect CC/BCC from headers
	cc := parseAddressList(msg.Header.Get("Cc"))
	bcc := parseAddressList(msg.Header.Get("Bcc"))

	event := ws.SMTPEvent{
		Type:        "smtp",
		From:        s.from,
		To:          s.to,
		CC:          cc,
		BCC:         bcc,
		Subject:     msg.Header.Get("Subject"),
		Body:        plainBody,
		HTMLBody:    htmlBody,
		RawHeader:   fmt.Sprintf("%v", msg.Header),
		Attachments: attachments,
		Timestamp:   time.Now(),
	}
	eventBytes, err := json.Marshal(event)
	if err != nil {
		logger.Errorf("Error marshalling dns query event: %v", err)
		return err
	}

	s.hub.Broadcast <- eventBytes

	smtpWHMessage := fmt.Sprintf(`[SMTP] - Message received

FROM: %s
TO: %s
CC: %s
BCC: %s
SUBJECT: %s
Attachments: %d

RawBody:
%s

HTMLBody:
%s`, s.from, s.to, cc, bcc, msg.Header.Get("Subject"), len(attachments), plainBody, htmlBody)

	logger.HandleWebhookSend(smtpWHMessage, "smtp", *s.webhook)

	return nil
}

func walkPart(header textproto.MIMEHeader, body io.Reader, plain, html *string, attachments *[]ws.SMTPAttachment) {
	ct := header.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}

	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		data, _ := io.ReadAll(decodeCTE(header.Get("Content-Transfer-Encoding"), body))
		if *plain == "" {
			*plain = string(data)
		}
		return
	}

	// Recurse into multipart
	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			walkPart(textproto.MIMEHeader(part.Header), part, plain, html, attachments)
		}
		return
	}

	// Decode transfer encoding first — we need the real bytes
	data, _ := io.ReadAll(decodeCTE(header.Get("Content-Transfer-Encoding"), body))

	// Determine real MIME type.
	// For text/* types: trust the declared type — sniffing short ASCII text
	// is unreliable and causes false overrides on legitimate plain bodies.
	// For everything else: sniff to catch binary data hiding behind fake types
	// (e.g. a JPEG sent as text/html).
	realMediaType := mediaType
	if !strings.HasPrefix(mediaType, "text/") && len(data) > 0 {
		sniffed := http.DetectContentType(data[:min512(data)])
		sniffedBase := strings.TrimSpace(strings.Split(sniffed, ";")[0])
		if sniffedBase != mediaType {
			realMediaType = sniffedBase
		}
	}

	// Check Content-Disposition for filename and attachment intent
	filename := params["name"] // from Content-Type: ...; name="foo.jpg"
	isAttach := false
	if cd := header.Get("Content-Disposition"); cd != "" {
		disp, cdParams, err := mime.ParseMediaType(cd)
		if err == nil {
			isAttach = strings.EqualFold(disp, "attachment")
			if fn := cdParams["filename"]; fn != "" {
				filename = fn // Content-Disposition wins over Content-Type name
				isAttach = true
			}
		}
	}

	switch {
	case realMediaType == "text/plain" && !isAttach:
		if *plain == "" {
			*plain = string(data)
		}
	case realMediaType == "text/html" && !isAttach:
		if *html == "" {
			*html = string(data)
		}
	default:
		if filename == "" {
			filename = deriveFilename(realMediaType)
		}
		id := uuid.NewString()
		smtpattach.Save(id, filename, realMediaType, data)
		*attachments = append(*attachments, ws.SMTPAttachment{
			ID:          id,
			Filename:    filename,
			ContentType: realMediaType,
			Size:        len(data),
		})
	}
}

// deriveFilename produces a meaningful filename from a MIME type when the
// sender did not supply one, e.g. "image/jpeg" → "attachment.jpg"
func deriveFilename(mimeType string) string {
	// mime.ExtensionsByType returns all registered extensions for a type.
	// We pick the first canonical one.
	exts, err := mime.ExtensionsByType(mimeType)
	if err == nil && len(exts) > 0 {
		// Go returns extensions sorted — pick the shortest/most common one.
		// e.g. for image/jpeg: [".jfif", ".jpe", ".jpeg", ".jpg"] — we want .jpg
		ext := exts[len(exts)-1] // last is alphabetically last, usually the common one
		// Override a few cases where the alphabetical last isn't the common choice
		switch mimeType {
		case "image/jpeg":
			ext = ".jpg"
		case "image/tiff":
			ext = ".tiff"
		case "video/mpeg":
			ext = ".mpeg"
		case "application/zip":
			ext = ".zip"
		case "text/plain":
			ext = ".txt"
		}
		return "attachment" + ext
	}

	// Fallback: derive from the subtype directly
	// e.g. "video/mp4" → ".mp4", "application/pdf" → ".pdf"
	parts := strings.SplitN(mimeType, "/", 2)
	if len(parts) == 2 && parts[1] != "" {
		sub := strings.Split(parts[1], ";")[0] // strip parameters
		sub = strings.TrimPrefix(sub, "x-")    // strip x- prefix
		return "attachment." + sub
	}

	return "attachment.bin"
}

// min512 returns the smaller of 512 or len(data) for DetectContentType
func min512(data []byte) int {
	if len(data) < 512 {
		return len(data)
	}
	return 512
}

// Simpler standalone version used in walkPart
func decodeCTE(cte string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	default:
		return r
	}
}

func parseAddressList(s string) []string {
	if s == "" {
		return nil
	}
	addrs, err := mail.ParseAddressList(s)
	if err != nil {
		return []string{s}
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.Address
	}
	return out
}

func (s *Session) Reset()        { s.to = nil }
func (s *Session) Logout() error { return nil }
