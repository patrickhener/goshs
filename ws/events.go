package ws

import "time"

type DNSEvent struct {
	Type   string    `json:"type"`   // "dns"
	Name   string    `json:"name"`   // queried hostname
	QType  string    `json:"qtype"`  // "A", "MX", "TXT" …
	Source string    `json:"source"` // client IP:port
	Time   time.Time `json:"timestamp"`
}

type SMTPAttachment struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
	Size        int    `json:"size"`
}

type SMTPEvent struct {
	Type        string           `json:"type"` // "smtp"
	From        string           `json:"from"`
	To          []string         `json:"to"`
	CC          []string         `json:"cc"`
	BCC         []string         `json:"bcc"`
	Subject     string           `json:"subject"`
	Body        string           `json:"body"`
	HTMLBody    string           `json:"htmlBody"`
	RawHeader   string           `json:"rawHeader"`
	Attachments []SMTPAttachment `json:"attachments"`
	Timestamp   time.Time        `json:"timestamp"`
}

type HTTPEvent struct {
	Type       string            `json:"type"`       // "http"
	Method     string            `json:"method"`     // "GET", "POST", "PUT", "DELETE"
	URL        string            `json:"url"`        // full URL including query string
	Body       string            `json:"body"`       // request/response body
	Parameters string            `json:"parameters"` // query parameters
	Headers    map[string]string `json:"headers"`    // HTTP headers
	Source     string            `json:"source"`     // client IP:port
	UserAgent  string            `json:"useragent"`  // browser/user agent string
	Status     int               `json:"status"`     // HTTP status code
	Timestamp  time.Time         `json:"timestamp"`
}

type NTLMEvent struct {
	Type            string    `json:"type"`            // "ntlm"
	Username        string    `json:"username"`        // username
	Domain          string    `json:"domain"`          // domain
	Workstation     string    `json:"workstation"`     // workstation
	Challenge       string    `json:"challenge"`       // challenge
	Hash            string    `json:"hash"`            // hashcat line
	HashType        string    `json:"hashType"`        // Distinguishing between NetNTLMv1/2, SSP, LM, etc.
	HashcatMode     string    `json:"hashcatMode"`     // hashcat mode (v2 5600, v1 5500, 3000 LM, 1000 NTLM)
	CrackedPassword string    `json:"crackedPassword"` // plaintext password if cracked, empty otherwise
	Source          string    `json:"source"`          // source
	Timestamp       time.Time `json:"timestamp"`
}
