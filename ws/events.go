package ws

import "time"

type DNSEvent struct {
	Type   string    `json:"type"`   // "dns"
	Name   string    `json:"name"`   // queried hostname
	QType  string    `json:"qtype"`  // "A", "MX", "TXT" …
	Source string    `json:"source"` // client IP:port
	Time   time.Time `json:"timestamp"`
}

type SMTPEvent struct {
	Type      string    `json:"type"` // "smtp"
	From      string    `json:"from"`
	To        []string  `json:"to"`
	CC        []string  `json:"cc"`
	BCC       []string  `json:"bcc"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	RawHeader string    `json:"rawHeader"`
	Timestamp time.Time `json:"timestamp"`
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
