package httpserver

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/patrickhener/goshs/logger"
	"github.com/patrickhener/goshs/ws"
)

func (fs *FileServer) emitCollabEvent(r *http.Request, status int) []byte {
	// Emit HTTP log event to webhook
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("Failed to read request body: %v", err)
	}
	defer r.Body.Close()

	// Flatten headers into a simple map (join multi-value headers with ", ").
	// Strip the CSRF token so it is never exposed in the collaborator tab.
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		if http.CanonicalHeaderKey(k) == "X-Csrf-Token" {
			continue
		}
		headers[k] = strings.Join(v, ", ")
	}

	event := ws.HTTPEvent{
		Type:       "http",
		Method:     r.Method,
		URL:        r.URL.String(),
		Body:       string(body),
		Parameters: r.URL.Query().Encode(),
		Headers:    headers,
		Source:     r.RemoteAddr,
		UserAgent:  r.UserAgent(),
		Status:     status,
		Timestamp:  time.Now(),
	}
	eventBytes, err := json.Marshal(event)
	if err != nil {
		logger.Errorf("Error marshalling dns query event: %v", err)
		return body
	}

	fs.Hub.Broadcast <- eventBytes
	return body
}
