package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPostJSON(t *testing.T) {
	// Setup a test HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check method and content type
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Optionally check request body, or just respond OK
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Call postJSON with the test server URL and some payload
	err := postJSON(ts.URL, map[string]string{"foo": "bar"})
	require.NoError(t, err)
}

func TestPostJSON_Failure(t *testing.T) {
	// Setup a test HTTP server that returns failure status
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	err := postJSON(ts.URL, map[string]string{"foo": "bar"})
	require.Error(t, err)
}

func TestPostJSON_InvalidPayload(t *testing.T) {
	// Pass something that cannot be marshalled into JSON, such as a channel
	err := postJSON("http://example.com", make(chan int))
	require.Error(t, err)
}

func TestPostJSON_HttpPostError(t *testing.T) {
	err := postJSON("http://\x7f\x7f\x7f\x7f", map[string]string{"foo": "bar"})
	require.Error(t, err)
}

func TestDiscordWebhook_Send(t *testing.T) {
	// Mock server to simulate Discord webhook endpoint
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check HTTP method and headers if needed
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Read body and verify payload
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		defer r.Body.Close()

		var payload map[string]string
		err = json.Unmarshal(body, &payload)
		require.NoError(t, err)

		// Check that the message and username are set as expected
		require.Equal(t, "Hello from test", payload["content"])
		require.Equal(t, "TestBot", payload["username"])

		w.WriteHeader(http.StatusOK) // simulate success
	}))
	defer ts.Close()

	d := &DiscordWebhook{
		URL:      ts.URL,
		Username: "TestBot",
	}

	err := d.Send("Hello from test")
	require.NoError(t, err)
}

func TestMattermostWebhook_Send(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		defer r.Body.Close()

		var payload map[string]interface{}
		err = json.Unmarshal(body, &payload)
		require.NoError(t, err)

		require.Equal(t, "Hello Mattermost", payload["text"])
		require.Equal(t, "MMBot", payload["username"])
		require.Equal(t, "https://example.com/icon.png", payload["icon_url"])

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	m := &MattermostWebhook{
		URL:      ts.URL,
		Username: "MMBot",
		IconURL:  "https://example.com/icon.png",
	}

	err := m.Send("Hello Mattermost")
	require.NoError(t, err)
}

func TestSlackWebhook_Send(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		defer r.Body.Close()

		var payload map[string]string
		err = json.Unmarshal(body, &payload)
		require.NoError(t, err)

		require.Equal(t, "Hello Slack", payload["text"])

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := &SlackWebhook{
		URL: ts.URL,
	}

	err := s.Send("Hello Slack")
	require.NoError(t, err)
}
