package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Webhook interface {
	Send(message string) error
	GetEnabled() bool
	GetEvents() []string
	Contains(event string) bool
}

func postJSON(url string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK || resp.StatusCode >= 300 {
		return fmt.Errorf("failed to send webhook: %s", resp.Status)
	}

	return nil
}

func Register(enabled bool, url string, provider string, events []string) *Webhook {
	var webhook Webhook

	switch strings.ToLower(provider) {
	case "discord":
		webhook = &DiscordWebhook{
			Enabled:  enabled,
			Events:   events,
			URL:      url,
			Username: "goshs",
		}
	case "slack":
		webhook = &SlackWebhook{
			Enabled: enabled,
			Events:  events,
			URL:     url,
		}
	case "mattermost":
		webhook = &MattermostWebhook{
			Enabled:  enabled,
			Events:   events,
			URL:      url,
			Username: "goshs",
		}
	default:
		webhook = &DiscordWebhook{
			Enabled: false,
		}
	}

	return &webhook
}
