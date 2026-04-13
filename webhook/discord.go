package webhook

import "slices"

type DiscordWebhook struct {
	Enabled  bool
	Events   []string
	URL      string
	Username string
}

func (d *DiscordWebhook) Send(message string) error {
	payload := map[string]string{
		"content":  message,
		"username": d.Username,
	}

	return postJSON(d.URL, payload)
}

func (d *DiscordWebhook) GetEnabled() bool {
	return d.Enabled
}

func (d *DiscordWebhook) GetEvents() []string {
	return d.Events
}

func (d *DiscordWebhook) Contains(event string) bool {
	return slices.Contains(d.Events, event)
}
