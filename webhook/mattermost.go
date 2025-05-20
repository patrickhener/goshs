package webhook

type MattermostWebhook struct {
	Enabled  bool
	Events   []string
	URL      string
	Username string
	IconURL  string
}

func (m *MattermostWebhook) Send(message string) error {
	payload := map[string]interface{}{
		"text":     message,
		"username": m.Username,
	}

	if m.IconURL != "" {
		payload["icon_url"] = m.IconURL
	}

	return postJSON(m.URL, payload)
}

func (m *MattermostWebhook) GetEnabled() bool {
	return m.Enabled
}

func (m *MattermostWebhook) GetEvents() []string {
	return m.Events
}

func (m *MattermostWebhook) Contains(event string) bool {
	for _, a := range m.Events {
		if a == event {
			return true
		}
	}
	return false
}
