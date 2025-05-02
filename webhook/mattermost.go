package webhook

type MattermostWebhook struct {
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
