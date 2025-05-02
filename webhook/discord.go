package webhook

type DiscordWebhook struct {
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
