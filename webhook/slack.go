package webhook

type SlackWebhook struct {
	URL string
}

func (s *SlackWebhook) Send(message string) error {
	payload := map[string]string{
		"text": message,
	}

	return postJSON(s.URL, payload)
}
