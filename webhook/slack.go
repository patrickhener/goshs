package webhook

type SlackWebhook struct {
	Enabled bool
	Events  []string
	URL     string
}

func (s *SlackWebhook) Send(message string) error {
	payload := map[string]string{
		"text": message,
	}

	return postJSON(s.URL, payload)
}

func (s *SlackWebhook) GetEnabled() bool {
	return s.Enabled
}

func (s *SlackWebhook) GetEvents() []string {
	return s.Events
}

func (s *SlackWebhook) Contains(event string) bool {
	for _, a := range s.Events {
		if a == event {
			return true
		}
	}
	return false
}
