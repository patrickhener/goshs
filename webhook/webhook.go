package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type Webhook interface {
	Send(message string) error
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
