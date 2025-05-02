package httpserver

import (
	"github.com/patrickhener/goshs/utils"
)

func (fs *FileServer) HandleWebhookSend(message string, event string) {
	// Only send if webhook is enabled and the event is in the list of events to notify
	if fs.WebhookEnable {
		if utils.Contains(fs.WebhookEvents, event) || fs.WebhookEvents[0] == "all" {
			fs.Webhook.Send(message)
		}
	}
}
