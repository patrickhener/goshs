package httpserver

import (
	"net/http"

	"github.com/patrickhener/goshs/logger"
)

func (fs *FileServer) logOnly(w http.ResponseWriter, req *http.Request) {
	logger.LogRequest(req, http.StatusOK, fs.Verbose)
	w.WriteHeader(200)
	w.Write([]byte("ok\n"))

	// Send webhook message
	fs.HandleWebhookSend("", "verbose")
}
