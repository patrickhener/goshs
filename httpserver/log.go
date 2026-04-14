package httpserver

import (
	"net/http"

	"github.com/patrickhener/goshs/v2/logger"
)

func (fs *FileServer) logOnly(w http.ResponseWriter, req *http.Request) {
	body := fs.emitCollabEvent(req, http.StatusOK)
	logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook, body)
	if fs.Invisible {
		// In invisible mode, do not respond
		fs.handleInvisible(w)
	} else {
		w.WriteHeader(200)
		_, err := w.Write([]byte("ok\n"))
		if err != nil {
			logger.Error(err)
		}
	}
}
