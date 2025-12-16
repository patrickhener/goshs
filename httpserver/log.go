package httpserver

import (
	"net/http"

	"github.com/patrickhener/goshs/logger"
)

func (fs *FileServer) logOnly(w http.ResponseWriter, req *http.Request) {
	logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook)
	if fs.Invisible {
		// In invisible mode, do not respond
		fs.handleInvisible(w)
	} else {
		w.WriteHeader(200)
		w.Write([]byte("ok\n"))
	}
}
