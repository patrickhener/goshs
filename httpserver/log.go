package httpserver

import (
	"net/http"

	"github.com/patrickhener/goshs/logger"
)

func (fs *FileServer) logOnly(w http.ResponseWriter, req *http.Request) {
	logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook)
	w.WriteHeader(200)
	w.Write([]byte("ok\n"))
}
