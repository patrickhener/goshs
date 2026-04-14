package httpserver

import (
	"fmt"
	"net/http"
	"time"

	"goshs.de/goshs/v2/logger"
)

// clipboardAdd will handle the add request for adding text to the clipboard
func (fs *FileServer) cbDown(w http.ResponseWriter, req *http.Request) {
	filename := fmt.Sprintf("%d-clipboard.json", time.Now().Unix())
	contentDisposition := fmt.Sprintf("attachment; filename=\"%s\"", filename)
	// Handle as download
	w.Header().Add("Content-Type", "application/octet-stream")
	w.Header().Add("Content-Disposition", contentDisposition)
	content, err := fs.Clipboard.Download()
	if err != nil {
		fs.handleError(w, req, err, 500)
	}

	if _, err := w.Write(content); err != nil {
		logger.Errorf("Error writing response to browser: %+v", err)
	}
}
