//go:build windows

package httpserver

import (
	"goshs.de/goshs/v2/logger"
)

func (fs *FileServer) dropPrivs() {
	if fs.DropUser != "" {
		logger.Warn("Dropping privileges with --user only works for unix systems, sorry.")
	}
}
