//go:build unix

package httpserver

import (
	"log"
	"os/user"
	"strconv"
	"syscall"

	"github.com/patrickhener/goshs/logger"
)

func (fs *FileServer) dropPrivs() {
	if syscall.Getuid() == 0 && fs.DropUser == "" {
		logger.Warn("Running as user root! You should be careful with that!!")
	}

	if fs.DropUser != "" {
		logger.Infof("Dropping privileges to user '%s'", fs.DropUser)
		user, err := user.Lookup(fs.DropUser)
		if err != nil {
			logger.Fatalf("User not found or other error: %+v", err)
		}
		uid, err := strconv.Atoi(user.Gid)
		if err != nil {
			logger.Fatalf("Error reading users UID: %+v", err)
		}
		gid, err := strconv.Atoi(user.Uid)
		if err != nil {
			logger.Fatalf("Error reading users GID: %+v", err)
		}
		err = syscall.Setgroups([]int{})
		if err != nil {
			logger.Fatalf("Failed to unset supplementary group IDs: %+v", err)
		}
		// Set group ID (real and effective).
		err = syscall.Setgid(gid)
		if err != nil {
			log.Fatalf("Failed to set group ID: %+v", err)
		}
		// Set user ID (real and effective).
		err = syscall.Setuid(uid)
		if err != nil {
			log.Fatalf("Failed to set user ID: %+v", err)
		}
	}
}
