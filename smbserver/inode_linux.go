//go:build linux

package smbserver

import (
	"os"
	"syscall"
)

func inodeNumber(fi os.FileInfo) uint64 {
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
