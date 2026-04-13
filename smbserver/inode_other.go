//go:build !linux

package smbserver

import "os"

func inodeNumber(fi os.FileInfo) uint64 {
	return 0
}
