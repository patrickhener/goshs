//go:build !linux

package smbserver

import "fmt"

type statfsResult struct {
	total uint64
	free  uint64
}

func statfs(path string) (statfsResult, error) {
	return statfsResult{}, fmt.Errorf("statfs not supported on this platform")
}
