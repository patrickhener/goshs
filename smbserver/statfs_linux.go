//go:build linux

package smbserver

import "syscall"

type statfsResult struct {
	total uint64
	free  uint64
}

func statfs(path string) (statfsResult, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return statfsResult{}, err
	}
	blockSize := uint64(st.Bsize)
	return statfsResult{
		total: uint64(st.Blocks) * blockSize,
		free:  uint64(st.Bavail) * blockSize,
	}, nil
}
