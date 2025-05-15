package integration

import "github.com/testcontainers/testcontainers-go"

type volumeSource struct {
	source    string
	mountType uint8
}

func (v *volumeSource) Source() string {
	return v.source
}

func (v *volumeSource) Type() testcontainers.MountType {
	return testcontainers.MountType(v.mountType)
}

type item struct {
	Name           string `json:"name"`
	Is_dir         bool   `json:"is_dir"`
	Is_symlink     bool   `json:"is_symlink"`
	Symlink_target string `json:"symlink_target"`
	Extension      string `json:"extension"`
	Size_bytes     int    `json:"size_bytes"`
	Last_modified  int    `json:"last_modified"`
	ReadOnly       bool   `json:"ReadOnly"`
	NoDelete       bool   `json:"NoDelete"`
}
