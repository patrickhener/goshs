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
