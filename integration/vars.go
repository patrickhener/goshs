package integration

import (
	"fmt"
	"os"
)

var (
	dockerfilePath = fmt.Sprintf("%s/../", os.Getenv("PWD"))
	storageVolume  = fmt.Sprintf("%s/files", os.Getenv("PWD"))
)
