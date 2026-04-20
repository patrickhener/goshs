package integration

import (
	"fmt"
	"os"
)

var (
	dockerfilePath = fmt.Sprintf("%s/../", os.Getenv("PWD"))
	storageVolume  = fmt.Sprintf("%s/files", os.Getenv("PWD"))
	// coverageDir is bind-mounted into each container at /covdata. The
	// goshs binary is built with `go build -cover` so it writes covdata
	// files here on graceful shutdown. Tests merge these in CI.
	coverageDir = fmt.Sprintf("%s/covdata", os.Getenv("PWD"))
)
