//go:build unix

package cli

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/patrickhener/goshs/logger"
)

func RunCMD(cmd string) (string, error) {
	cmdArray := strings.Split(cmd, " ")
	// disable G204 (CWE-78): Subprocess launched with a potential tainted input or cmd arguments
	// This is intended behaviour
	// #nosec G204
	cmdRun := exec.Command(cmdArray[0], cmdArray[1:]...)
	var stdout, stderr bytes.Buffer
	cmdRun.Stdout = &stdout
	cmdRun.Stderr = &stderr
	err := cmdRun.Run()
	if err != nil {
		logger.Errorf("error running system command: %+v", err)
	}
	outStr := stdout.String()
	outErr := stderr.String()
	if outErr != "" {
		return outErr, nil
	}
	return outStr, nil
}
