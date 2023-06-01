//go:build windows

package cli

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/patrickhener/goshs/logger"
)

func RunCMD(cmd string) (string, error) {
	newCmd := "/c " + cmd
	cmdArray := strings.Split(newCmd, " ")
	cmdRun := exec.Command("cmd.exe", cmdArray...)
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
