package cli

import (
	"os/exec"
	"strings"
)

func RunCMD(cmd string) (string, error) {
	cmdArray := strings.Split(cmd, " ")
	cmdRun := exec.Command(cmdArray[0], cmdArray[1:]...)
	output, err := cmdRun.CombinedOutput()
	if err != nil {
		return err.Error(), err
	}

	return string(output), nil
}
