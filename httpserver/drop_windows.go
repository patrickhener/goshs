//go:build windows

package httpserver

import (
	"github.com/patrickhener/goshs/logger"

	"golang.org/x/sys/windows"
)

var (
	sid *windows.SID
)

func (fs *FileServer) dropPrivs() {
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		logger.Fatalf("SID Error: %s", err)
		return
	}

	token := windows.Token(0)

	member, err := token.IsMember(sid)
	if err != nil {
		logger.Fatalf("Token Membership Error: %s", err)
		return
	}

	logger.Debugf("Elevated: %+v", token.IsElevated())
	logger.Debugf("Admin: %+v", member)

	if member && fs.DropUser == "" {
		logger.Warn("Running with administrative privileges! You should be careful with that!!")
	}

	if fs.DropUser != "" {
		logger.Warn("Dropping privileges with --user only works for unix systems, sorry.")
	}
}
