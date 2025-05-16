package sftpserver

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewSFTPServer(t *testing.T) {
	server := NewSFTPServer("0.0.0.0", 2022, "", "test", "test", os.Getenv("PWD"), false, "")

	require.Equal(t, server.IP, "0.0.0.0")
	require.Equal(t, server.Port, 2022)
	require.Equal(t, server.KeyFile, "")
	require.Equal(t, server.Username, "test")
	require.Equal(t, server.Password, "test")
	require.Equal(t, server.Root, os.Getenv("PWD"))
	require.Equal(t, server.ReadOnly, false)
	require.Equal(t, server.HostKeyFile, "")
}

func TestStart(t *testing.T) {
	server := NewSFTPServer("0.0.0.0", 2022, "authorized_keys", "test", "test", os.Getenv("PWD"), true, "goshs_host_key_rsa")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})

	go func() {
		err := server.Start()
		require.NoError(t, err)
	}()
	// Wait for context timeout or server error
	<-ctx.Done()
	// Timeout reached, stop the server gracefully
	close(done)
}

func TestErrors(t *testing.T) {
	server := NewSFTPServer("0.0.0.0", 2022, "authorized_keys.foo", "", "", os.Getenv("PWD"), false, "")
	err := server.Start()
	require.Error(t, err)

	server = NewSFTPServer("0.0.0.0", 2022, "", "", "", os.Getenv("PWD"), false, "foo")
	err = server.Start()
	require.Error(t, err)

}
