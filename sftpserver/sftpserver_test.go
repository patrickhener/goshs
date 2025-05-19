package sftpserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

func TestNewSFTPServer(t *testing.T) {
	server := NewSFTPServer("0.0.0.0", 2022, "", "test", "test", os.Getenv("PWD"), false, false, "")

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
	server := NewSFTPServer("0.0.0.0", 2022, "authorized_keys", "test", "test", os.Getenv("PWD"), true, false, "goshs_host_key_rsa")

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
	server := NewSFTPServer("0.0.0.0", 2022, "authorized_keys.foo", "", "", os.Getenv("PWD"), false, false, "")
	err := server.Start()
	require.Error(t, err)

	server = NewSFTPServer("0.0.0.0", 2022, "", "", "", os.Getenv("PWD"), false, false, "foo")
	err = server.Start()
	require.Error(t, err)
}

func TestSanitizePath(t *testing.T) {
	root := "/home/user"
	path := "/home/user/../test"
	_, err := sanitizePath(path, root)
	require.Error(t, err)

	root = "/home/user"
	path = "/home/user/foo/bar/baz"
	_, err = sanitizePath(path, root)
	require.NoError(t, err)
}

func TestReadFile(t *testing.T) {
	req := &sftp.Request{
		Method: "Readfile",
		Target: filepath.Join(os.Getenv("PWD"), "authorized_keys"),
	}
	file, err := readFile(filepath.Join(os.Getenv("PWD"), "authorized_keys"), os.Getenv("PWD"), req, "127.0.0.1")
	require.NoError(t, err)
	require.Equal(t, file.Name(), filepath.Join(os.Getenv("PWD"), "authorized_keys"))
}

func TestListFile(t *testing.T) {
	req := &sftp.Request{
		Method: "Stat",
		Target: filepath.Join(os.Getenv("PWD"), "authorized_keys"),
	}
	files, err := listFile(filepath.Join(os.Getenv("PWD"), "authorized_keys"), os.Getenv("PWD"), req, "127.0.0.1")
	require.NoError(t, err)
	file := files.files[0]
	require.Equal(t, filepath.Join(os.Getenv("PWD"), file.Name()), filepath.Join(os.Getenv("PWD"), "authorized_keys"))

	req = &sftp.Request{
		Method: "Listfiles",
		Target: filepath.Join(os.Getenv("PWD"), "authorized_keys"),
	}

	files, err = listFile(os.Getenv("PWD"), os.Getenv("PWD"), req, "127.0.0.1")
	require.NoError(t, err)
	require.Greater(t, len(files.files), 4)
}

func TestWriteFile(t *testing.T) {
	req := &sftp.Request{
		Method: "Writefile",
		Target: filepath.Join(os.Getenv("PWD"), "test.txt"),
	}
	file, err := writeFile(filepath.Join(os.Getenv("PWD"), "test.txt"), os.Getenv("PWD"), req, "127.0.0.1")
	require.NoError(t, err)
	_, err = file.Write([]byte("test content"))
	require.NoError(t, err)
}

func TestCmd(t *testing.T) {
	req := &sftp.Request{
		Method:   "Stat",
		Filepath: filepath.Join(os.Getenv("PWD"), "authorized_keys"),
	}

	err := cmdFile(filepath.Join(os.Getenv("PWD"), "authorized_keys"), os.Getenv("PWD"), req, "127.0.0.1")
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Lstat",
		Filepath: filepath.Join(os.Getenv("PWD"), "authorized_keys"),
	}

	err = cmdFile(filepath.Join(os.Getenv("PWD"), "authorized_keys"), os.Getenv("PWD"), req, "127.0.0.1")
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Mkdir",
		Filepath: filepath.Join(os.Getenv("PWD"), "testdir"),
	}

	err = cmdFile(filepath.Join(os.Getenv("PWD"), "testdir"), os.Getenv("PWD"), req, "127.0.0.1")
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Rename",
		Filepath: filepath.Join(os.Getenv("PWD"), "test.txt"),
		Target:   filepath.Join(os.Getenv("PWD"), "testdir", "test.txt"),
	}

	err = cmdFile(filepath.Join(os.Getenv("PWD"), "test.txt"), os.Getenv("PWD"), req, "127.0.0.1")
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Setstat",
		Filepath: filepath.Join(os.Getenv("PWD"), "testdir", "test.txt"),
		Attrs:    []byte(`{"mode": 0644}`), // Invalid
	}
	err = cmdFile(filepath.Join(os.Getenv("PWD"), "testdir", "test.txt"), os.Getenv("PWD"), req, "127.0.0.1")
	require.NoError(t, err)

	// TODO: Add test for Setstat with valid attributes

	req = &sftp.Request{
		Method:   "Remove",
		Filepath: filepath.Join(os.Getenv("PWD"), "testdir", "test.txt"),
	}

	err = cmdFile(filepath.Join(os.Getenv("PWD"), "testdir", "test.txt"), os.Getenv("PWD"), req, "127.0.0.1")
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Rmdir",
		Filepath: filepath.Join(os.Getenv("PWD"), "testdir"),
	}

	err = cmdFile(filepath.Join(os.Getenv("PWD"), "testdir"), os.Getenv("PWD"), req, "127.0.0.1")
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "INVALID",
		Filepath: os.Getenv("PWD"),
	}

	err = cmdFile(os.Getenv("PWD"), os.Getenv("PWD"), req, "127.0.0.1")
	require.Error(t, err)
}
