package sftpserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/patrickhener/goshs/webhook"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

var sftpserver *SFTPServer = &SFTPServer{
	IP:          "0.0.0.0",
	Port:        2022,
	KeyFile:     "authorized_keys",
	Username:    "test",
	Password:    "test",
	Root:        os.Getenv("PWD"),
	ReadOnly:    false,
	UploadOnly:  false,
	HostKeyFile: "goshs_host_key_rsa",
	Webhook: &webhook.DiscordWebhook{
		Enabled: false,
	},
}

func TestStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})

	go func() {
		err := sftpserver.Start()
		require.NoError(t, err)
	}()
	// Wait for context timeout or server error
	<-ctx.Done()
	// Timeout reached, stop the server gracefully
	close(done)
}

func TestErrors(t *testing.T) {
	server := &SFTPServer{
		IP:          "0.0.0.0",
		Port:        2022,
		KeyFile:     "authorized_keys.foo",
		Username:    "",
		Password:    "",
		Root:        os.Getenv("PWD"),
		ReadOnly:    false,
		UploadOnly:  false,
		HostKeyFile: "",
		Webhook: &webhook.DiscordWebhook{
			Enabled: false,
		},
	}
	err := server.Start()
	require.Error(t, err)

	server = &SFTPServer{
		IP:          "0.0.0.0",
		Port:        2022,
		KeyFile:     "",
		Username:    "",
		Password:    "",
		Root:        os.Getenv("PWD"),
		ReadOnly:    false,
		UploadOnly:  false,
		HostKeyFile: "foo",
		Webhook: &webhook.DiscordWebhook{
			Enabled: false,
		},
	}
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
		Method:   "Readfile",
		Filepath: filepath.Join(os.Getenv("PWD"), "authorized_keys"),
	}
	file, err := readFile(os.Getenv("PWD"), req, "127.0.0.1", sftpserver)
	require.NoError(t, err)
	require.Equal(t, file.Name(), filepath.Join(os.Getenv("PWD"), "authorized_keys"))
}

func TestListFile(t *testing.T) {
	req := &sftp.Request{
		Method:   "Stat",
		Filepath: filepath.Join(os.Getenv("PWD"), "authorized_keys"),
	}
	files, err := listFile(os.Getenv("PWD"), req, "127.0.0.1", sftpserver)
	require.NoError(t, err)
	file := files.files[0]
	require.Equal(t, filepath.Join(os.Getenv("PWD"), file.Name()), filepath.Join(os.Getenv("PWD"), "authorized_keys"))

	req = &sftp.Request{
		Method:   "Listfiles",
		Filepath: os.Getenv("PWD"),
	}

	files, err = listFile(os.Getenv("PWD"), req, "127.0.0.1", sftpserver)
	require.NoError(t, err)
	require.Greater(t, len(files.files), 4)
}

func TestWriteFile(t *testing.T) {
	req := &sftp.Request{
		Method:   "Writefile",
		Filepath: filepath.Join(os.Getenv("PWD"), "test.txt"),
	}
	file, err := writeFile(os.Getenv("PWD"), req, "127.0.0.1", sftpserver)
	require.NoError(t, err)
	_, err = file.Write([]byte("test content"))
	require.NoError(t, err)
}

func TestCmd(t *testing.T) {
	req := &sftp.Request{
		Method:   "Stat",
		Filepath: filepath.Join(os.Getenv("PWD"), "authorized_keys"),
	}

	err := cmdFile(os.Getenv("PWD"), req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Lstat",
		Filepath: filepath.Join(os.Getenv("PWD"), "authorized_keys"),
	}

	err = cmdFile(os.Getenv("PWD"), req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Mkdir",
		Filepath: filepath.Join(os.Getenv("PWD"), "testdir"),
	}

	err = cmdFile(os.Getenv("PWD"), req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Rename",
		Filepath: filepath.Join(os.Getenv("PWD"), "test.txt"),
		Target:   filepath.Join(os.Getenv("PWD"), "testdir", "test.txt"),
	}

	err = cmdFile(os.Getenv("PWD"), req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Setstat",
		Filepath: filepath.Join(os.Getenv("PWD"), "testdir", "test.txt"),
		Attrs:    []byte(`{"mode": 0644}`), // Invalid
	}
	err = cmdFile(os.Getenv("PWD"), req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	// TODO: Add test for Setstat with valid attributes

	req = &sftp.Request{
		Method:   "Remove",
		Filepath: filepath.Join(os.Getenv("PWD"), "testdir", "test.txt"),
	}

	err = cmdFile(os.Getenv("PWD"), req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Rmdir",
		Filepath: filepath.Join(os.Getenv("PWD"), "testdir"),
	}

	err = cmdFile(os.Getenv("PWD"), req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "INVALID",
		Filepath: os.Getenv("PWD"),
	}

	err = cmdFile(os.Getenv("PWD"), req, "127.0.0.1", sftpserver)
	require.Error(t, err)
}
