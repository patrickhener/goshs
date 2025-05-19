package sftpserver

import (
	"errors"
	"io"

	"github.com/patrickhener/goshs/logger"
	"github.com/pkg/sftp"
)

// ReadOnlyHandler is an SFTP handler that only allows read operations
type ReadOnlyHandler struct {
	Root     string
	ClientIP string
}

func (h *ReadOnlyHandler) GetHandler() sftp.Handlers {
	return sftp.Handlers{
		FileGet:  &ReadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP},
		FilePut:  &ReadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP},
		FileCmd:  &ReadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP},
		FileList: &ReadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP},
	}
}

func (h *ReadOnlyHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	return readFile(h.Root, r, h.ClientIP)
}

func (h *ReadOnlyHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	logger.LogSFTPRequestBlocked(r, h.ClientIP, errors.New("upload not allowed in read-only mode"))
	return nil, errors.New("upload not allowed in read-only mode")
}

func (h *ReadOnlyHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	return listFile(h.Root, r, h.ClientIP)
}

func (h *ReadOnlyHandler) Filecmd(r *sftp.Request) error {
	logger.LogSFTPRequestBlocked(r, h.ClientIP, errors.New("file commands are not allowed in read-only mode"))
	return errors.New("file commands are not allowed in read-only mode")
}

// UploadOnlyHandler is an SFTP handler that only allows upload operations
type UploadOnlyHandler struct {
	Root     string
	ClientIP string
}

func (h *UploadOnlyHandler) GetHandler() sftp.Handlers {
	return sftp.Handlers{
		FileGet:  &UploadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP},
		FilePut:  &UploadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP},
		FileCmd:  &UploadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP},
		FileList: &UploadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP},
	}
}

func (h *UploadOnlyHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	logger.LogSFTPRequestBlocked(r, h.ClientIP, errors.New("download not allowed in upload-only mode"))
	return nil, errors.New("download not allowed in upload-only mode")
}

func (h *UploadOnlyHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	return writeFile(h.Root, r, h.ClientIP)
}

func (h *UploadOnlyHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	return listFile(h.Root, r, h.ClientIP)
}

func (h *UploadOnlyHandler) Filecmd(r *sftp.Request) error {
	logger.LogSFTPRequestBlocked(r, h.ClientIP, errors.New("file commands are not allowed in upload-only mode"))
	return errors.New("file commands are not allowed in upload-only mode")
}

// DefaultHandler is an SFTP handler that allows all operations
type DefaultHandler struct {
	Root     string
	ClientIP string
}

func (h *DefaultHandler) GetHandler() sftp.Handlers {
	return sftp.Handlers{
		FileGet:  &DefaultHandler{Root: h.Root, ClientIP: h.ClientIP},
		FilePut:  &DefaultHandler{Root: h.Root, ClientIP: h.ClientIP},
		FileCmd:  &DefaultHandler{Root: h.Root, ClientIP: h.ClientIP},
		FileList: &DefaultHandler{Root: h.Root, ClientIP: h.ClientIP},
	}
}

func (h *DefaultHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	return readFile(h.Root, r, h.ClientIP)
}

func (h *DefaultHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	return writeFile(h.Root, r, h.ClientIP)
}

func (h *DefaultHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	return listFile(h.Root, r, h.ClientIP)
}

func (h *DefaultHandler) Filecmd(r *sftp.Request) error {
	return cmdFile(h.Root, r, h.ClientIP)
}
