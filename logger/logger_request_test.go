package logger

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pkg/sftp"
	"goshs.de/goshs/v2/webhook"
)

func webhookDisabled() webhook.Webhook {
	w := webhook.Register(false, "", "discord", []string{})
	return *w
}

func TestLogRequest_StatusOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test?foo=bar", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusOK, false, nil, nil)
}

func TestLogRequest_StatusNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusNotFound, false, nil, nil)
}

func TestLogRequest_StatusUnauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusUnauthorized, false, nil, nil)
}

func TestLogRequest_StatusForbidden(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/forbidden", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusForbidden, false, nil, nil)
}

func TestLogRequest_StatusBadRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/bad", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusBadRequest, false, nil, nil)
}

func TestLogRequest_StatusInternalServerError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/error", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusInternalServerError, false, nil, nil)
}

func TestLogRequest_Redirect(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/redirect", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusSeeOther, false, nil, nil)
	LogRequest(req, http.StatusMovedPermanently, false, nil, nil)
	LogRequest(req, http.StatusTemporaryRedirect, false, nil, nil)
	LogRequest(req, http.StatusPermanentRedirect, false, nil, nil)
}

func TestLogRequest_StatusResetContent(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/file", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusResetContent, false, nil, nil)
}

func TestLogRequest_VerboseBasicAuth(t *testing.T) {
	wh := webhookDisabled()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("Authorization", "Basic UGVyc29uOmFzZGY=")
	LogRequest(req, http.StatusOK, true, wh, nil)
}

func TestLogRequest_VerboseNonBase64Header(t *testing.T) {
	wh := webhookDisabled()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("X-Custom", "not-base64!!!")
	LogRequest(req, http.StatusOK, true, wh, nil)
}

func TestLogRequest_VerboseBase64Header(t *testing.T) {
	wh := webhookDisabled()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("X-Custom", "SGVsbG8gV29ybGQ=")
	LogRequest(req, http.StatusOK, true, wh, nil)
}

func TestLogRequest_VerboseJSONParam(t *testing.T) {
	wh := webhookDisabled()
	req := httptest.NewRequest(http.MethodGet, "/?data=%7B%22key%22%3A%22value%22%7D", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusOK, true, wh, nil)
}

func TestLogRequest_VerboseBase64Param(t *testing.T) {
	wh := webhookDisabled()
	req := httptest.NewRequest(http.MethodGet, "/?data=SGVsbG8gV29ybGQ=", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusOK, true, wh, nil)
}

func TestLogRequest_VerbosePlainParam(t *testing.T) {
	wh := webhookDisabled()
	req := httptest.NewRequest(http.MethodGet, "/?name=test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusOK, true, wh, nil)
}

func TestLogRequest_VerboseJSONBody(t *testing.T) {
	wh := webhookDisabled()
	body := []byte(`{"hello": "world"}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("Content-Type", "application/json")
	LogRequest(req, http.StatusOK, true, wh, body)
}

func TestLogRequest_VerboseBase64Body(t *testing.T) {
	wh := webhookDisabled()
	body := []byte("SGVsbG8gV29ybGQ=")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusOK, true, wh, body)
}

func TestLogRequest_VerbosePlainBody(t *testing.T) {
	wh := webhookDisabled()
	body := []byte("plain text body")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusOK, true, wh, body)
}

func TestLogSFTPRequest(t *testing.T) {
	r := &sftp.Request{Method: "Get", Filepath: "/test.txt"}
	LogSFTPRequest(r, "1.2.3.4")

	rRename := &sftp.Request{Method: "Rename", Filepath: "/old.txt", Target: "/new.txt"}
	LogSFTPRequest(rRename, "1.2.3.4")
}

func TestLogSFTPRequestBlocked(t *testing.T) {
	r := &sftp.Request{Method: "Get", Filepath: "/blocked.txt"}
	LogSFTPRequestBlocked(r, "1.2.3.4", errors.New("access denied"))

	rRename := &sftp.Request{Method: "Rename", Filepath: "/old.txt", Target: "/new.txt"}
	LogSFTPRequestBlocked(rRename, "1.2.3.4", errors.New("not allowed"))
}

func TestLogRequest_VerboseBasicAuthBadEncoding(t *testing.T) {
	wh := webhookDisabled()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("Authorization", "Basic !!invalid!!")
	LogRequest(req, http.StatusOK, true, wh, nil)
}

func TestHandleWebhookSend_Disabled(t *testing.T) {
	wh := webhookDisabled()
	HandleWebhookSend("test", "upload", wh)
}

func TestHandleWebhookSend_NilWebhook(t *testing.T) {
	wh := webhookDisabled()
	HandleWebhookSend("test", "upload", wh)
}

func TestLogRequest_EmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	LogRequest(req, http.StatusOK, true, nil, nil)
}
