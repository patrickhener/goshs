// Package logger will take care of all logging messages using logrus
package logger

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/patrickhener/goshs/webhook"
	"github.com/pkg/sftp"
	"github.com/sirupsen/logrus"
)

func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func validateAndParseJSON(input []byte) (bool, interface{}) {
	var data interface{}

	// Attempt to unmarshal the input
	err := json.Unmarshal(input, &data)
	if err != nil {
		return false, nil
	}

	// If successful, return true and the parsed JSON
	return true, data
}

// LogRequest will log the request in a uniform way
func LogRequest(req *http.Request, status int, verbose bool, wh webhook.Webhook) {
	logger.Debug("We are about to log a request")
	if status == http.StatusInternalServerError || status == http.StatusNotFound || status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusBadRequest {
		logger.Errorf("%s - [\x1b[1;31m%d\x1b[0m] - \"%s %s %s\"", req.RemoteAddr, status, req.Method, req.URL, req.Proto)
	} else if status == http.StatusSeeOther || status == http.StatusMovedPermanently || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect {
		logger.Infof("%s - [\x1b[1;34m%d\x1b[0m] - \"%s %s %s\"", req.RemoteAddr, status, req.Method, req.URL, req.Proto)
	} else if status == http.StatusResetContent {
		logger.Infof("%s - [\x1b[1;31m%d\x1b[0m] - \"%s %s %s\"", req.RemoteAddr, status, req.Method, req.URL, req.Proto)
	} else {
		logger.Infof("%s - [\x1b[1;32m%d\x1b[0m] - \"%s %s %s\"", req.RemoteAddr, status, req.Method, req.URL, req.Proto)
	}
	if req.URL.Query() != nil {
		for k, v := range req.URL.Query() {
			logger.Debugf("Parameter %s is %s", k, v)
		}
	}
	if verbose {
		logger.Debug("We are using verbose logging")
		logVerbose(req, wh)
	}
}

func logVerbose(req *http.Request, wh webhook.Webhook) {
	// Headers
	for k, v := range req.Header {
		if k == "Authorization" {
			auth := v[0]
			logger.Verbosef("Authorization Header: %s", writeMagenta(auth))
			HandleWebhookSend(fmt.Sprintf("[VERBOSE] Authorization Header: %s", auth), "verbose", wh)
			if strings.Contains(strings.ToLower(auth), "basic") {
				decodedAuth, err := base64.StdEncoding.DecodeString(auth[6:])
				if err != nil {
					logger.Warnf("error decoding basic auth: %s", err)
					HandleWebhookSend(fmt.Sprintf("[VERBOSE] error decoding basic auth: %s", err), "verbose", wh)
					return
				}
				logger.Verbosef("Decoded Authorization is: '%s'", writeMagenta(string(decodedAuth)))
				HandleWebhookSend(fmt.Sprintf("[VERBOSE] Decoded Authorization is: `%s`", decodedAuth), "verbose", wh)
			}
		} else {
			decodedBase64, err := base64.StdEncoding.DecodeString(v[0])
			if err == nil && k != "Content-Type" && k != "Accept" && k != "Accept-Encoding" {
				logger.Verbosef("Header %s is base64 and decodes to '%s'", writeMagenta(k), writeMagenta(string(decodedBase64)))
				HandleWebhookSend(fmt.Sprintf("[VERBOSE] Header `%s` is base64 and decodes to\n```%s```\n", k, decodedBase64), "verbose", wh)
			} else {
				logger.Verbosef("Header %s is %s", writeMagenta(k), writeMagentaSlice(v))
				HandleWebhookSend(fmt.Sprintf("[VERBOSE] Header `%s` is `%s`", k, v), "verbose", wh)
			}
		}
	}
	// URL Parameter
	for k, v := range req.URL.Query() {
		input, err := url.QueryUnescape(v[0])
		if err != nil {
			logger.Warnf("error unescaping url parameter: %+v", err)
			HandleWebhookSend(fmt.Sprintf("[VERBOSE] error unescaping url parameter: %+v", err), "verbose", wh)
		}
		isValid, _ := validateAndParseJSON([]byte(input))
		if isValid {
			logger.Debug("JSON format detected")
			dst := &bytes.Buffer{}
			json.Indent(dst, []byte(v[0]), "", "  ")
			logger.Verbosef("Parameter %s is %s\n", writeMagenta(k), writeMagenta(dst.String()))
			HandleWebhookSend(fmt.Sprintf("[VERBOSE] JSON detected, Parameter %s is \n```%s```", k, dst.String()), "verbose", wh)
			continue
		}

		if isBase64(v[0]) {
			logger.Debug("Base64 detected")
			logger.Verbosef("Decoding Base64 before printing")
			decodedBytes, _ := base64.StdEncoding.DecodeString(v[0])
			logger.Verbosef("Parameter %s is %s\n", writeMagenta(k), writeMagenta(string(decodedBytes)))
			HandleWebhookSend(fmt.Sprintf("[VERBOSE] Base64 detected, Parameter `%s` is \n```%s```", k, string(decodedBytes)), "verbose", wh)

			continue
		}

		logger.Debug("Neither JSON nor Base64 parameter, so printing plain")
		logger.Verbosef("Parameter %s is %s", writeMagenta(k), writeMagenta(v[0]))
		HandleWebhookSend(fmt.Sprintf("[VERBOSE] Parameter `%s` is `%s`", k, v[0]), "verbose", wh)
	}

	// Body
	if req.Body != nil {
		logger.Debug("Body is detected")
		body, err := io.ReadAll(req.Body)
		if err != nil {
			logger.Warnf("error reading body: %+v", err)
			HandleWebhookSend(fmt.Sprintf("[VERBOSE] error reading body: %+v", err), "verbose", wh)
		}
		defer req.Body.Close()

		if len(body) > 0 {
			logger.Debug("Body is actually not empty")
			if req.Header.Get("Content-Type") == "application/json" {
				var prettyJson bytes.Buffer
				err := json.Indent(&prettyJson, body, "", "  ")
				if err != nil {
					logger.Warnf("error printing pretty json body: %+v", err)
					HandleWebhookSend(fmt.Sprintf("[VERBOSE] error printing pretty json body: %+v", err), "verbose", wh)
				}
				logger.Verbosef("JSON Request Body: \n%s\n", writeMagenta(prettyJson.String()))
				HandleWebhookSend(fmt.Sprintf("[VERBOSE] JSON Request Body: \n```%s```\n", prettyJson.String()), "verbose", wh)
				return
			}
			if isBase64(string(body)) {
				decodedBytes, _ := base64.StdEncoding.DecodeString(string(body))
				logger.Verbosef("Base64 Request Body: \n%s\n", writeMagenta(string(decodedBytes)))
				HandleWebhookSend(fmt.Sprintf("[VERBOSE] Base64 Request Body: \n```%s```\n", decodedBytes), "verbose", wh)
				return
			}

			logger.Verbosef("Request Body: \n%s\n", writeMagenta(string(body)))
			HandleWebhookSend(fmt.Sprintf("[VERBOSE] Request Body: \n```%s```\n", body), "verbose", wh)
		}
	}
}

func LogSFTPRequest(r *sftp.Request, ip string) {
	switch r.Method {
	case "Rename":
		logger.Infof("SFTP: %s - [\x1b[1;32m%s\x1b[0m] - \"%s to %s\"", ip, r.Method, r.Filepath, r.Target)
	default:
		logger.Infof("SFTP: %s - [\x1b[1;32m%s\x1b[0m] - \"%s\"", ip, r.Method, r.Filepath)
	}
}

func LogSFTPRequestBlocked(r *sftp.Request, ip string, err error) {
	switch r.Method {
	case "Rename":
		logger.Errorf("SFTP: %s - [\x1b[1;31m%s\x1b[0m] - \"%s to %s\" - %+v", ip, r.Method, r.Filepath, r.Target, err.Error())
	default:
		logger.Errorf("SFTP: %s - [\x1b[1;31m%s\x1b[0m] - \"%s\": %+v", ip, r.Method, r.Filepath, err.Error())
	}
}

func HandleWebhookSend(message string, event string, wh webhook.Webhook) {
	if wh.GetEnabled() {
		// Only send if wh.Contains(event) or if the first event is "all" but wh.Contains("verbose") is false
		if wh.Contains("all") && event != "verbose" {
			wh.Send(message)
		} else if wh.Contains(event) {
			wh.Send(message)
		} else if wh.Contains("verbose") && event == "verbose" {
			wh.Send(message)
		}
	}
}

var logger *StandardLogger

func writeMagenta(s string) string {
	return fmt.Sprintf("\x1b[1;35m%s\x1b[0m", s)
}

func writeMagentaSlice(s []string) string {
	return fmt.Sprintf("\x1b[1;35m%s\x1b[0m", strings.Join(s, " "))
}

func init() {
	logger = NewLogger()
}

// Event stores messages to log later, from our standard interface.
type Event struct {
	id      int
	message string
}

// StandardLogger enforces specific log message formats.
type StandardLogger struct {
	*logrus.Logger
}

type CustomFormatter struct {
	logrus.TextFormatter
}

func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// Check for custom 'verbose' field
	if verbose, ok := entry.Data["verbose"]; ok && verbose == true {
		// Format timestamp
		timestamp := entry.Time.Format(f.TimestampFormat)
		// Apply a different color (e.g. magenta: "\x1b[1;35m")
		output := fmt.Sprintf("\x1b[1;35mVERB\x1b[0m   [%s] %s\n", timestamp, entry.Message)

		return []byte(output), nil
	}
	return f.TextFormatter.Format(entry)
}

// NewLogger initializes the standard logger.
func NewLogger() *StandardLogger {
	baseLogger := logrus.New()
	standardLogger := &StandardLogger{baseLogger}

	standardLogger.SetFormatter(&CustomFormatter{
		TextFormatter: logrus.TextFormatter{
			FullTimestamp:   true,
			ForceColors:     true,
			PadLevelText:    true,
			TimestampFormat: "2006-01-02 15:04:05",
		},
	})

	// Log level
	standardLogger.SetLevel(logrus.InfoLevel)

	if os.Getenv("DEBUG") == "TRUE" {
		standardLogger.SetLevel(logrus.DebugLevel)
		// standardLogger.SetReportCaller(true)
	}

	return standardLogger
}

func LogFile(multiwriter io.Writer) {
	logger.SetOutput(multiwriter)
}

// Declare variables to store log messages as new Events
var (
	missingEnvMessage = Event{1, "Missing env key: %s"}
)

// MissingEnv is a standard error message
func MissingEnv(envName string) {
	logger.Panicf(missingEnvMessage.message, envName)
}

// Debug Log
func Debug(args ...interface{}) {
	logger.Debugln(args...)
}

// Debugf Log
func Debugf(format string, args ...interface{}) {
	logger.Debugf(format, args...)
}

// Info Log
func Info(args ...interface{}) {
	logger.Infoln(args...)
}

// Infof Log
func Infof(format string, args ...interface{}) {
	logger.Infof(format, args...)
}

// Warn Log
func Warn(args ...interface{}) {
	logger.Warnln(args...)
}

// Warnf Log
func Warnf(format string, args ...interface{}) {
	logger.Warnf(format, args...)
}

// Panic Log
func Panic(args ...interface{}) {
	logger.Panicln(args...)
}

// Panicf Log
func Panicf(format string, args ...interface{}) {
	logger.Panicf(format, args...)
}

// Error Log
func Error(args ...interface{}) {
	logger.Errorln(args...)
}

// Errorf Log
func Errorf(format string, args ...interface{}) {
	logger.Errorf(format, args...)
}

// Fatal Log
func Fatal(args ...interface{}) {
	logger.Fatalln(args...)
}

// Fatalf Log
func Fatalf(format string, args ...interface{}) {
	logger.Fatalf(format, args...)
}

// Verbose Log
func (l *StandardLogger) Verbose(args ...interface{}) {
	l.WithField("verbose", true).Infoln(args...)
}

// Verbosef Log
func (l *StandardLogger) Verbosef(format string, args ...interface{}) {
	l.WithField("verbose", true).Infof(format, args...)
}
