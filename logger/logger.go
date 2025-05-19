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
func LogRequest(req *http.Request, status int, verbose bool) {
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
		logVerbose(req)
	}
}

func logVerbose(req *http.Request) {
	// User Agent
	logger.Infof("User Agent: %s", req.UserAgent())
	// Authentication
	auth := req.Header.Get("Authorization")
	if auth != "" {
		logger.Infof("Authorization Header: %s", auth)
		if strings.Contains(auth, "Basic") {
			decodedAuth, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(auth, "Basic ", ""))
			if err != nil {
				logger.Warnf("error decoding basic auth: %s", err)
				return
			}
			logger.Infof("Decoded Authorization is: '%s'", decodedAuth)
		}
	}
	// URL Parameter
	for k, v := range req.URL.Query() {
		logger.Infof("Parameter %s is", k)
		input, err := url.QueryUnescape(v[0])
		if err != nil {
			logger.Warnf("error unescaping url parameter: %+v", err)
		}
		isValid, _ := validateAndParseJSON([]byte(input))
		if isValid {
			logger.Debug("JSON format detected")
			dst := &bytes.Buffer{}
			json.Indent(dst, []byte(v[0]), "", "  ")
			fmt.Println(dst.String())
			continue
		}

		if isBase64(v[0]) {
			logger.Debug("Base64 detected")
			logger.Info("Decoding Base64 before printing")
			decodedBytes, _ := base64.StdEncoding.DecodeString(v[0])
			fmt.Println(string(decodedBytes))

			continue
		}

		logger.Debug("Neither JSON nor Base64 parameter, so printing plain")
		fmt.Println(v[0])
	}

	// Body
	if req.Body != nil {
		logger.Debug("Body is detected")
		body, err := io.ReadAll(req.Body)
		if err != nil {
			Warnf("error reading body: %+v", err)
		}
		defer req.Body.Close()

		if len(body) > 0 {
			logger.Debug("Body is actually not empty")
			if req.Header.Get("Content-Type") == "application/json" {
				var prettyJson bytes.Buffer
				err := json.Indent(&prettyJson, body, "", "  ")
				if err != nil {
					Warnf("error printing pretty json body: %+v", err)
				}
				logger.Infof("JSON Request Body: \n%s\n", prettyJson.String())
				return
			}
			if isBase64(string(body)) {
				decodedBytes, _ := base64.StdEncoding.DecodeString(string(body))
				logger.Infof("Base64 Request Body: \n%s\n", decodedBytes)
				return
			}

			logger.Infof("Request Body: \n%s\n", body)
		}
	}
}

func LogSFTPRequest(r *sftp.Request, ip string) {
	switch r.Method {
	case "Rename":
		logger.Infof("%s - [\x1b[1;34m%s\x1b[0m] - \"%s to %s\"", ip, r.Method, r.Filepath, r.Target)
	default:
		logger.Infof("%s - [\x1b[1;34m%s\x1b[0m] - \"%s\"", ip, r.Method, r.Filepath)
	}
}

var logger *StandardLogger

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

// NewLogger initializes the standard logger.
func NewLogger() *StandardLogger {
	baseLogger := logrus.New()
	standardLogger := &StandardLogger{baseLogger}

	standardLogger.Formatter = &logrus.TextFormatter{
		FullTimestamp:   true,
		ForceColors:     true,
		PadLevelText:    true,
		TimestampFormat: "2006-01-02 15:04:05",
	}
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
