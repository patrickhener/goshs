package mylog

import (
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
)

// LogRequest will log the request in a uniform way
func LogRequest(req *http.Request, status int, verbose bool) {
	if status == http.StatusInternalServerError || status == http.StatusNotFound {
		if verbose {
			logger.Errorf("[User-Agent: %s] %s - - \"%s %s %s\" - %+v", req.UserAgent(), req.RemoteAddr, req.Method, req.URL, req.Proto, status)
			return

		}
		logger.Errorf("%s - - \"%s %s %s\" - %+v", req.RemoteAddr, req.Method, req.URL, req.Proto, status)
		return
	}
	if verbose {
		logger.Infof("[User-Agent: %s] %s - - \"%s %s %s\" - %+v", req.UserAgent(), req.RemoteAddr, req.Method, req.URL, req.Proto, status)
		if req.URL.Query() != nil {
			for k, v := range req.URL.Query() {
				logger.Debugf("Parameter %s is %s", k, v)
			}
		}
		return
	}
	logger.Infof("%s - - \"%s %s %s\" - %+v", req.RemoteAddr, req.Method, req.URL, req.Proto, status)
	if req.URL.Query() != nil {
		for k, v := range req.URL.Query() {
			logger.Debugf("Parameter %s is %s", k, v)
		}
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

	// We could transform the errors into a JSON format, for external log SaaS tools such as splunk or logstash
	// standardLogger.Formatter = &logrus.JSONFormatter{
	//   PrettyPrint: true,
	// }

	return standardLogger
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
