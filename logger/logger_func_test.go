package logger

import (
	"bytes"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// captureOutput redirects the global logger to a buffer and returns a restore function.
func captureOutput(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	orig := logger.Out
	buf := &bytes.Buffer{}
	logger.SetOutput(buf)
	return buf, func() { logger.SetOutput(orig) }
}

func TestNewLogger(t *testing.T) {
	l := NewLogger()
	require.NotNil(t, l)
	require.Equal(t, logrus.InfoLevel, l.GetLevel())
}

func TestDebug(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()
	logger.SetLevel(logrus.DebugLevel)
	defer logger.SetLevel(logrus.InfoLevel)

	Debug("debug msg")
	require.Contains(t, buf.String(), "debug msg")
}

func TestDebugf(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()
	logger.SetLevel(logrus.DebugLevel)
	defer logger.SetLevel(logrus.InfoLevel)

	Debugf("val=%d", 42)
	require.Contains(t, buf.String(), "val=42")
}

func TestInfo(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()

	Info("info msg")
	require.Contains(t, buf.String(), "info msg")
}

func TestInfof(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()

	Infof("hello %s", "world")
	require.Contains(t, buf.String(), "hello world")
}

func TestWarn(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()

	Warn("warn msg")
	require.Contains(t, buf.String(), "warn msg")
}

func TestWarnf(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()

	Warnf("warning: %s", "test")
	require.Contains(t, buf.String(), "warning: test")
}

func TestError(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()

	Error("error msg")
	require.Contains(t, buf.String(), "error msg")
}

func TestErrorf(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()

	Errorf("err: %d", 1)
	require.Contains(t, buf.String(), "err: 1")
}

func TestPanic(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()

	require.Panics(t, func() {
		Panic("panic msg")
	})
	require.Contains(t, buf.String(), "panic msg")
}

func TestPanicf(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()

	require.Panics(t, func() {
		Panicf("panic: %s", "boom")
	})
	require.Contains(t, buf.String(), "panic: boom")
}

func TestMissingEnv(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()

	require.Panics(t, func() {
		MissingEnv("MY_VAR")
	})
	require.Contains(t, buf.String(), "MY_VAR")
}

func TestLogFile(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()

	// LogFile sets output to a multiwriter wrapping the buffer
	LogFile(buf)
	Info("logtest")
	require.Contains(t, buf.String(), "logtest")
}

func TestVerbose(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()

	logger.Verbose("verbose msg")
	require.Contains(t, buf.String(), "VERB")
	require.Contains(t, buf.String(), "verbose msg")
}

func TestVerbosef(t *testing.T) {
	buf, restore := captureOutput(t)
	defer restore()

	logger.Verbosef("val=%d", 99)
	require.Contains(t, buf.String(), "VERB")
	require.Contains(t, buf.String(), "val=99")
}

func TestWriteMagenta(t *testing.T) {
	s := writeMagenta("test")
	require.Contains(t, s, "test")
	require.Contains(t, s, "\x1b[1;35m")
}

func TestWriteMagentaSlice(t *testing.T) {
	s := writeMagentaSlice([]string{"a", "b"})
	require.Contains(t, s, "a b")
	require.Contains(t, s, "\x1b[1;35m")
}

func TestCustomFormatter_Verbose(t *testing.T) {
	f := &CustomFormatter{
		TextFormatter: logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		},
	}
	entry := &logrus.Entry{
		Data:    map[string]any{"verbose": true},
		Message: "test verbose",
	}
	out, err := f.Format(entry)
	require.NoError(t, err)
	require.Contains(t, string(out), "VERB")
	require.Contains(t, string(out), "test verbose")
}

func TestCustomFormatter_Normal(t *testing.T) {
	f := &CustomFormatter{
		TextFormatter: logrus.TextFormatter{
			DisableTimestamp: true,
		},
	}
	entry := &logrus.Entry{
		Data:    map[string]any{},
		Message: "normal msg",
		Level:   logrus.InfoLevel,
	}
	out, err := f.Format(entry)
	require.NoError(t, err)
	require.Contains(t, string(out), "normal msg")
}
