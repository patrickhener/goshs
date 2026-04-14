package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"goshs.de/goshs/options"
	"github.com/stretchr/testify/require"
)

func writeTempConfig(t *testing.T, cfg Config) string {
	t.Helper()
	b, err := json.MarshalIndent(cfg, "", "  ")
	require.NoError(t, err)
	f, err := os.CreateTemp(t.TempDir(), "goshs-cfg-*.json")
	require.NoError(t, err)
	_, err = f.Write(b)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestLoadConfig_BasicFields(t *testing.T) {
	cfg := Config{
		Interface: "127.0.0.1",
		Port:      9090,
		Directory: "/tmp/testroot",
		SSL:       true,
		SelfSigned: true,
	}

	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", result.IP)
	require.Equal(t, 9090, result.Port)
	require.Equal(t, "/tmp/testroot", result.Webroot)
	require.True(t, result.SSL)
	require.True(t, result.SelfSigned)
}

func TestLoadConfig_BasicAuth(t *testing.T) {
	cfg := Config{
		AuthUsername: "alice",
		AuthPassword: "s3cret",
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.Equal(t, "alice:s3cret", result.BasicAuth)
}

func TestLoadConfig_UploadFolderDefaultsToWebroot(t *testing.T) {
	cfg := Config{
		Directory:    "/srv/web",
		UploadFolder: "",
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.Equal(t, "/srv/web", result.UploadFolder, "upload folder should default to webroot when not set")
}

func TestLoadConfig_ExplicitUploadFolder(t *testing.T) {
	cfg := Config{
		Directory:    "/srv/web",
		UploadFolder: "/srv/uploads",
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.Equal(t, "/srv/uploads", result.UploadFolder)
}

func TestLoadConfig_WebhookFields(t *testing.T) {
	cfg := Config{
		WebhookEnabled:  true,
		WebhookURL:      "https://hooks.example.com/abc",
		WebhookProvider: "slack",
		WebhookEvents:   []string{"upload", "download"},
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.True(t, result.WebhookEnabled)
	require.Equal(t, "https://hooks.example.com/abc", result.WebhookURL)
	require.Equal(t, "slack", result.WebhookProvider)
	require.Equal(t, []string{"upload", "download"}, result.WebhookEventsParsed)
}

func TestLoadConfig_ConfigPathIsAbsolute(t *testing.T) {
	cfg := Config{}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.True(t, filepath.IsAbs(result.ConfigPath))
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	opts := &options.Options{ConfigFile: "/nonexistent/path/config.json"}
	_, err := LoadConfig(opts)
	require.Error(t, err)
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bad-*.json")
	require.NoError(t, err)
	_, err = f.WriteString("{not valid json")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	opts := &options.Options{ConfigFile: f.Name()}
	_, err = LoadConfig(opts)
	require.Error(t, err)
}

func TestPrintExample_ValidJSON(t *testing.T) {
	out, err := PrintExample()
	require.NoError(t, err)
	require.NotEmpty(t, out)

	// Must be valid JSON
	var cfg Config
	err = json.Unmarshal([]byte(out), &cfg)
	require.NoError(t, err)
}

func TestPrintExample_DefaultValues(t *testing.T) {
	out, err := PrintExample()
	require.NoError(t, err)

	var cfg Config
	require.NoError(t, json.Unmarshal([]byte(out), &cfg))
	require.Equal(t, "0.0.0.0", cfg.Interface)
	require.Equal(t, 8000, cfg.Port)
	require.Equal(t, ".", cfg.Directory)
	require.Equal(t, "discord", cfg.WebhookProvider)
}
