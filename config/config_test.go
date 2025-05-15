package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	configPath := filepath.Join(os.Getenv("PWD"), "goodConfig.json")

	config, err := Load(configPath)
	require.NoError(t, err)
	require.Equal(t, config.WebdavPort, 8001)

	configPath = filepath.Join(os.Getenv("PWD"), "goodConfig.json.foo")
	_, err = Load(configPath)
	require.Error(t, err)

	configPath = filepath.Join(os.Getenv("PWD"), "brokenConfig.json")
	_, err = Load(configPath)

	require.Error(t, err)
}

func TestPrintExample(t *testing.T) {
	result, err := PrintExample()
	require.NoError(t, err)
	require.Contains(t, result, "interface")
}

func TestSanityChecks(t *testing.T) {
	webroot := filepath.Join(os.Getenv("PWD"))
	differentWebroot := filepath.Join(os.Getenv("PWD"), "NotConfigPath")
	configPath := filepath.Join(os.Getenv("PWD"), "goodConfig.json")
	badConfigPath := filepath.Join(os.Getenv("PWD"), "goodConfig.json.foo")
	configPathReadOnly := filepath.Join(os.Getenv("PWD"), "goodConfigReadOnly.json")

	// Test config file accessible and writable
	err := SanityChecks(webroot, configPath, "testpassword")
	require.Error(t, err)

	// Test config file not openable
	err = SanityChecks(webroot, badConfigPath, "testpassword")
	require.Error(t, err)

	// Test config file not in webroot and unhashed password
	err = SanityChecks(differentWebroot, configPathReadOnly, "testpassword")
	require.NoError(t, err)
}
