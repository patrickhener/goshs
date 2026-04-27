package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestCertificationAuth test that cert auth is working
func TestCertificationAuth(t *testing.T) {
	// spawn a test container
	port := spawnTestContainer(t, "%s/configs/cert_auth.json", false, false)
	baseUrl := fmt.Sprintf("https://localhost:%d", port.Int())

	// Test unauth connection
	testUnauthCertConnection(t, baseUrl)

	// Test auth connection
	certFile := filepath.Join(os.Getenv("PWD"), "certs", "client.crt")
	keyFile := filepath.Join(os.Getenv("PWD"), "certs", "client.key")
	testAuthCertConnection(t, baseUrl, certFile, keyFile)
}

// TestSelfSignedTLS tests self signed certificates
func TestSelfSignedTLS(t *testing.T) {
	// spawn a test container
	port := spawnTestContainer(t, "%s/configs/tls_self_signed.json", false, false)
	baseUrl := fmt.Sprintf("https://localhost:%d", port.Int())

	// Test TLS Connection
	testSelfSigned(t, baseUrl)
}

// TestTLS tests tls with given key and cert
func TestTLS(t *testing.T) {
	// spawn a test container
	port := spawnTestContainer(t, "%s/configs/tls_self_signed.json", false, false)
	baseUrl := fmt.Sprintf("https://localhost:%d", port.Int())

	// Test TLS Connection
	testSelfSigned(t, baseUrl)
}

// TestTLSP12 tests tls with given p12
func TestTLSP12(t *testing.T) {
	// spawn a test container
	port := spawnTestContainer(t, "%s/configs/tls_p12.json", false, false)
	baseUrl := fmt.Sprintf("https://localhost:%d", port.Int())

	// Test TLS Connection
	testSelfSigned(t, baseUrl)
}

// TestWebdav test if webdav works
func TestWebdav(t *testing.T) {
	// spawn a test container
	port := spawnTestContainer(t, "%s/configs/webdav.json", true, false)
	baseUrl := fmt.Sprintf("http://localhost:%d", port.Int())

	// Test connection
	testWebdavConnection(t, baseUrl)

	// Test List Files
	testWebdavListFiles(t, baseUrl)

	// Test Create Dir
	testWebdavCreateDir(t, baseUrl)

	// Test Download
	testWebdavDownload(t, baseUrl)

	// Test Upload
	testWebdavUpload(t, baseUrl)

	// Test Move/Copy
	testWebdavMoveCopy(t, baseUrl)

	// Teste Delete File
	testWebdavDelete(t, baseUrl)
}

// TestWebdavAuth test if webdav works
func TestWebdavAuth(t *testing.T) {
	port := spawnTestContainer(t, "%s/configs/webdav_auth.json", true, false)
	baseUrl := fmt.Sprintf("http://localhost:%d", port.Int())

	// Test Unauth Connection
	testWebdavUnauthConnection(t, baseUrl)

	// Test Auth Connection
	testWebdavAuthConnection(t, baseUrl)
}

// ─── SMB tests ───────────────────────────────────────────────────────────────

// TestSmb tests SMB file operations (anonymous/capture mode)
func TestSmb(t *testing.T) {
	port := spawnTestContainer(t, "%s/configs/smb.json", false, true)
	host := "localhost"
	smbPort := port.Int()

	// Test connection
	testSmbConnection(t, host, smbPort)

	// Test list files
	testSmbListShare(t, host, smbPort)

	// Test download
	testSmbDownload(t, host, smbPort)

	// Test upload
	testSmbUpload(t, host, smbPort)

	// Test mkdir
	testSmbMkdir(t, host, smbPort)

	// Test rename (move file into new folder)
	testSmbRename(t, host, smbPort)

	// Test delete
	testSmbDelete(t, host, smbPort)
}

// TestSmbAuth tests SMB with authentication
func TestSmbAuth(t *testing.T) {
	port := spawnTestContainer(t, "%s/configs/smb_auth.json", false, true)
	host := "localhost"
	smbPort := port.Int()

	// Test that unauth connection fails
	testSmbUnauthConnection(t, host, smbPort)

	// Test that auth connection succeeds
	testSmbAuthConnection(t, host, smbPort)
}
