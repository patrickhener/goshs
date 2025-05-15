package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUnsecureServer tests all functionality of the unsecured server and the most basic functions of goshs
func TestUnsecureServer(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/unsecured.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("http://localhost:%d", port.Int())

	// Test connection
	testConnection(t, baseUrl)

	// Test View
	testView(t, fmt.Sprintf("%s/test_data.txt", baseUrl), false)

	// Test Download
	testDownload(t, fmt.Sprintf("%s/test_data.txt?download", baseUrl), false)

	// Test Upload via HTTP PUT, POST
	testUploadPost(t, baseUrl, false, false)
	testUploadPut(t, baseUrl, false, false)

	// Test Bulk Download
	testBulkDownload(t, fmt.Sprintf("http://localhost:%d/?file=%%252Ftest_data.txt&file=%%252Fupload_POST_test_data.txt&file=%%252Fupload_PUT_test_data.txt&bulk=true", port.Int()), false)

	// Test JSON view
	testJsonOutput(t, fmt.Sprintf("%s/?json", baseUrl))

	// Test File Removal
	testRemoval(t, fmt.Sprintf("%s/%%2Fupload_POST_test_data.txt?delete", baseUrl), false)
	testRemoval(t, fmt.Sprintf("%s/%%2Fupload_PUT_test_data.txt?delete", baseUrl), false)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestBasicAuthServer test that basic auth is working
func TestBasicAuthServer(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/basic_auth.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("http://localhost:%d", port.Int())

	// Test unauth connection - should 401
	testUnauthConnection(t, baseUrl)

	// Test auth connection - should 200
	testAuthConnection(t, baseUrl)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestBasicAuthServerHashed test that basic auth is working with hashed password in config
func TestBasicAuthServerHashed(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/basic_auth_hashed.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("http://localhost:%d", port.Int())

	// Test unauth connection - should 401
	testUnauthConnection(t, baseUrl)

	// Test auth connection - should 200
	testAuthConnection(t, baseUrl)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestCertificationAuth test that cert auth is working
func TestCertificationAuth(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/cert_auth.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("https://localhost:%d", port.Int())

	// Test unauth connection
	testUnauthCertConnection(t, baseUrl)

	// Test auth connection
	certFile := filepath.Join(os.Getenv("PWD"), "certs", "client.crt")
	keyFile := filepath.Join(os.Getenv("PWD"), "certs", "client.key")
	testAuthCertConnection(t, baseUrl, certFile, keyFile)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestSelfSignedTLS tests self signed certificates
func TestSelfSignedTLS(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/tls_self_signed.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("https://localhost:%d", port.Int())

	// Test TLS Connection
	testSelfSigned(t, baseUrl)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestTLS tests tls with given key and cert
func TestTLS(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/tls_self_signed.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("https://localhost:%d", port.Int())

	// Test TLS Connection
	testSelfSigned(t, baseUrl)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestTLSP12 tests tls with given p12
func TestTLSP12(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/tls_p12.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("https://localhost:%d", port.Int())

	// Test TLS Connection
	testSelfSigned(t, baseUrl)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestReadOnly tests if read only works
func TestReadOnly(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/read_only.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("http://localhost:%d", port.Int())

	// Test upload not allowed
	testUploadPost(t, baseUrl, true, false)
	testUploadPut(t, baseUrl, true, false)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestUploadOnly tests if upload only works
func TestUploadOnly(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/upload_only.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("http://localhost:%d", port.Int())

	// Test View
	testView(t, fmt.Sprintf("%s/test_data.txt", baseUrl), true)

	// Test Download
	testDownload(t, fmt.Sprintf("%s/test_data.txt?download", baseUrl), true)

	// Test Upload via HTTP PUT, POST
	testUploadPost(t, baseUrl, false, true)
	testUploadPut(t, baseUrl, false, true)

	// Test Bulk Download
	testBulkDownload(t, fmt.Sprintf("http://localhost:%d/?file=%%252Ftest_data.txt&file=%%252Fupload_POST_test_data.txt&file=%%252Fupload_PUT_test_data.txt&bulk=true", port.Int()), true)

	// Test JSON view
	testJsonOutput(t, fmt.Sprintf("%s/?json", baseUrl))

	// Test File Removal
	testRemoval(t, fmt.Sprintf("%s/%%2Fupload_POST_test_data.txt?delete", baseUrl), true)
	testRemoval(t, fmt.Sprintf("%s/%%2Fupload_PUT_test_data.txt?delete", baseUrl), true)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestNoClipboard test if the clipboard is not in UI anymore
func TestNoClipboard(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/no_clipboard.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("http://localhost:%d", port.Int())

	// Test no rednder clipboard
	testNoClipboard(t, baseUrl)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestNoDelete test if no delete works
func TestNoDelete(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/no_delete.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("http://localhost:%d", port.Int())

	// Test Upload via HTTP PUT, POST
	testUploadPost(t, baseUrl, false, false)
	testUploadPut(t, baseUrl, false, false)

	// Test File Removal
	testRemoval(t, fmt.Sprintf("%s/%%2Fupload_POST_test_data.txt?delete", baseUrl), true)
	testRemoval(t, fmt.Sprintf("%s/%%2Fupload_PUT_test_data.txt?delete", baseUrl), true)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestWebdav test if webdav works
func TestWebdav(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/webdav.json", true)
	require.NoError(t, err)
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

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestWebdavAuth test if webdav works
func TestWebdavAuth(t *testing.T) {
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/webdav_auth.json", true)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("http://localhost:%d", port.Int())

	// Test Unauth Connection
	testWebdavUnauthConnection(t, baseUrl)

	// Test Unauth Connection
	testWebdavAuthConnection(t, baseUrl)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestFileBasedACL test if ACLs work
func TestFileBasedACL(t *testing.T) {
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/unsecured.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("http://localhost:%d", port.Int())

	// Test ACLs
	testACLs(t, baseUrl)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestOutputLog test if output to log works
func TestOutputLog(t *testing.T) {
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/output_log.json", false)
	require.NoError(t, err)
	baseUrl := fmt.Sprintf("http://localhost:%d", port.Int())

	// Test if log was written and contains content
	testLogOutput(t, baseUrl)

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}
