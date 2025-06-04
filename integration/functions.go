package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
	"github.com/studio-b12/gowebdav"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func spawnTestContainer(t *testing.T, config string, webdav bool) (nat.Port, testcontainers.Container, error) {
	// webdav ports
	var webdavPort string
	var webdavPortNat nat.Port

	// fetch the server config
	configPath := fmt.Sprintf(config, os.Getenv("PWD"))
	caCertPath := fmt.Sprintf("%s/certs/ca.crt", os.Getenv("PWD"))
	serverP12Path := fmt.Sprintf("%s/certs/goshs.p12", os.Getenv("PWD"))
	serverCertPath := fmt.Sprintf("%s/certs/goshs.crt", os.Getenv("PWD"))
	serverKeyPath := fmt.Sprintf("%s/certs/goshs.key", os.Getenv("PWD"))

	// Output paths
	fmt.Printf("Config path: %+v\n", configPath)
	fmt.Printf("CA path: %+v\n", caCertPath)
	fmt.Printf("P12 path: %+v\n", serverP12Path)

	// readers for file copy
	r, err := os.Open(configPath)
	require.NoError(t, err)

	c, err := os.Open(caCertPath)
	require.NoError(t, err)

	p, err := os.Open(serverP12Path)
	require.NoError(t, err)

	crt, err := os.Open(serverCertPath)
	require.NoError(t, err)

	k, err := os.Open(serverKeyPath)
	require.NoError(t, err)

	// declare the port for this test
	testPort := fmt.Sprintf("%d", UnsecuredServerPort)
	testPortNat, err := nat.NewPort("tcp", testPort)
	require.NoError(t, err)

	if webdav {
		// declare webdav port
		webdavPort = fmt.Sprintf("%d", UnsecuredWebdavPort)
		webdavPortNat, err = nat.NewPort("tcp", webdavPort)
		require.NoError(t, err)
	}

	// ContainerRequest for the test container
	ctx := context.Background()
	testContainer := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    dockerfilePath,
			Dockerfile: "Dockerfile",
			Repo:       "patrickhener/goshs",
			Tag:        "integration",
		},
		ConfigModifier: func(c *container.Config) {
			c.User = "1000:1000"
		},
		// mount a volume to the container; this will allow you to
		// use a behavior analogous to docker run -v "$PWD:/pwd"
		// and load files into the container from your local filesystem
		Mounts: testcontainers.ContainerMounts{
			testcontainers.ContainerMount{
				Source: &volumeSource{
					source: storageVolume,
				},
				Target: testcontainers.ContainerMountTarget("/pwd"),
			},
		},
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      configPath,
			Reader:            r,
			ContainerFilePath: "/configs/config.json",
			FileMode:          0o777,
		}, {
			HostFilePath:      caCertPath,
			Reader:            c,
			ContainerFilePath: "/certs/ca.crt",
			FileMode:          0o777,
		}, {
			HostFilePath:      serverP12Path,
			Reader:            p,
			ContainerFilePath: "/certs/goshs.p12",
			FileMode:          0o777,
		}, {
			HostFilePath:      serverCertPath,
			Reader:            crt,
			ContainerFilePath: "/certs/goshs.crt",
			FileMode:          0o777,
		}, {
			HostFilePath:      serverKeyPath,
			Reader:            k,
			ContainerFilePath: "/certs/goshs.key",
			FileMode:          0o777,
		}},
		Cmd: []string{"-C", "/configs/config.json"},
	}

	// Set ports and waitFor depending on webdav
	if webdav {
		testContainer.ExposedPorts = []string{testPort, webdavPort}
		testContainer.WaitingFor = wait.ForAll(wait.ForListeningPort(testPortNat), wait.ForListeningPort(webdavPortNat))
	} else {
		testContainer.ExposedPorts = []string{testPort}
		testContainer.WaitingFor = wait.ForListeningPort(testPortNat)
	}

	// start container
	goshsServer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testContainer,
		Started:          true,
	})
	require.NoError(t, err)

	// return either webdav or web port for testing
	if webdav {
		webdavReturnPort, err := goshsServer.MappedPort(ctx, webdavPortNat)
		require.NoError(t, err)
		return webdavReturnPort, goshsServer, nil
	} else {
		webReturnPort, err := goshsServer.MappedPort(ctx, testPortNat)
		require.NoError(t, err)
		return webReturnPort, goshsServer, nil
	}
}

func cleanupContainer(t *testing.T, container testcontainers.Container) {
	testcontainers.CleanupContainer(t, container)
}

func testConnection(t *testing.T, path string) {
	resp, err := http.Get(path)
	require.NoError(t, err)
	require.Equal(t, resp.Status, "200 OK")
}

func testView(t *testing.T, path string, negative bool) {
	resp, err := http.Get(path)
	require.NoError(t, err)
	if !negative {
		require.Equal(t, resp.Status, "200 OK")
		bodyBytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, string(bodyBytes), test_data)
	} else {
		require.Equal(t, resp.StatusCode, 403)
	}
}

func testDownload(t *testing.T, path string, negative bool) {
	resp, err := http.Get(path)
	require.NoError(t, err)
	if !negative {
		require.Contains(t, resp.Header.Get("Content-Disposition"), "attachment; filename=\"test_data.txt\"")

		respBytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, string(respBytes), test_data)
	} else {
		require.Equal(t, resp.StatusCode, 403)
	}
}

func testUploadPost(t *testing.T, basePath string, negative bool, upload_only bool) {
	// Read input file
	filePath := filepath.Join(os.Getenv("PWD"), "keepFiles", "upload_POST_test_data.txt")
	file, err := os.Open(filePath)
	require.NoError(t, err)

	// new multipart writer
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	// Create file
	part, err := writer.CreateFormFile("files[0]", "upload_POST_test_data.txt")
	require.NoError(t, err)

	// Copy content of file in part
	_, err = io.Copy(part, file)
	require.NoError(t, err)

	// Close writer
	err = writer.Close()
	require.NoError(t, err)

	// Construct request
	uploadUrl := fmt.Sprintf("%s/upload", basePath)
	req, err := http.NewRequest("POST", uploadUrl, &requestBody)
	require.NoError(t, err)
	req.Header.Add("Content-Type", writer.FormDataContentType())

	// Do request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)

	if !negative {
		require.Equal(t, resp.StatusCode, 200)

		if !upload_only {
			// Check if file was uploaded
			path := fmt.Sprintf("%s/upload_POST_test_data.txt", basePath)
			resp, err = http.Get(path)
			require.NoError(t, err)
			require.Equal(t, resp.StatusCode, 200)
			respBytes, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, string(respBytes), post_data)
		}
	} else {
		require.Equal(t, resp.StatusCode, 403)
	}
}

func testUploadPut(t *testing.T, basePath string, negative bool, upload_only bool) {
	// Read input file
	filePath := filepath.Join(os.Getenv("PWD"), "keepFiles", "upload_PUT_test_data.txt")
	file, err := os.Open(filePath)
	require.NoError(t, err)

	// Contruct request
	uploadUrl := fmt.Sprintf("%s/upload_PUT_test_data.txt", basePath)
	req, err := http.NewRequest("PUT", uploadUrl, file)
	require.NoError(t, err)

	// Do request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)

	if !negative {
		require.Equal(t, resp.StatusCode, 200)
		if !upload_only {
			// Check if file was uploaded
			path := fmt.Sprintf("%s/upload_PUT_test_data.txt", basePath)
			resp, err = http.Get(path)
			require.NoError(t, err)
			require.Equal(t, resp.StatusCode, 200)
			respBytes, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, string(respBytes), put_data)
		}
	} else {
		require.Equal(t, resp.StatusCode, 403)
	}

}

func testBulkDownload(t *testing.T, path string, negative bool) {
	resp, err := http.Get(path)
	require.NoError(t, err)
	if !negative {
		require.Contains(t, resp.Header.Get("Content-Disposition"), "goshs_download.zip")
		require.Contains(t, resp.Header.Get("Content-Transfer-Encoding"), "binary")
	} else {
		require.Equal(t, resp.StatusCode, 403)
	}
}

func testRemoval(t *testing.T, path string, negative bool) {
	resp, err := http.Get(path)
	require.NoError(t, err)
	if !negative {
		require.Equal(t, resp.StatusCode, 200)

		getPath := strings.Split(path, "?")[0]
		resp, err = http.Get(getPath)
		require.NoError(t, err)
		require.Equal(t, resp.StatusCode, 404)
	} else {
		require.Equal(t, resp.StatusCode, 403)
	}
}

func testUnauthConnection(t *testing.T, path string) {
	resp, err := http.Get(path)
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 401)
}

func testAuthConnection(t *testing.T, path string) {
	username := "admin"
	password := "admin"

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	client := &http.Client{}
	req, err := http.NewRequest("GET", path, nil)
	require.NoError(t, err)
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 200)
}

func testJsonOutput(t *testing.T, path string) {
	resp, err := http.Get(path)
	require.NoError(t, err)

	var items []item

	respBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	err = json.Unmarshal(respBytes, &items)
	require.NoError(t, err)

	require.Equal(t, items[0].Name, "ACL/")
}

func testUnauthCertConnection(t *testing.T, path string) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	req, err := http.NewRequest("GET", path, nil)
	require.NoError(t, err)

	_, err = client.Do(req)
	require.Error(t, err)
}

func testAuthCertConnection(t *testing.T, path string, certFile string, keyFile string) {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
			},
		},
	}

	req, err := http.NewRequest("GET", path, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 200)
}

func testSelfSigned(t *testing.T, url string) {
	clientInsecure := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	_, err := http.Get(url)
	require.Error(t, err)

	resp, err := clientInsecure.Get(url)
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 200)
}

func testNoClipboard(t *testing.T, path string) {
	resp, err := http.Get(path)
	require.NoError(t, err)
	respBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NotContains(t, string(respBytes), "<h1>Clipboard</h1>")
}

func testWebdavConnection(t *testing.T, path string) {
	c := gowebdav.NewClient(path, "", "")
	err := c.Connect()
	require.NoError(t, err)
}

func testWebdavListFiles(t *testing.T, path string) {
	c := gowebdav.NewClient(path, "", "")
	err := c.Connect()
	require.NoError(t, err)

	files, err := c.ReadDir("/")
	require.NoError(t, err)
	require.Equal(t, files[0].Name(), "ACL")
}

func testWebdavCreateDir(t *testing.T, path string) {
	c := gowebdav.NewClient(path, "", "")
	err := c.Connect()
	require.NoError(t, err)

	err = c.Mkdir("testfolder", 0777)
	require.NoError(t, err)

	info, err := c.Stat("testfolder")
	require.NoError(t, err)
	require.Equal(t, info.IsDir(), true)
}

func testWebdavDownload(t *testing.T, path string) {
	c := gowebdav.NewClient(path, "", "")
	err := c.Connect()
	require.NoError(t, err)

	bytes, err := c.Read("test_data.txt")
	require.NoError(t, err)
	require.Equal(t, string(bytes), test_data)
}

func testWebdavUpload(t *testing.T, path string) {
	c := gowebdav.NewClient(path, "", "")
	err := c.Connect()
	require.NoError(t, err)

	filePath := filepath.Join(os.Getenv("PWD"), "keepFiles", "upload_webdav_test_data.txt")
	file, err := os.Open(filePath)
	require.NoError(t, err)

	err = c.WriteStream("upload_webdav_test_data.txt", file, 0777)
	require.NoError(t, err)

	bytes, err := c.Read("upload_webdav_test_data.txt")
	require.NoError(t, err)
	require.Equal(t, string(bytes), "WEBDAV TEST CONFIRMED")
}

func testWebdavMoveCopy(t *testing.T, path string) {
	c := gowebdav.NewClient(path, "", "")
	err := c.Connect()
	require.NoError(t, err)

	err = c.Rename("upload_webdav_test_data.txt", "testfolder/upload_webdav_test_data.txt", false)
	require.NoError(t, err)

	err = c.Copy("testfolder/upload_webdav_test_data.txt", "upload_webdav_test_data.txt", false)
	require.NoError(t, err)
}

func testWebdavDelete(t *testing.T, path string) {
	c := gowebdav.NewClient(path, "", "")
	err := c.Connect()
	require.NoError(t, err)

	err = c.Remove("upload_webdav_test_data.txt")
	require.NoError(t, err)

	_, err = c.Read("upload_webdav_test_data.txt")
	require.Error(t, err)
}

func testWebdavUnauthConnection(t *testing.T, path string) {
	c := gowebdav.NewClient(path, "", "")
	err := c.Connect()
	require.Error(t, err)
}

func testWebdavAuthConnection(t *testing.T, path string) {
	c := gowebdav.NewClient(path, "admin", "admin")
	err := c.Connect()
	require.NoError(t, err)
}

func testACLs(t *testing.T, path string) {
	// ACL/testfile.txt should be blocked
	resp, err := http.Get(fmt.Sprintf("%s/ACL/testfile.txt", path))
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 404)
	// ACL/testfile2.txt should be allowed
	resp, err = http.Get(fmt.Sprintf("%s/ACL/testfile2.txt", path))
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 200)
	// ACL/testfolder should be blocked
	resp, err = http.Get(fmt.Sprintf("%s/ACL/testfolder", path))
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 404)
	// ACL/testfolder/testfile2.txt should be allowed
	resp, err = http.Get(fmt.Sprintf("%s/ACL/testfolder/testfile2.txt", path))
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 200)

	// ACLAuth/ should only be allowed only with auth
	resp, err = http.Get(fmt.Sprintf("%s/ACLAuth/", path))
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 401)

	username := "admin"
	password := "admin"

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/ACLAuth/", path), nil)
	require.NoError(t, err)
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 200)

	// ACLAuth/testfile.txt should be blocked
	req, err = http.NewRequest("GET", fmt.Sprintf("%s/ACLAuth/testfile.txt", path), nil)
	require.NoError(t, err)
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 404)
	// ACLAuth/testfile2.txt should be allowed
	req, err = http.NewRequest("GET", fmt.Sprintf("%s/ACLAuth/testfile2.txt", path), nil)
	require.NoError(t, err)
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 200)
	// ACLAuth/testfolder should be blocked
	req, err = http.NewRequest("GET", fmt.Sprintf("%s/ACLAuth/testfolder", path), nil)
	require.NoError(t, err)
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 404)
	// ACLAuth/testfolder/testfile2.txt should be allowed
	req, err = http.NewRequest("GET", fmt.Sprintf("%s/ACLAuth/testfolder/testfile2.txt", path), nil)
	require.NoError(t, err)
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, resp.StatusCode, 200)
}

func testLogOutput(t *testing.T, path string) {
	resp, err := http.Get(fmt.Sprintf("%s/goshs.log", path))
	require.NoError(t, err)
	respBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Greater(t, len(string(respBytes)), 0)
	require.Contains(t, string(respBytes), "Serving HTTP from /pwd")
}
