package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
	"github.com/studio-b12/gowebdav"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func spawnTestContainer(t *testing.T, config string, webdav bool) (nat.Port, testcontainers.Container, error) {
	// Make sure the host-side coverage drop dir exists and is writable
	// by the container's non-root uid (1000). 0o777 is fine for an
	// ephemeral test artifact directory.
	require.NoError(t, os.MkdirAll(coverageDir, 0o777))
	require.NoError(t, os.Chmod(coverageDir, 0o777))

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
		HostConfigModifier: func(hc *container.HostConfig) {
			// Bind-mount host coverage dir so the -cover instrumented
			// binary's emitted covdata survives container removal.
			hc.Mounts = append(hc.Mounts, mount.Mount{
				Type:   mount.TypeBind,
				Source: coverageDir,
				Target: "/covdata",
			})
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

func cleanupContainer(t *testing.T, c testcontainers.Container) {
	// Send SIGTERM and wait for graceful shutdown so the -cover
	// instrumented binary flushes its covdata files into the bind-mounted
	// /covdata before the container is removed. testcontainers.CleanupContainer
	// otherwise terminates with a short timeout that may not give Go time
	// to write the profile.
	timeout := 5 * time.Second
	if err := c.Stop(context.Background(), &timeout); err != nil {
		t.Logf("graceful stop failed (coverage may be incomplete): %v", err)
	}
	testcontainers.CleanupContainer(t, c)
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

	var names []string
	for _, f := range files {
		names = append(names, f.Name())
	}
	require.Contains(t, names, "test_data.txt")
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

	filePath := fmt.Sprintf("%s/keepFiles/upload_webdav_test_data.txt", os.Getenv("PWD"))
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
