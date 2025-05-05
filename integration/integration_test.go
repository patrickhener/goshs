package integration

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	dockerfilePath = fmt.Sprintf("%s/../", os.Getenv("PWD"))
	storageVolume  = fmt.Sprintf("%s/files/", os.Getenv("PWD"))
)

type volumeSource struct {
	source    string
	mountType uint8
}

func (v *volumeSource) Source() string {
	return v.source
}

func (v *volumeSource) Type() testcontainers.MountType {
	return testcontainers.MountType(v.mountType)
}

const (
	// note that per docs, each testcontainer uses a random port to avoid collisions
	// we fetch that port at test runtime
	UnsecuredServerPort = 8001
)

func spawnTestContainer(t *testing.T, config string) (nat.Port, testcontainers.Container, error) {
	// fetch the server config
	configPath := fmt.Sprintf(config, os.Getenv("PWD"))

	r, err := os.Open(configPath)
	require.NoError(t, err)

	// declare the port for this test
	testPort := fmt.Sprintf("%d", UnsecuredServerPort)
	testPortNat, err := nat.NewPort("tcp", testPort)
	require.NoError(t, err)

	ctx := context.Background()
	testContainer := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    dockerfilePath,
			Dockerfile: "Dockerfile",
		},
		ExposedPorts: []string{testPort},
		// mount a volume to the container; this will allow you to
		// use a behavior analagous to docker run -v "$PWD:/pwd"
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
			FileMode:          0o700,
		}},
		WaitingFor: wait.ForListeningPort(testPortNat),
		Cmd:        []string{"-C", "/configs/config.json"},
	}

	goshsServer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testContainer,
		Started:          true,
	})
	require.NoError(t, err)

	port, err := goshsServer.MappedPort(ctx, testPortNat)
	require.NoError(t, err)

	return port, goshsServer, nil
}

func cleanupContainer(t *testing.T, container testcontainers.Container) {
	testcontainers.CleanupContainer(t, container)
}

// TestUnsecureServer tests all functionality of the unsecured server
func TestUnsecureServer(t *testing.T) {
	// spawn a test container
	port, goshsServer, err := spawnTestContainer(t, "%s/configs/unsecured.json")

	// Test connection
	path := fmt.Sprintf("http://localhost:%d/", port.Int())
	resp, err := http.Get(path)
	require.NoError(t, err)

	require.Equal(t, resp.Status, "200 OK")

	// Test View
	path = fmt.Sprintf("http://localhost:%d/test_data.txt", port.Int())
	resp, err = http.Get(path)
	require.NoError(t, err)

	require.Equal(t, resp.Status, "200 OK")
	require.Equal(t, resp.Header.Get("Content-Type"), "text/plain")

	// Test Upload via HTTP PUT, POST

	// Test Bulk Download

	// Test File Removal

	// Test Clipboard add, download, delete

	// Cleanup Container
	cleanupContainer(t, goshsServer)
}

// TestBasicAuthServer test that basic auth is working
func TestBasicAuthServer(t *testing.T) {
	// stub; fetch basic_auth, mirror pattern above
	// configPath := fmt.Sprintf("%s/configs/basic_auth.json", os.Getenv("PWD"))
}
