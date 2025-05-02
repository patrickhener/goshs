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
	goshsContainer = "patrickhener/goshs:latest"
	storageVolume  = fmt.Sprintf("%s/docker-storage/", os.Getenv("PWD"))
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

// TestUnsecureServer
func TestUnsecureServer(t *testing.T) {
	// fetch the unsecured server config
	configPath := fmt.Sprintf("%s/configs/unsecured.json", os.Getenv("PWD"))

	r, err := os.Open(configPath)
	require.NoError(t, err)

	// declare the port for this test
	testPort := fmt.Sprintf("%d", UnsecuredServerPort)
	testPortNat, err := nat.NewPort("tcp", testPort)
	require.NoError(t, err)

	ctx := context.Background()
	testContainer := testcontainers.ContainerRequest{
		Image:        goshsContainer,
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

	/*
		Now we can do integration tests: http test this container
		write files/read them
		verify secure servers are working properly with basic auth, signed certs, unsigned certs, etc
	*/
	path := fmt.Sprintf("http://localhost:%d/", port.Int())
	resp, err := http.Get(path)
	require.NoError(t, err)

	require.Equal(t, resp.Status, "200 OK")

	// if you fetched a file, you can verify its contents by reading the response;
	// or by reading the object retrieved from the filesystem

	testcontainers.CleanupContainer(t, goshsServer)
	require.NoError(t, err)
}

/*
	This is a stub; we can match the pattern above and use
*/
// TestBasicAuthServer test that basic auth is working
func TestBasicAuthServer(t *testing.T) {
	// stub; fetch basic_auth, mirror pattern above
	// configPath := fmt.Sprintf("%s/configs/basic_auth.json", os.Getenv("PWD"))
}
