package test_helpers

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/farberg/dynamic-zones/internal/helper"
)

const (
	imageName               = "powerdns/pdns-auth-master:latest"
	testContainerNamePrefix = "pdns-auth-test"
	configFileContent       = `# PowerDNS configuration file
local-address=0.0.0.0
local-port=53
write-pid=no
zone-cache-refresh-interval=0
# logLevel: 0 = emergency, 1 = alert, 2 = critical, 3 = error, 4 = warning, 5 = notice, 6 = info, 7 = debug
loglevel=7
# SQLite3
launch=gsqlite3
gsqlite3-database=/var/lib/powerdns/pdns.sqlite3
# API
webserver-address=0.0.0.0
webserver-port=8081
webserver-allow-from=0.0.0.0/0
webserver-loglevel=normal # none, normal, detailed
api=yes
api-key=my-default-api-key
dnsupdate=yes
allow-dnsupdate-from=
dnsupdate-require-tsig=true
`
)

var containerLabels = map[string]string{
	"de.farberg.dynamic-zones-dns-api": "pdns-auth-test",
}

type PdnsContainerTestInstance struct {
	containerId      string
	dockerController *DockerController
	cleanupHooks     []func() error
	apiPort          int
	externalDnsPort  uint16
	baseUrl          string
}

func (instance *PdnsContainerTestInstance) GetApiKey() string {
	return "my-default-api-key"
}

func (instance *PdnsContainerTestInstance) GetBaseUrl() string {
	return instance.baseUrl
}

func (instance *PdnsContainerTestInstance) GetExternalDnsPort() uint16 {
	return instance.externalDnsPort
}

func StartPndsTestContainer(ctx context.Context) (instance *PdnsContainerTestInstance, err error) {
	testContainerName := testContainerNamePrefix + "-" + helper.RandomString(10)

	// Create a new Docker controller
	_, log := helper.InitLogger(true)

	dc, err := NewDockerController(log)
	if err != nil {
		return nil, err
	}

	// Pull the image
	err = dc.UpdateContainerImage(ctx, imageName)
	if err != nil {
		return nil, err
	}

	// Write configuration file to a temporary location

	// Create a temporary file
	tempConfigFile, err := os.CreateTemp("", "pdns-test-*.conf")
	if err != nil {
		return nil, err
	}

	// Write the configuration content to the temporary file
	_, err = tempConfigFile.WriteString(configFileContent)
	if err != nil {
		return nil, err
	}

	// Convert to an absolute path
	absolutePathToConfig, err := filepath.Abs(tempConfigFile.Name())
	if err != nil {
		return nil, err
	}

	// Configure the container
	externalApiPort := rand.Intn(10000) + 30000
	externalDnsPort := externalApiPort + 1

	// Create host configuration
	hostConfig := &container.HostConfig{
		Binds: []string{
			fmt.Sprintf("%s:/etc/powerdns/pdns.conf:ro", absolutePathToConfig),
		},
		PortBindings: nat.PortMap{
			"8081/tcp": []nat.PortBinding{
				{
					HostIP:   "0.0.0.0",
					HostPort: fmt.Sprintf("%d", externalApiPort),
				},
			},
			"53/tcp": []nat.PortBinding{
				{
					HostIP:   "0.0.0.0",
					HostPort: fmt.Sprintf("%d", externalDnsPort),
				},
			},
			"53/udp": []nat.PortBinding{
				{
					HostIP:   "0.0.0.0",
					HostPort: fmt.Sprintf("%d", externalDnsPort),
				},
			},
		},
	}

	// Start the container
	containerID, err := dc.StartContainer(ctx, testContainerName, imageName, containerLabels, hostConfig)
	if err != nil {
		return nil, err
	}

	return &PdnsContainerTestInstance{
		containerId:      containerID,
		dockerController: dc,
		apiPort:          externalApiPort,
		externalDnsPort:  uint16(externalDnsPort),
		baseUrl:          fmt.Sprintf("http://localhost:%d", externalApiPort),
		cleanupHooks: []func() error{
			func() error {
				// Remove the temporary configuration file
				if err := os.Remove(tempConfigFile.Name()); err != nil {
					return fmt.Errorf("test_helpers.StartPndsTestContainer: failed to remove temporary config file: %w", err)
				}
				return nil
			},
		},
	}, nil
}

func (instance *PdnsContainerTestInstance) Cleanup() error {
	// stop and delete the container
	ctx := context.Background()

	summaries, err := instance.dockerController.GetContainersWithLabels(ctx, containerLabels)
	if err != nil {
		return fmt.Errorf("test_helpers.Cleanup: failed to get container IDs with labels: %w", err)
	}

	if len(summaries) == 0 {
		return fmt.Errorf("test_helpers.Cleanup: no containers found with labels: %v", containerLabels)
	}

	for _, summary := range summaries {
		if err := instance.dockerController.StopAndDeleteContainer(ctx, summary.ID); err != nil {
			return fmt.Errorf("test_helpers.Cleanup: failed to stop and delete container %s (Names: %+v): %w", summary.ID, summary.Names, err)
		}
	}

	// Execute all cleanup hooks
	for _, hook := range instance.cleanupHooks {
		if err := hook(); err != nil {
			return fmt.Errorf("test_helpers.Cleanup: failed to execute cleanup hook: %w", err)
		}
	}

	// Clear the cleanup hooks
	instance.cleanupHooks = []func() error{}

	return nil
}
