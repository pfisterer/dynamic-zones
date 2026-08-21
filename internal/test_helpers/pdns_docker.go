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
	"github.com/pfisterer/cloud-self-service-golib/logging"
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

// Diagnose reports what the container is actually doing. A readiness check
// that only says "did not become ready" leaves the reader guessing whether the
// port is wrong, the process crashed, or the image never started — and that
// guess costs a CI round trip each time.
func (p *PdnsContainerTestInstance) Diagnose(ctx context.Context) string {
	info, err := p.dockerController.GetContainerById(ctx, p.containerId)
	if err != nil {
		return fmt.Sprintf("container %s could not be inspected: %v", p.containerId[:12], err)
	}
	if info.State == nil {
		return fmt.Sprintf("container %s has no state", p.containerId[:12])
	}
	return fmt.Sprintf("container %s: status=%s running=%t exitCode=%d oomKilled=%t error=%q",
		p.containerId[:12], info.State.Status, info.State.Running, info.State.ExitCode,
		info.State.OOMKilled, info.State.Error)
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
	_, log := logging.Init(true)

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

	// os.CreateTemp makes the file 0600, owned by whoever runs the tests. PowerDNS
	// runs as an unprivileged user inside the container and then cannot read its
	// own configuration — it exits 99 before binding anything, which looks from
	// the outside like "the port is not published". Docker Desktop hides this by
	// remapping ownership on its file shares; a Linux runner does not.
	if err := os.Chmod(tempConfigFile.Name(), 0o644); err != nil {
		return nil, fmt.Errorf("test_helpers.StartPndsTestContainer: making the config readable in the container: %w", err)
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
		// 127.0.0.1, not localhost: on a GitHub runner that name resolves to ::1
		// first, while the container publishes its port on IPv4 only — every
		// connection then fails with "dial tcp [::1]:<port>: connection refused".
		// Docker Desktop binds both, which is why this only ever broke in CI.
		baseUrl: fmt.Sprintf("http://127.0.0.1:%d", externalApiPort),
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
