package test_helpers

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"slices"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"go.uber.org/zap"
)

// DockerController provides methods to manage Docker containers.
type DockerController struct {
	client *client.Client
	log    *zap.SugaredLogger
}

// NewDockerController creates a new DockerController instance.
func NewDockerController(log *zap.SugaredLogger) (*DockerController, error) {
	// Create standard Docker client, test if accessible
	context := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	_, err = cli.Ping(context)

	if err != nil {
		// Fallback to macOS specific path if needed
		if runtime.GOOS == "darwin" {
			defaultDockerHost := fmt.Sprintf("unix://%s/.docker/run/docker.sock", os.Getenv("HOME"))
			cli, err = client.NewClientWithOpts(client.WithHost(defaultDockerHost), client.WithAPIVersionNegotiation())
			if err != nil {
				return nil, fmt.Errorf("test_helpers.NewDockerController: failed to create Docker client: %w", err)
			}
		} else {
			return nil, fmt.Errorf("test_helpers.NewDockerController: failed to create Docker client: %w", err)
		}
	}

	_, err = cli.Ping(context)
	if err != nil {
		return nil, fmt.Errorf("test_helpers.NewDockerController: failed to ping Docker daemon: %w", err)
	}

	return &DockerController{client: cli, log: log}, nil
}

// StartContainer starts a new container with the given name, image, and tag (including hash).
func (dc *DockerController) StartContainer(ctx context.Context, containerName, imageNameWithTag string, containerLabels map[string]string, hostConfig *container.HostConfig) (string, error) {
	containerConfig := &container.Config{
		Image:  imageNameWithTag,
		Labels: containerLabels,
	}

	resp, err := dc.client.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, containerName)
	if err != nil {
		return "", fmt.Errorf("test_helpers.StartContainer: failed to create container '%s' from image '%s': %w", containerName, imageNameWithTag, err)
	}

	if err := dc.client.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return "", fmt.Errorf("test_helpers.StartContainer: failed to start container '%s' (%s): %w", containerName, resp.ID, err)
	}

	return resp.ID, nil
}

func (dc *DockerController) ContainerImageExists(ctx context.Context, imageNameWithTag string) error {
	images, err := dc.client.ImageList(ctx, image.ListOptions{Filters: filters.NewArgs(filters.Arg("reference", imageNameWithTag))})
	if err != nil {
		return fmt.Errorf("test_helpers.ContainerImageExists: failed to list images: %w", err)
	}

	if len(images) == 0 {
		return fmt.Errorf("test_helpers.ContainerImageExists: image '%s' does not exist", imageNameWithTag)
	}

	dc.log.Debugf("test_helpers.ContainerImageExists: Image '%s' exists with ID %s", imageNameWithTag, images[0].ID)
	return nil
}

// UpdateContainerImage pulls the latest image (or the specified tag/hash) for a container.
func (dc *DockerController) UpdateContainerImage(ctx context.Context, imageNameWithTag string) error {
	out, err := dc.client.ImagePull(ctx, imageNameWithTag, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("test_helpers.UpdateContainerImage: failed to pull image '%s': %w", imageNameWithTag, err)
	}
	// Read the output from 'out' for pull progress to make sure, we wait until the image is fully pulled
	defer out.Close()

	_, err = io.ReadAll(out)
	if err != nil {
		return fmt.Errorf("test_helpers.UpdateContainerImage: failed to read image pull output: %w", err)
	}
	dc.log.Debugf("test_helpers.UpdateContainerImage: Successfully pulled updated image '%s'", imageNameWithTag)

	return nil
}

// DeleteOldImages removes images that are not currently in use by any containers.
func (dc *DockerController) DeleteOldImages(ctx context.Context) error {
	containers, err := dc.client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return fmt.Errorf("test_helpers.DeleteOldImages: failed to list containers: %w", err)
	}

	usedImages := make(map[string]bool)
	for _, c := range containers {
		usedImages[c.ImageID] = true
	}

	images, err := dc.client.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return fmt.Errorf("test_helpers.ImageList: failed to list images: %w", err)
	}

	for _, img := range images {
		if len(img.RepoTags) == 0 { // Skip images with no tags (often intermediate layers)
			continue
		}
		isUsed := false
		if usedImages[img.ID] {
			isUsed = true
		}
		if !isUsed {
			for _, tag := range img.RepoTags {
				dc.log.Infof("test_helpers.ImageList: Removing unused image: %s (%s)", tag, img.ID)
				_, err := dc.client.ImageRemove(ctx, img.ID, image.RemoveOptions{Force: false, PruneChildren: false})
				if err != nil && !strings.Contains(err.Error(), "No such image") {
					dc.log.Warnf("test_helpers.ImageList: Error removing image %s (%s): %v", tag, img.ID, err)
				}
			}
		}
	}
	return nil
}

// StopAndDeleteContainer stops and then removes a container by its name.
func (dc *DockerController) StopAndDeleteContainer(ctx context.Context, containerID string) error {
	timeout := 5 // seconds to wait before forcefully stopping

	err := dc.client.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout})
	if err != nil && !strings.Contains(err.Error(), "No such container") {
		return fmt.Errorf("test_helpers.StopAndDeleteContainer: failed to stop container '%s' (%s): %w", containerID, containerID, err)
	}

	removeOptions := container.RemoveOptions{
		Force: true, // Force the removal if it's still running (though we tried to stop it)
	}
	err = dc.client.ContainerRemove(ctx, containerID, removeOptions)
	if err != nil && !strings.Contains(err.Error(), "No such container") {
		return fmt.Errorf("test_helpers.StopAndDeleteContainer: failed to remove container '%s' (%s): %w", containerID, containerID, err)
	}

	dc.log.Debugf("test_helpers.StopAndDeleteContainer: Container '%s' (%s) stopped and deleted successfully.\n", containerID, containerID)
	return nil
}

// getContainerIDByName retrieves the ID of a container given its name.
func (dc *DockerController) GetContainerIDByName(ctx context.Context, containerName string) (string, error) {
	containers, err := dc.client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return "", fmt.Errorf("test_helpers.GetContainerIDByName: failed to list containers: %w", err)
	}
	for _, c := range containers {
		if slices.Contains(c.Names, "/"+containerName) { // Docker prepends a '/' to container names
			return c.ID, nil
		}
	}
	return "", nil
}

func (dc *DockerController) GetContainerById(ctx context.Context, containerID string) (*container.InspectResponse, error) {
	container, err := dc.client.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("test_helpers.GetContainerById: failed to inspect container '%s': %w", containerID, err)
	}
	return &container, nil
}

func (dc *DockerController) GetContainersWithLabels(ctx context.Context, labels map[string]string) ([]container.Summary, error) {
	containers, err := dc.client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("test_helpers.GetContainersWithLabels: failed to list containers: %w", err)
	}

	var filteredContainers []container.Summary
	for _, c := range containers {
		matches := true
		for key, value := range labels {
			if c.Labels[key] != value {
				matches = false
				break
			}
		}
		if matches {
			filteredContainers = append(filteredContainers, c)
		}
	}

	return filteredContainers, nil
}
