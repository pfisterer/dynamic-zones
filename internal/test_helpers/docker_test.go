package test_helpers

import (
	"context"
	"testing"
	"time"

	"github.com/farberg/dynamic-zones/internal/helper"
)

const (
	testImageName     = "powerdns/pdns-auth-master:latest"
	containerLifetime = 3 * time.Second
)

func TestContainerLifecycle(t *testing.T) {
	_, log := helper.InitLogger(true)
	ctx := context.Background()
	dc, err := NewDockerController(log)

	testContainerName := testContainerNamePrefix + "-" + helper.RandomString(10)

	if err != nil {
		t.Fatalf("test_helpers.TestContainerLifecycleError: creating Docker controller: %v", err)
	}

	// Test StartContainer
	containerID, err := dc.StartContainer(ctx, testContainerName, testImageName, containerLabels, nil)
	if err != nil {
		t.Fatalf("test_helpers.StartContainer failed: %v", err)
	}
	t.Logf("test_helpers.TestContainerLifecycle: Container '%s' started with ID: %s, waiting %v before stopping it", testContainerName, containerID, containerLifetime)

	// Give the container a moment to start
	time.Sleep(containerLifetime)

	// Test StopAndDeleteContainer (forced)
	err = dc.StopAndDeleteContainer(ctx, containerID)
	if err != nil {
		t.Fatalf("test_helpers.TestContainerLifecycle: StopAndDeleteContainer failed: %v", err)
	}
	t.Logf("test_helpers.TestContainerLifecycle: Container '%s' stopped and deleted.", containerID)

	// Verify the container is gone
	containerIDAfterDeletion, err := dc.GetContainerIDByName(ctx, testContainerName)
	if err != nil {
		t.Fatalf("test_helpers.TestContainerLifecycle: Error checking for container after deletion: %v", err)
	}
	if containerIDAfterDeletion != "" {
		t.Errorf("test_helpers.TestContainerLifecycle: Container '%s' still exists after deletion (ID: %s)", testContainerName, containerIDAfterDeletion)
	}
}
