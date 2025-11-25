package zones

import (
	"os"
	"testing"

	"github.com/farberg/dynamic-zones/internal/auth"
	"github.com/farberg/dynamic-zones/internal/config"
	"go.uber.org/zap"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupLoggerForTest(t *testing.T) *zap.Logger {
	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	logger, err := config.Build()
	require.NoError(t, err)
	return logger
}

func createTempScriptFile(t *testing.T, content string) string {
	tmpDir := t.TempDir()
	tmpFile, err := os.CreateTemp(tmpDir, "test_script.js")
	require.NoError(t, err)

	_, err = tmpFile.WriteString(content)
	require.NoError(t, err)

	err = tmpFile.Close()
	require.NoError(t, err)

	return tmpFile.Name()
}

func TestZoneProviderJavaScript_GetUserZones(t *testing.T) {
	logger := setupLoggerForTest(t)

	scriptContent := `
	function getUserZones(user) {
		console.log("getUserZones called for user: " + user.preferred_username);
		if (user.preferred_username === "testuser") {
			return [{zone: "testzone", ttl: 300}];
		}
		return [];
	}

	function isAllowedZone(user, zone) {
		console.log("isAllowedZone called for user: " + user.preferred_username + " and zone: " + zone);
		return [true, {zone: zone, ttl: 300}, null];
	}
	`
	scriptPath := createTempScriptFile(t, scriptContent)

	cfg := &config.UserZoneProviderConfig{
		ScriptPath: scriptPath,
	}

	provider, err := NewZoneProviderJavaScript(cfg, logger)
	require.NoError(t, err)

	user := &auth.UserClaims{
		PreferredUsername: "testuser",
	}

	zones, err := provider.GetUserZones(user)
	assert.NoError(t, err)
	assert.Len(t, zones, 1)
	assert.Equal(t, "", zones[0].Zone)

	user = &auth.UserClaims{
		PreferredUsername: "anotheruser",
	}

	zones, err = provider.GetUserZones(user)
	assert.NoError(t, err)
	assert.Len(t, zones, 0)
}
