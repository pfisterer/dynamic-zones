package zones

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/dop251/goja"
	"github.com/farberg/dynamic-zones/internal/auth"
	"github.com/farberg/dynamic-zones/internal/config"
	"go.uber.org/zap"
)

// jsReturnType is a helper struct to parse the return values
type jsReturnType struct {
	IsAllowed    bool         `json:"isAllowed"`
	ZoneResponse ZoneResponse `json:"zoneResponse"`
	ErrorMessage string       `json:"errorMessage"`
}

// ZoneProviderJavaScript implements ZoneProvider by executing a user-provided JavaScript script.
type ZoneProviderJavaScript struct {
	vm                *goja.Runtime
	getUserZonesFunc  goja.Callable
	isAllowedZoneFunc goja.Callable
	mutex             sync.Mutex
	logger            *zap.Logger
	log               *zap.SugaredLogger
}

func NewZoneProviderJavaScript(c *config.UserZoneProviderConfig, logger *zap.Logger) (*ZoneProviderJavaScript, error) {
	log := logger.Sugar()
	vm := goja.New()

	// Inject Console/Logging
	if err := setupJsConsoleLogging(vm, log); err != nil {
		return nil, fmt.Errorf("failed to set up console logging: %w", err)
	}

	// Inject Go helper functions into the VM global scope
	err := vm.Set("makeDnsCompliantGo", makeDnsCompliant)
	if err != nil {
		return nil, fmt.Errorf("failed to expose Go function: %w", err)
	}

	// Read the script file
	scriptBytes, err := os.ReadFile(c.ScriptPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read script file: %w", err)
	}

	// Run the script
	_, err = vm.RunString(string(scriptBytes))
	if err != nil {
		return nil, fmt.Errorf("error running script: %w", err)
	}

	// Get the Go function for getUserZones
	getUserZonesVal := vm.Get("getUserZones")
	getUserZonesFunc, ok := goja.AssertFunction(getUserZonesVal)
	if !ok {
		return nil, fmt.Errorf("'getUserZones' is not a function or missing")
	}

	// Get the isAllowedZone function
	isAllowedZoneVal := vm.Get("isAllowedZone")
	isAllowedZoneFunc, ok := goja.AssertFunction(isAllowedZoneVal)
	if !ok {
		return nil, fmt.Errorf("'isAllowedZone' is not a function or missing")
	}

	logger.Info("zones.NewZoneProviderJavaScript: initialized ZoneProviderJavaScript",
		zap.String("script_path", c.ScriptPath))

	return &ZoneProviderJavaScript{
		vm:                vm,
		getUserZonesFunc:  getUserZonesFunc,
		isAllowedZoneFunc: isAllowedZoneFunc,
		logger:            logger,
		log:               log,
	}, nil
}

func (m *ZoneProviderJavaScript) GetUserZones(ctx context.Context, user *auth.UserClaims) ([]ZoneResponse, error) {
	// Marshal user to goja Value
	jsUser, err := m.marshalToJS(user)
	if err != nil {
		return nil, err
	}

	// Lock the VM for thread safety
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Invoke the JavaScript function to get user zones
	jsResult, err := m.getUserZonesFunc(goja.Undefined(), jsUser)
	if err != nil {
		return nil, fmt.Errorf("error executing JavaScript getUserZones: %w", err)
	}

	// Convert the result back
	genericGoValue := jsResult.Export()
	jsonBytes, err := json.Marshal(genericGoValue)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal generic Go value to JSON: %w", err)
	}

	// Unmarshal JSON into []ZoneResponse
	var result []ZoneResponse
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON into []ZoneResponse: %w", err)
	}

	m.log.Debugf("zones.GetUserZones: returning zones for user %s: %v", user.PreferredUsername, result)
	return result, nil
}

func (m *ZoneProviderJavaScript) IsAllowedZone(ctx context.Context, user *auth.UserClaims, zone string) (bool, ZoneResponse, error) {
	jsUser, err := m.marshalToJS(user)
	if err != nil {
		return false, ZoneResponse{}, err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	jsResult, err := m.isAllowedZoneFunc(goja.Undefined(), jsUser, m.vm.ToValue(zone))
	if err != nil {
		return false, ZoneResponse{}, fmt.Errorf("error executing JavaScript isAllowedZone: %w", err)
	}

	genericGoValue := jsResult.Export()
	jsonBytes, err := json.Marshal(genericGoValue)
	if err != nil {
		return false, ZoneResponse{}, fmt.Errorf("failed to marshal generic Go value to JSON: %w", err)
	}

	// 3. Demarshall den JSON-Byte-Slice direkt in die Zielstruktur IsAllowedZoneResult
	var result jsReturnType
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return false, ZoneResponse{}, fmt.Errorf("failed to unmarshal JSON into IsAllowedZoneResult: %w", err)
	}

	// Extrahieren des Skriptfehlers
	var scriptErr error
	if result.ErrorMessage != "" {
		scriptErr = fmt.Errorf("script error: %s", result.ErrorMessage)
	}

	// Rückgabe des Booleans und der ZoneResponse
	return result.IsAllowed, result.ZoneResponse, scriptErr
}

// setupJsConsoleLogging creates a 'console' object in the VM and binds its methods
// (log, warn, error) to the provided zap.SugaredLogger.
func setupJsConsoleLogging(vm *goja.Runtime, log *zap.SugaredLogger) error {
	// This is the core Go function that handles the JS function call
	jsLogFn := func(level string) func(goja.FunctionCall) goja.Value {
		return func(c goja.FunctionCall) goja.Value {
			// Collect arguments as a slice of interfaces
			var output []interface{}
			for _, arg := range c.Arguments {
				output = append(output, arg.Export())
			}

			// Format all arguments into a single string message (like standard console.log)
			// Note: Using fmt.Sprint is better than fmt.Sprintf for variadic types when no format string is needed.
			msg := fmt.Sprint(output...)

			switch level {
			case "warn":
				log.Warnf("JS_CONSOLE_WARN: %s", msg)
			case "error":
				log.Errorf("JS_CONSOLE_ERROR: %s", msg)
			case "debug":
				log.Debugf("JS_CONSOLE_DEBUG: %s", msg)
			default:
				log.Infof("JS_CONSOLE_LOG: %s", msg)
			}

			return goja.Undefined()
		}
	}

	// Create a JavaScript object named 'console'
	console := vm.NewObject()

	// Bind the logging methods
	if err := console.Set("log", jsLogFn("log")); err != nil {
		return err
	}
	if err := console.Set("info", jsLogFn("info")); err != nil {
		return err
	}
	if err := console.Set("warn", jsLogFn("warn")); err != nil {
		return err
	}
	if err := console.Set("error", jsLogFn("error")); err != nil {
		return err
	}
	if err := console.Set("debug", jsLogFn("debug")); err != nil {
		return err
	}

	// Set the 'console' object in the global scope
	return vm.Set("console", console)
}

// Helper to convert Go struct to a goja Value
func (m *ZoneProviderJavaScript) marshalToJS(data interface{}) (goja.Value, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Go object: %w", err)
	}

	var raw interface{}
	if err := json.Unmarshal(bytes, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON for goja: %w", err)
	}

	return m.vm.ToValue(raw), nil
}
