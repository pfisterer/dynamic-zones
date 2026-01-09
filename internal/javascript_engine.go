package app

import (
	"fmt"

	"github.com/dop251/goja"
	"go.uber.org/zap"
)

// JavaScriptEngine manages the JS execution environment and data access
type JavaScriptEngine struct {
	vm     *goja.Runtime
	logger *zap.SugaredLogger
	app    *AppData
}

// NewJavaScriptEngine initializes the JS VM and binds Go methods
func NewJavaScriptEngine(app *AppData) (*JavaScriptEngine, error) {
	// Create Goja VM
	p := &JavaScriptEngine{
		vm:     goja.New(),
		logger: app.Log,
		app:    app,
	}

	// Setup Environment
	if err := p.setupConsole(); err != nil {
		return nil, fmt.Errorf("console setup failed: %w", err)
	}

	// Expose AppData methods to JS
	p.exposePolicyMethods()

	return p, nil
}

// Run executes the script and invokes the entrypoint function
func (p *JavaScriptEngine) Run(script []byte) error {

	// Run the script
	if _, err := p.vm.RunString(string(script)); err != nil {
		return fmt.Errorf("js execution error: %w", err)
	}

	return nil
}

// exposePolicyMethods maps the AppData methods to JS-friendly names
func (p *JavaScriptEngine) exposePolicyMethods() {
	// We wrap these in an object for better JS namespacing: e.g., policy.getAllUserRules()
	policyObj := p.vm.NewObject()

	// Mapping Go methods to JS
	// Goja handles the conversion of Go types to JS types automatically for basic types/structs
	policyObj.Set("getAllUserRules", p.getAllUserRulesWrapper())
	policyObj.Set("getUserZones", p.getUserZonesWrapper())
	policyObj.Set("isZoneAllowed", p.isZoneAllowedWrapper())
	policyObj.Set("createRule", p.createRuleWrapper())
	policyObj.Set("updateRule", p.updateRuleWrapper())
	policyObj.Set("deleteRule", p.deleteRuleWrapper())
	policyObj.Set("getAll", p.getAllWrapper())

	p.vm.Set("policy", policyObj)

}

// createRuleWrapper wraps PolicyCreateRule to handle JS object conversion
func (p *JavaScriptEngine) createRuleWrapper() func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return p.vm.NewGoError(fmt.Errorf("createRule requires an object argument"))
		}

		obj := call.Arguments[0].ToObject(p.vm)
		if obj == nil {
			return p.vm.NewGoError(fmt.Errorf("createRule argument must be an object"))
		}

		// Extract fields from the JavaScript object
		req := PolicyRuleRequest{
			ZonePattern:      toString(obj.Get("zone_pattern")),
			ZoneSoa:          toString(obj.Get("zone_soa")),
			TargetUserFilter: toString(obj.Get("target_user_filter")),
			Description:      toString(obj.Get("description")),
		}

		result, err := p.app.PolicyCreateRule(req)
		if err != nil {
			return p.vm.NewGoError(err)
		}

		return p.policyRuleToJSObject(result)
	}
}

// updateRuleWrapper wraps PolicyUpdateRule to handle JS object conversion
func (p *JavaScriptEngine) updateRuleWrapper() func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			return p.vm.NewGoError(fmt.Errorf("updateRule requires id and object arguments"))
		}

		id := call.Arguments[0].ToInteger()
		obj := call.Arguments[1].ToObject(p.vm)
		if obj == nil {
			return p.vm.NewGoError(fmt.Errorf("updateRule second argument must be an object"))
		}

		// Extract fields from the JavaScript object
		req := PolicyRuleRequest{
			ZonePattern:      toString(obj.Get("zone_pattern")),
			ZoneSoa:          toString(obj.Get("zone_soa")),
			TargetUserFilter: toString(obj.Get("target_user_filter")),
			Description:      toString(obj.Get("description")),
		}

		result, err := p.app.PolicyUpdateRule(id, req)
		if err != nil {
			return p.vm.NewGoError(err)
		}

		return p.policyRuleToJSObject(result)
	}
}

// deleteRuleWrapper wraps PolicyDeleteRule to handle JS conversion
func (p *JavaScriptEngine) deleteRuleWrapper() func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return p.vm.NewGoError(fmt.Errorf("deleteRule requires an id argument"))
		}

		id := call.Arguments[0].ToInteger()

		err := p.app.PolicyDeleteRule(id)
		if err != nil {
			return p.vm.NewGoError(err)
		}

		return goja.Undefined()
	}
}

// getAllUserRulesWrapper wraps PolicyGetAllUserRules to handle JS conversion
func (p *JavaScriptEngine) getAllUserRulesWrapper() func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return p.vm.NewGoError(fmt.Errorf("getAllUserRules requires a user object argument"))
		}

		userObj := call.Arguments[0].ToObject(p.vm)
		if userObj == nil {
			return p.vm.NewGoError(fmt.Errorf("getAllUserRules argument must be an object"))
		}

		// Convert JS object to UserClaims
		user := p.jsObjectToUserClaims(userObj)

		result, err := p.app.PolicyGetAllUserRules(user)
		if err != nil {
			return p.vm.NewGoError(err)
		}

		return p.policyRulesResponseToJSObject(result)
	}
}

// getUserZonesWrapper wraps PolicyGetUserZones to handle JS conversion
func (p *JavaScriptEngine) getUserZonesWrapper() func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return p.vm.NewGoError(fmt.Errorf("getUserZones requires a user object argument"))
		}

		userObj := call.Arguments[0].ToObject(p.vm)
		if userObj == nil {
			return p.vm.NewGoError(fmt.Errorf("getUserZones argument must be an object"))
		}

		// Convert JS object to UserClaims
		user := p.jsObjectToUserClaims(userObj)

		zones, err := p.app.PolicyGetUserZones(user)
		if err != nil {
			return p.vm.NewGoError(err)
		}

		return p.vm.ToValue(zones)
	}
}

// isZoneAllowedWrapper wraps PolicyIsZoneAllowedForUser to handle JS conversion
func (p *JavaScriptEngine) isZoneAllowedWrapper() func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			return p.vm.NewGoError(fmt.Errorf("isZoneAllowed requires zone and user arguments"))
		}

		zone := call.Arguments[0].String()
		userObj := call.Arguments[1].ToObject(p.vm)
		if userObj == nil {
			return p.vm.NewGoError(fmt.Errorf("isZoneAllowed second argument must be an object"))
		}

		// Convert JS object to UserClaims
		user := p.jsObjectToUserClaims(userObj)

		allowed, zoneResp, err := p.app.PolicyIsZoneAllowedForUser(zone, user)
		if err != nil {
			return p.vm.NewGoError(err)
		}

		result := p.vm.NewObject()
		result.Set("allowed", allowed)
		if zoneResp != nil {
			result.Set("zone", p.vm.ToValue(zoneResp))
		}

		return result
	}
}

// getAllWrapper wraps Storage.PolicyGetAll to handle JS conversion
func (p *JavaScriptEngine) getAllWrapper() func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		rules, err := p.app.Storage.PolicyGetAll()
		if err != nil {
			return p.vm.NewGoError(err)
		}

		// Convert each rule to JS object
		rulesArray := p.vm.NewArray()
		for i, rule := range rules {
			rulesArray.Set(fmt.Sprintf("%d", i), p.policyRuleToJSObject(&rule))
		}

		return rulesArray
	}
}

// toString converts a Goja Value to a string, returning empty string if nil
func toString(val goja.Value) string {
	if val == nil {
		return ""
	}
	return val.String()
}

// jsObjectToUserClaims converts a JavaScript object to UserClaims struct
func (p *JavaScriptEngine) jsObjectToUserClaims(obj *goja.Object) *UserClaims {
	return &UserClaims{
		Subject:           toString(obj.Get("sub")),
		Email:             toString(obj.Get("email")),
		PreferredUsername: toString(obj.Get("preferred_username")),
		Name:              toString(obj.Get("name")),
	}
}

// policyRuleToJSObject converts a PolicyRule struct to a JavaScript object
// with snake_case property names to match the JSON struct tags
func (p *JavaScriptEngine) policyRuleToJSObject(rule *PolicyRule) goja.Value {
	obj := p.vm.NewObject()
	obj.Set("id", rule.ID)
	obj.Set("zone_pattern", rule.ZonePattern)
	obj.Set("zone_soa", rule.ZoneSoa)
	obj.Set("target_user_filter", rule.TargetUserFilter)
	obj.Set("description", rule.Description)
	obj.Set("created_at", rule.CreatedAt.String())
	return obj
}

// policyRulesResponseToJSObject converts a PolicyRulesResponse to a JavaScript object
func (p *JavaScriptEngine) policyRulesResponseToJSObject(resp *PolicyRulesResponse) goja.Value {
	obj := p.vm.NewObject()
	obj.Set("edit_allowed", resp.EditAllowed)

	// Convert rules array
	rulesArray := p.vm.NewArray()
	for i, rule := range resp.Rules {
		rulesArray.Set(fmt.Sprintf("%d", i), p.policyRuleToJSObject(&rule))
	}
	obj.Set("rules", rulesArray)

	return obj
}

func (p *JavaScriptEngine) setupConsole() error {
	console := p.vm.NewObject()
	logFn := func(level string) func(goja.FunctionCall) goja.Value {
		return func(call goja.FunctionCall) goja.Value {
			msg := ""
			for _, arg := range call.Arguments {
				msg = fmt.Sprintf("%s %v", msg, arg.Export())
			}

			switch level {
			case "error":
				p.logger.Error(msg)
			case "warn":
				p.logger.Warn(msg)
			default:
				p.logger.Info(msg)
			}
			return goja.Undefined()
		}
	}

	console.Set("log", logFn("info"))
	console.Set("error", logFn("error"))
	console.Set("warn", logFn("warn"))

	return p.vm.Set("console", console)
}
