package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"reflect"
	"strings"
)

// EnvVarInfo holds the extracted data for a single environment variable.
type EnvVarInfo struct {
	Name          string
	Default       string
	Description   string
	Category      string
	ValidationTag string
}

// FieldMetadata holds the description and validation tag from struct definitions.
type FieldMetadata struct {
	Description   string
	ValidationTag string
}

// Global map to store field metadata found in the first pass
var fieldMetadata = make(map[string]FieldMetadata)

func main() {
	// Aggressive panic recovery to ensure we catch any crash
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "!!! CRITICAL PANIC CAUGHT: %v\n", r)
			fmt.Fprintf(os.Stderr, "Check the stack trace to find the failing type assertion.\n")
			os.Exit(1)
		}
	}()

	if len(os.Args) < 2 {
		fmt.Println("Error: Please provide the Go source file path as the first argument.")
		os.Exit(1)
	}

	targetFile := os.Args[1]

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, targetFile, nil, parser.ParseComments)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing file: %v\n", err)
		os.Exit(1)
	}

	envVars := make(map[string]EnvVarInfo)

	// --- FIRST PASS: Extract Field Descriptions and Validation Tags from Structs ---
	for _, decl := range node.Decls {
		if genDecl, ok := decl.(*ast.GenDecl); ok && genDecl.Tok == token.TYPE {
			for _, spec := range genDecl.Specs {
				if typeSpec, ok := spec.(*ast.TypeSpec); ok {
					if structType, ok := typeSpec.Type.(*ast.StructType); ok {
						extractStructFieldDescriptions(structType)
					}
				}
			}
		}
	}

	// --- SECOND PASS: Extract Env Vars and Defaults from the function (MAIN DEBUG AREA) ---
	ast.Inspect(node, func(n ast.Node) bool {
		// Find the target function GetAppConfigFromEnvironment
		if funcDecl, ok := n.(*ast.FuncDecl); ok && funcDecl.Name.Name == "GetAppConfigFromEnvironment" {

			if funcDecl.Body == nil || len(funcDecl.Body.List) == 0 {
				fmt.Fprintf(os.Stderr, "TRACE: Function body is nil or empty.\n")
				return false
			}

			// Statement 0 is expected to be 'err := error(nil)' or similar, Statement 1 is the config assignment.
			// We assume the variable is declared and initialized on the first line (err := nil) and the config assignment is the second, or the first is the config.
			// If the declaration is 'var appConfig AppConfig', and the assignment is appConfig = AppConfig{...}
			// We must be robust: Check all statements for the assignment.
			var configLit *ast.CompositeLit

			// Search the body for the config assignment
			for _, stmt := range funcDecl.Body.List {
				if assignStmt, ok := stmt.(*ast.AssignStmt); ok {
					if len(assignStmt.Rhs) > 0 {
						if lit, ok := assignStmt.Rhs[0].(*ast.CompositeLit); ok {
							// Found the AppConfig{...} literal
							configLit = lit
							break
						}
					}
				} else if declStmt, ok := stmt.(*ast.DeclStmt); ok {
					// Handle variable declaration followed by assignment (unlikely in your structure, but safer)
					if genDecl, ok := declStmt.Decl.(*ast.GenDecl); ok && genDecl.Tok == token.VAR {
						// Handle the case where the config is declared globally/earlier
					}
				}
			}

			if configLit == nil {
				fmt.Fprintf(os.Stderr, "TRACE: AppConfig CompositeLit not found in function body statements.\n")
				return false
			}

			// Iterate over the top-level fields of AppConfig
			for _, element := range configLit.Elts {
				if keyValue, ok := element.(*ast.KeyValueExpr); ok {

					keyIdent, keyOk := keyValue.Key.(*ast.Ident)
					if !keyOk {
						fmt.Fprintf(os.Stderr, "TRACE: Skipping element in AppConfig. Key is not *ast.Ident. Type: %T\n", keyValue.Key)
						continue
					}

					fieldName := keyIdent.Name

					// Special case: DevMode is complex, skip it here.
					if fieldName == "DevMode" {
						continue
					}

					category := strings.Trim(fieldName, " ")

					// Check the value, which is another CompositeLit (nested struct)
					if nestedLit, ok := keyValue.Value.(*ast.CompositeLit); ok {
						extractNestedEnvVars(fset, nestedLit, category, envVars)
					}
				}
			}

			return false // Stop inspection after finding the function
		}
		return true
	})

	// Manually add DevMode which is complex and requires special handling
	addDevModeEntry(fset, node, envVars)

	fmt.Fprintf(os.Stderr, "TRACE: Final variables extracted count: %d\n", len(envVars))

	// 4. Generate Markdown
	generateMarkdown(envVars)
}

// --- CORE FUNCTIONS ---

func extractStructFieldDescriptions(structType *ast.StructType) {
	for _, field := range structType.Fields.List {
		var description string
		var validationTag string

		if field.Doc != nil {
			description = field.Doc.Text()
		} else if field.Comment != nil {
			description = field.Comment.Text()
		}

		if field.Tag != nil {
			rawTag := strings.Trim(field.Tag.Value, "`")
			tag := reflect.StructTag(rawTag)
			validationTag = tag.Get("validate")
		}

		description = strings.TrimSpace(description)
		description = strings.ReplaceAll(description, "\n", " ")

		if (description != "" || validationTag != "") && len(field.Names) > 0 {
			fieldName := field.Names[0].Name
			fieldMetadata[fieldName] = FieldMetadata{
				Description:   description,
				ValidationTag: validationTag,
			}
		}
	}
}

// processEnvCall is a helper to extract the details from a helper.GetEnv* call expression.
func processEnvCall(fset *token.FileSet, fieldName, category string, envVars map[string]EnvVarInfo, callExpr *ast.CallExpr) {
	args := callExpr.Args

	// Arg 0: Environment Variable Name (safe extraction)
	var envVar string
	if basicLit, ok := args[0].(*ast.BasicLit); ok {
		envVar = strings.Trim(basicLit.Value, "\"")
	} else {
		fmt.Fprintf(os.Stderr, "TRACE: WARNING: Skipping field %s: Env Var name (Arg 0) is not a literal, type is %T.\n", fieldName, args[0])
		return
	}

	// Arg 1: Default Value
	defaultValue := extractDefaultValue(fset, args[1])

	// Retrieve the metadata
	metadata, found := fieldMetadata[fieldName]
	description := "No documentation comment found."
	validationTag := ""
	if found {
		description = metadata.Description
		validationTag = metadata.ValidationTag
	}

	info := EnvVarInfo{
		Name:          envVar,
		Default:       defaultValue,
		Category:      category,
		Description:   description,
		ValidationTag: validationTag,
	}
	envVars[envVar] = info
}

// extractNestedEnvVars finds helper.GetEnv* calls inside nested structs and retrieves validation info.
func extractNestedEnvVars(fset *token.FileSet, lit *ast.CompositeLit, category string, envVars map[string]EnvVarInfo) {
	for _, element := range lit.Elts {
		if keyValue, ok := element.(*ast.KeyValueExpr); ok {

			keyIdent, keyOk := keyValue.Key.(*ast.Ident)
			if !keyOk {
				fmt.Fprintf(os.Stderr, "TRACE: WARNING: Skipping element in %s. Key is not *ast.Ident. Type: %T\n", category, keyValue.Key)
				continue
			}
			fieldName := keyIdent.Name

			if callExpr, ok := keyValue.Value.(*ast.CallExpr); ok {
				if fun, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
					// SIMPLE CASE: Direct call (e.g., Server: helper.GetEnvString(...))
					// Safety check for fun.X
					if ident, ok := fun.X.(*ast.Ident); ok && ident.Name == "helper" && strings.HasPrefix(fun.Sel.Name, "GetEnv") {
						processEnvCall(fset, fieldName, category, envVars, callExpr)
						continue
					}
				}

				// COMPLEX CASE: Anonymous function call (e.g., DefaultRecords: func() {...}())
				if funcLit, ok := callExpr.Fun.(*ast.FuncLit); ok {
					//fmt.Fprintf(os.Stderr, "TRACE: Checking complex field %s\n", fieldName)

					ast.Inspect(funcLit.Body, func(n ast.Node) bool {
						if nestedCallExpr, ok := n.(*ast.CallExpr); ok {
							if nestedFun, ok := nestedCallExpr.Fun.(*ast.SelectorExpr); ok {
								// Safety check for nestedFun.X
								if ident, ok := nestedFun.X.(*ast.Ident); ok && ident.Name == "helper" && nestedFun.Sel.Name == "GetEnvString" {
									//fmt.Fprintf(os.Stderr, "TRACE: Found ENV Var: %s\n", nestedCallExpr.Args[0].(*ast.BasicLit).Value)
									processEnvCall(fset, fieldName, category, envVars, nestedCallExpr)
									return false // Found it, stop inspecting this branch
								}
							}
						}
						return true
					})
				}
			}
		}
	}
}

// extractDefaultValue handles literals, identifiers, and complex expressions.
func extractDefaultValue(fset *token.FileSet, expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.BasicLit:
		return strings.Trim(v.Value, "\"")
	case *ast.Ident:
		return v.Name
	default:
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, expr); err == nil {
			s := buf.String()

			s = strings.TrimPrefix(s, "int32(")
			s = strings.TrimPrefix(s, "uint64(")
			s = strings.TrimSuffix(s, ")")

			if strings.Contains(s, "time.Hour") {
				return "31536000 (Calculated as 1 year)"
			}

			if s == "\"[]\"" {
				return "[] (Empty JSON Array)"
			}

			return s
		}
		return ""
	}
}

// addDevModeEntry manually extracts the DYNAMIC_ZONES_API_MODE variable.
func addDevModeEntry(fset *token.FileSet, node *ast.File, envVars map[string]EnvVarInfo) {
	ast.Inspect(node, func(n ast.Node) bool {
		if funcDecl, ok := n.(*ast.FuncDecl); ok && funcDecl.Name.Name == "GetAppConfigFromEnvironment" {

			var configLit *ast.CompositeLit
			for _, stmt := range funcDecl.Body.List {
				if assignStmt, ok := stmt.(*ast.AssignStmt); ok {
					if len(assignStmt.Rhs) > 0 {
						if lit, ok := assignStmt.Rhs[0].(*ast.CompositeLit); ok {
							configLit = lit
							break
						}
					}
				}
			}

			if configLit == nil {
				return false
			}

			for _, element := range configLit.Elts {
				if keyValue, ok := element.(*ast.KeyValueExpr); ok {
					if keyValue.Key.(*ast.Ident).Name == "DevMode" {
						if binaryExpr, ok := keyValue.Value.(*ast.BinaryExpr); ok {
							if callExpr, ok := binaryExpr.X.(*ast.CallExpr); ok {
								args := callExpr.Args

								var envVar, defaultValue string

								if basicLit, ok := args[0].(*ast.BasicLit); ok {
									envVar = strings.Trim(basicLit.Value, "\"")
								}

								if basicLit, ok := args[1].(*ast.BasicLit); ok {
									defaultValue = strings.Trim(basicLit.Value, "\"")
								}

								if envVar == "" || defaultValue == "" {
									fmt.Fprintf(os.Stderr, "TRACE: WARNING: Skipping DevMode: Could not safely extract env var or default value.\n")
									return true
								}

								metadata := fieldMetadata["DevMode"]
								desc := metadata.Description
								if desc == "" {
									desc = "Run mode; returns true if set to 'development'."
								}

								validationTag := ""

								envVars[envVar] = EnvVarInfo{
									Name:          envVar,
									Default:       fmt.Sprintf("'%s' (defaults to false)", defaultValue),
									Description:   desc,
									Category:      "General Settings",
									ValidationTag: validationTag,
								}
							}
						}
					}
				}
			}
			return false
		}
		return true
	})
}

// generateMarkdown prints the final output table with intermediate bolded headers, including a validation column.
func generateMarkdown(envVars map[string]EnvVarInfo) {
	categoryOrder := map[string]string{
		"UpstreamDns":      "Upstream DNS Updates",
		"PowerDns":         "PowerDNS Configuration",
		"Storage":          "Storage Configuration",
		"WebServer":        "API Server Configuration",
		"UserZoneProvider": "Zone Provider Settings",
		"General Settings": "General Settings",
	}

	fmt.Println("\n## ⚙️ Environment Variables Reference")
	fmt.Println("")

	grouped := make(map[string][]EnvVarInfo)
	for _, info := range envVars {
		catName := categoryOrder[info.Category]
		if catName == "" {
			catName = "Other Settings"
		}
		grouped[catName] = append(grouped[catName], info)
	}

	fmt.Println("| **Variable Name** | **Default Value** | **Validation** | **Description** |")
	fmt.Println("| :---: | :---: | :---: | :--- |")

	for _, catName := range categoryOrder {
		if vars, ok := grouped[catName]; ok && len(vars) > 0 {

			fmt.Printf("| **%s** | | | |\n", catName)

			for _, info := range vars {
				desc := info.Description
				if desc == "" {
					desc = "No doc comment provided."
				}

				defaultValue := strings.TrimSpace(info.Default)
				if defaultValue == "" {
					defaultValue = "''"
				}

				validationReq := formatValidationTag(info.ValidationTag)

				fmt.Printf("| `%s` | `%s` | %s | %s |\n", info.Name, defaultValue, validationReq, desc)
			}
		}
	}
}

// formatValidationTag converts the raw validate tag string into a human-readable format.
func formatValidationTag(tag string) string {
	if tag == "" {
		return "*(None)*"
	}

	rules := strings.Split(tag, ",")
	var readableRules []string

	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		parts := strings.SplitN(rule, "=", 2)
		ruleName := parts[0]

		switch ruleName {
		case "required":
			readableRules = append(readableRules, "**Required**")
		case "url":
			readableRules = append(readableRules, "Must be a valid URL")
		case "ip":
			readableRules = append(readableRules, "Must be a valid IP address")
		case "port":
			readableRules = append(readableRules, "Must be a valid port number (1-65535)")
		case "base64":
			readableRules = append(readableRules, "Must be a valid Base64 string")
		case "min":
			if len(parts) == 2 {
				readableRules = append(readableRules, fmt.Sprintf("Minimum value: `%s`", parts[1]))
			}
		case "max":
			if len(parts) == 2 {
				readableRules = append(readableRules, fmt.Sprintf("Maximum value: `%s`", parts[1]))
			}
		case "oneof":
			if len(parts) == 2 {
				options := strings.ReplaceAll(parts[1], " ", ", ")
				readableRules = append(readableRules, fmt.Sprintf("Must be one of: `%s`", options))
			}
		case "required_if":
			if len(parts) == 2 {
				conditionParts := strings.Split(parts[1], " ")
				if len(conditionParts) >= 2 {
					field := conditionParts[0]
					value := conditionParts[1]
					readableRules = append(readableRules, fmt.Sprintf("Required if **%s** is set to `%s`", field, value))
				}
			}
		default:
			readableRules = append(readableRules, fmt.Sprintf("Custom rule: `%s`", rule))
		}
	}

	return strings.Join(readableRules, "<br>")
}
