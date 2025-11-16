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
	ValidationTag string // Stores the raw validation tag
}

// FieldMetadata holds the description and validation tag from struct definitions.
type FieldMetadata struct {
	Description   string
	ValidationTag string
}

// Global map to store field metadata found in the first pass
var fieldMetadata = make(map[string]FieldMetadata)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Error: Please provide the Go source file path as the first argument.")
		fmt.Println("Usage: go run docgen.go <path/to/config.go>")
		os.Exit(1)
	}

	targetFile := os.Args[1]

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, targetFile, nil, parser.ParseComments)
	if err != nil {
		fmt.Printf("Error parsing file: %v\n", err)
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

	// --- SECOND PASS: Extract Env Vars and Defaults from the function ---
	ast.Inspect(node, func(n ast.Node) bool {
		// Find the target function GetAppConfigFromEnvironment
		if funcDecl, ok := n.(*ast.FuncDecl); ok && funcDecl.Name.Name == "GetAppConfigFromEnvironment" {

			// *** CRITICAL FIX: Look for the variable assignment (appConfig := AppConfig{...}) ***
			if assignStmt, ok := funcDecl.Body.List[0].(*ast.AssignStmt); ok {

				// The value on the right side of the assignment (RHS) is the CompositeLit: AppConfig{...}
				if lit, ok := assignStmt.Rhs[0].(*ast.CompositeLit); ok {

					// Iterate over the top-level fields of AppConfig
					for _, element := range lit.Elts {
						if keyValue, ok := element.(*ast.KeyValueExpr); ok {
							fieldName := keyValue.Key.(*ast.Ident).Name

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
				}
			}
			return false // Stop inspection after finding the function
		}
		return true
	})

	// Manually add DevMode which is complex and requires special handling
	addDevModeEntry(fset, node, envVars)

	// 4. Generate Markdown
	generateMarkdown(envVars)
}

// extractStructFieldDescriptions captures Doc, Comment, and the 'validate' tag for fields.
func extractStructFieldDescriptions(structType *ast.StructType) {
	for _, field := range structType.Fields.List {
		var description string
		var validationTag string

		// Get comment/doc
		if field.Doc != nil {
			description = field.Doc.Text()
		} else if field.Comment != nil {
			description = field.Comment.Text()
		}

		// --- FIX: Use reflect.StructTag to safely parse the tag ---
		if field.Tag != nil {
			// Remove backticks
			rawTag := strings.Trim(field.Tag.Value, "`")

			// Use reflect to parse the tag string correctly
			tag := reflect.StructTag(rawTag)

			// Get the value associated with the "validate" key
			validationTag = tag.Get("validate")
		}

		// Clean up the description
		description = strings.TrimSpace(description)
		description = strings.ReplaceAll(description, "\n", " ")

		if (description != "" || validationTag != "") && len(field.Names) > 0 {
			fieldName := field.Names[0].Name // Get the field name (e.g., Server)
			fieldMetadata[fieldName] = FieldMetadata{
				Description:   description,
				ValidationTag: validationTag,
			}
		}
	}
}

// extractNestedEnvVars finds helper.GetEnv* calls inside nested structs and retrieves validation info.
func extractNestedEnvVars(fset *token.FileSet, lit *ast.CompositeLit, category string, envVars map[string]EnvVarInfo) {
	for _, element := range lit.Elts {
		if keyValue, ok := element.(*ast.KeyValueExpr); ok {
			fieldName := keyValue.Key.(*ast.Ident).Name

			if callExpr, ok := keyValue.Value.(*ast.CallExpr); ok {
				if fun, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
					// Check for calls to helper.GetEnv*
					if fun.X.(*ast.Ident).Name == "helper" && strings.HasPrefix(fun.Sel.Name, "GetEnv") {
						args := callExpr.Args

						// Arg 0: Environment Variable Name
						envVar := strings.Trim(args[0].(*ast.BasicLit).Value, "\"")

						// Arg 1: Default Value (use the FileSet to print complex expressions)
						defaultValue := extractDefaultValue(fset, args[1])

						// Retrieve the metadata (description and validation tag)
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
							ValidationTag: validationTag, // Store the raw tag
						}
						envVars[envVar] = info
					}
				}
			}
		}
	}
}

// extractDefaultValue handles literals, identifiers, and complex expressions.
func extractDefaultValue(fset *token.FileSet, expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.BasicLit:
		// Basic literal (string, int, float)
		return strings.Trim(v.Value, "\"")
	case *ast.Ident:
		// Identifier (e.g., constant or boolean 'true')
		return v.Name
	default:
		// Use go/printer for complex expressions (like calculations or function calls)
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, expr); err == nil {
			s := buf.String()

			// Clean up type casts for display (e.g., int32(...) -> ...)
			s = strings.TrimPrefix(s, "int32(")
			s = strings.TrimPrefix(s, "uint64(")
			s = strings.TrimSuffix(s, ")")

			// Special handling for the DefaultTTLSeconds calculation
			if strings.Contains(s, "time.Hour") {
				return "31536000 (Calculated as 1 year)"
			}

			return s
		}
		return ""
	}
}

// addDevModeEntry manually extracts the DYNAMIC_ZONES_API_MODE variable.
func addDevModeEntry(fset *token.FileSet, node *ast.File, envVars map[string]EnvVarInfo) {
	// We search the AST again specifically for the DevMode field initialization
	ast.Inspect(node, func(n ast.Node) bool {
		if funcDecl, ok := n.(*ast.FuncDecl); ok && funcDecl.Name.Name == "GetAppConfigFromEnvironment" {
			// *** CRITICAL FIX: Look for the assignment statement (the first statement in the body) ***
			if assignStmt, ok := funcDecl.Body.List[0].(*ast.AssignStmt); ok {
				if lit, ok := assignStmt.Rhs[0].(*ast.CompositeLit); ok {
					for _, element := range lit.Elts {
						if keyValue, ok := element.(*ast.KeyValueExpr); ok {
							if keyValue.Key.(*ast.Ident).Name == "DevMode" {
								if binaryExpr, ok := keyValue.Value.(*ast.BinaryExpr); ok {
									// The left side is the helper.GetEnvString(...) call
									if callExpr, ok := binaryExpr.X.(*ast.CallExpr); ok {
										args := callExpr.Args

										// Arg 0: Environment Variable Name
										envVar := strings.Trim(args[0].(*ast.BasicLit).Value, "\"")

										// Arg 1: Default Value (which is 'production')
										defaultValue := strings.Trim(args[1].(*ast.BasicLit).Value, "\"")

										// Get description for DevMode (manual or lookup)
										metadata := fieldMetadata["DevMode"]
										desc := metadata.Description
										if desc == "" {
											desc = "Run mode; returns true if set to 'development'."
										}

										// DevMode has no direct validation on the env var itself.
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
				}
			}
			return false
		}
		return true
	})
}

// generateMarkdown prints the final output table with intermediate bolded headers, including a validation column.
func generateMarkdown(envVars map[string]EnvVarInfo) {
	// A basic ordered list of categories for cleaner output
	categoryOrder := map[string]string{
		"UpstreamDns":      "Upstream DNS Updates",
		"PowerDns":         "PowerDNS Configuration",
		"Storage":          "Storage Configuration",
		"WebServer":        "API Server Configuration",
		"UserZoneProvider": "Zone Provider Settings",
		"General Settings": "General Settings", // For DevMode
	}

	fmt.Println("\n## ⚙️ Environment Variables Reference")
	fmt.Println("") // Add a newline after the main header

	// Create a map to group variables by the user-friendly category name
	grouped := make(map[string][]EnvVarInfo)
	for _, info := range envVars {
		catName := categoryOrder[info.Category]
		if catName == "" {
			catName = "Other Settings"
		}
		grouped[catName] = append(grouped[catName], info)
	}

	// --- Start the single large table ---
	// Using 4 columns
	fmt.Println("| **Variable Name** | **Default Value** | **Validation** | **Description** |")
	// Using uniform length delimiters for better column width suggestion and centered content where appropriate
	fmt.Println("| :---: | :---: | :---: | :--- |")

	// Print in the defined order
	for _, catName := range categoryOrder {
		if vars, ok := grouped[catName]; ok && len(vars) > 0 {

			// 1. Print the category header row (bolded)
			fmt.Printf("| **%s** | | | |\n", catName)

			// 2. Print the environment variables for this category
			for _, info := range vars {
				desc := info.Description
				if desc == "" {
					desc = "No doc comment provided."
				}

				defaultValue := strings.TrimSpace(info.Default)
				if defaultValue == "" {
					defaultValue = "''"
				}

				// Format the raw validation tag for display
				validationReq := formatValidationTag(info.ValidationTag)

				// Print the row with the new column
				fmt.Printf("| `%s` | `%s` | %s | %s |\n", info.Name, defaultValue, validationReq, desc)
			}
		}
	}
	// --- Table ends implicitly here ---
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
				// --- THIS IS THE CORRECT LOGIC ---
				// It takes "sqlite postgres mysql" and converts it to "sqlite, postgres, mysql"
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
