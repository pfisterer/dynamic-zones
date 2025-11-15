package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"strings"
)

// EnvVarInfo holds the extracted data for a single environment variable.
type EnvVarInfo struct {
	Name        string
	Default     string
	Description string
	Category    string
}

// Global map to store field descriptions found in the first pass
var fieldDescriptions = make(map[string]string)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Error: Please provide the Go source file path as the first argument.")
		fmt.Println("Usage: go run docgen.go <path/to/config.go>")
		os.Exit(1)
	}

	targetFile := os.Args[1]

	fset := token.NewFileSet()
	// Parse the file and get the Abstract Syntax Tree, including comments
	node, err := parser.ParseFile(fset, targetFile, nil, parser.ParseComments)
	if err != nil {
		fmt.Printf("Error parsing file: %v\n", err)
		os.Exit(1)
	}

	envVars := make(map[string]EnvVarInfo)

	// --- FIRST PASS: Extract Field Descriptions from Structs ---
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
			if blockStmt, ok := funcDecl.Body.List[0].(*ast.ReturnStmt); ok {
				if lit, ok := blockStmt.Results[0].(*ast.CompositeLit); ok {
					// Iterate over the top-level fields of AppConfig
					for _, element := range lit.Elts {
						if keyValue, ok := element.(*ast.KeyValueExpr); ok {
							fieldName := keyValue.Key.(*ast.Ident).Name

							// Special case: DevMode is a comparison, not a direct GetEnv* call, so we skip it here.
							if fieldName == "DevMode" {
								// NOTE: We could manually define EnvVarInfo for DevMode here if needed.
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

// extractStructFieldDescriptions captures both Doc and Comment types for fields.
func extractStructFieldDescriptions(structType *ast.StructType) {
	for _, field := range structType.Fields.List {
		var description string

		// Check for Doc comments (above the field block)
		if field.Doc != nil {
			description = field.Doc.Text()
		} else if field.Comment != nil {
			// Check for inline comments (e.g., // The DNS server...)
			description = field.Comment.Text()
		}

		// Clean up the description
		description = strings.TrimSpace(description)
		description = strings.ReplaceAll(description, "\n", " ")

		if description != "" && len(field.Names) > 0 {
			fieldName := field.Names[0].Name // Get the field name (e.g., Server)
			fieldDescriptions[fieldName] = description
		}
	}
}

// extractNestedEnvVars finds helper.GetEnv* calls inside nested structs.
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

						// Retrieve the description
						description, found := fieldDescriptions[fieldName]
						if !found {
							description = "No documentation comment found."
						}

						info := EnvVarInfo{
							Name:        envVar,
							Default:     defaultValue,
							Category:    category,
							Description: description,
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
			if blockStmt, ok := funcDecl.Body.List[0].(*ast.ReturnStmt); ok {
				if lit, ok := blockStmt.Results[0].(*ast.CompositeLit); ok {
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
										desc := fieldDescriptions["DevMode"]
										if desc == "" {
											desc = "Run mode; returns true if set to 'development'."
										}

										envVars[envVar] = EnvVarInfo{
											Name:        envVar,
											Default:     fmt.Sprintf("'%s' (defaults to false)", defaultValue),
											Description: desc,
											Category:    "General Settings",
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

// generateMarkdown prints the final output table.
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

	// Create a map to group variables by the user-friendly category name
	grouped := make(map[string][]EnvVarInfo)
	for _, info := range envVars {
		catName := categoryOrder[info.Category]
		if catName == "" {
			catName = "Other Settings"
		}
		grouped[catName] = append(grouped[catName], info)
	}

	// Print in the defined order
	for _, catName := range categoryOrder {
		if vars, ok := grouped[catName]; ok && len(vars) > 0 {
			fmt.Printf("\n### %s\n", catName)
			fmt.Println("\n| **Variable Name** | **Default Value** | **Description** |")
			fmt.Println("| :---------------- | :---------------- | :-------------- |")

			for _, info := range vars {
				// Clean up description and default value for display
				desc := info.Description
				if desc == "" {
					desc = "No doc comment provided."
				}

				defaultValue := strings.TrimSpace(info.Default)
				if defaultValue == "" {
					defaultValue = "'' (empty string)"
				}

				fmt.Printf("| `%s` | `%s` | %s |\n", info.Name, defaultValue, desc)
			}
		}
	}
}
