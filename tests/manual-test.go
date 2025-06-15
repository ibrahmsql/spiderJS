package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

func main() {
	// Read file content
	content, err := os.ReadFile("tests/testdata/react_app.js")
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	script := string(content)
	fmt.Println("File content length:", len(script))
	fmt.Println("First 100 chars:", script[:100])

	// Check for import statements (ES modules)
	importRegex := regexp.MustCompile(`import\s+(?:{[^}]*}|[^{}\n;]+)\s+from\s+['"]([@\w\-/.]+)['"]`)
	matches := importRegex.FindAllStringSubmatch(script, -1)

	fmt.Println("\nImport matches:", len(matches))
	for i, match := range matches {
		if len(match) >= 2 {
			importName := match[1]
			fmt.Printf("Import %d: %s\n", i+1, importName)

			// Extract package name (handle scoped packages like @angular/core)
			packageName := importName
			if strings.Contains(packageName, "/") {
				parts := strings.Split(packageName, "/")
				if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
					packageName = parts[0] + "/" + parts[1] // Keep the scope
				} else {
					packageName = parts[0]
				}
			}

			fmt.Printf("  - Package name: %s\n", packageName)

			// Check for react
			if strings.Contains(packageName, "react") {
				fmt.Printf("  - DETECTED: React framework\n")
			}
		}
	}

	// Check for version
	versionRegex := regexp.MustCompile(`(const|let|var)\s+\w*VERSION\w*\s*=\s*['"]([0-9.]+)['"]`)
	versionMatches := versionRegex.FindAllStringSubmatch(script, -1)

	fmt.Println("\nVersion matches:", len(versionMatches))
	for i, match := range versionMatches {
		if len(match) >= 3 {
			fmt.Printf("Version %d: %s\n", i+1, match[2])
		}
	}
}
