// cmd/sentra/commands/build.go
package commands

import (
	"fmt"
	"os"
	"sentra/internal/build"
)

// BuildCommand handles the build command
func BuildCommand(args []string) error {
	projectRoot := "."
	if len(args) > 0 {
		projectRoot = args[0]
	}

	builder, err := build.NewBuilder(projectRoot)
	if err != nil {
		return fmt.Errorf("failed to initialize builder: %w", err)
	}

	return builder.Build()
}

// WatchCommand handles the watch command
func WatchCommand(args []string) error {
	projectRoot := "."
	if len(args) > 0 {
		projectRoot = args[0]
	}

	builder, err := build.NewBuilder(projectRoot)
	if err != nil {
		return fmt.Errorf("failed to initialize builder: %w", err)
	}

	return builder.Watch()
}

// CleanCommand handles the clean command
func CleanCommand(args []string) error {
	projectRoot := "."
	if len(args) > 0 {
		projectRoot = args[0]
	}

	builder, err := build.NewBuilder(projectRoot)
	if err != nil {
		return fmt.Errorf("failed to initialize builder: %w", err)
	}

	return builder.Clean()
}

// InitCommand initializes a new Sentra project
func InitCommand(args []string) error {
	projectName := "sentra-project"
	if len(args) > 0 {
		projectName = args[0]
	}

	fmt.Printf("Initializing new Sentra project: %s\n", projectName)

	// Create project directory
	if err := os.MkdirAll(projectName, 0755); err != nil {
		return err
	}

	// Create sentra.json
	manifestContent := fmt.Sprintf(`{
  "name": "%s",
  "version": "0.1.0",
  "description": "A Sentra security automation project",
  "author": "",
  "license": "MIT",
  "entry_point": "main.sn",
  "dependencies": {},
  "scripts": {
    "start": "sentra run main.sn",
    "build": "sentra build",
    "test": "sentra test"
  },
  "build": {
    "output_path": "dist/%s.snb",
    "optimize": true,
    "include_debug": false
  }
}`, projectName, projectName)

	manifestPath := projectName + "/sentra.json"
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		return err
	}

	// Create main.sn
	mainContent := `#!/usr/bin/env sentra
// Main entry point for the project

import "sentra/security"

fn main() {
    log("Starting security automation...")
    
    // Your code here
    
    log("Done!")
}

// Run the main function
main()
`

	mainPath := projectName + "/main.sn"
	if err := os.WriteFile(mainPath, []byte(mainContent), 0644); err != nil {
		return err
	}

	// Create .gitignore
	gitignoreContent := `# Sentra
dist/
vendor/
*.snb
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
`

	gitignorePath := projectName + "/.gitignore"
	if err := os.WriteFile(gitignorePath, []byte(gitignoreContent), 0644); err != nil {
		return err
	}

	// Create README.md
	readmeContent := fmt.Sprintf(`# %s

A Sentra security automation project.

## Getting Started

### Prerequisites

- Sentra runtime installed
- Go 1.21+ (for building from source)

### Installation

1. Install dependencies:
   ` + "```bash" + `
   sentra mod install
   ` + "```" + `

2. Run the project:
   ` + "```bash" + `
   sentra run main.sn
   ` + "```" + `

### Building

To build a distributable bundle:

` + "```bash" + `
sentra build
` + "```" + `

This will create a compiled bundle in the ` + "`dist/`" + ` directory.

## Project Structure

- ` + "`main.sn`" + ` - Entry point
- ` + "`sentra.json`" + ` - Project manifest
- ` + "`vendor/`" + ` - Dependencies (auto-generated)
- ` + "`dist/`" + ` - Build output (auto-generated)

## License

MIT
`, projectName)

	readmePath := projectName + "/README.md"
	if err := os.WriteFile(readmePath, []byte(readmeContent), 0644); err != nil {
		return err
	}

	// Create src directory
	srcPath := projectName + "/src"
	if err := os.MkdirAll(srcPath, 0755); err != nil {
		return err
	}

	// Create tests directory
	testsPath := projectName + "/tests"
	if err := os.MkdirAll(testsPath, 0755); err != nil {
		return err
	}

	// Create a sample test
	testContent := `#!/usr/bin/env sentra
// Sample test file

import "sentra/testing"

fn test_example() {
    let result = 2 + 2
    assert(result == 4, "Math should work")
}

// Run tests
test_example()
log("All tests passed!")
`

	testPath := testsPath + "/example_test.sn"
	if err := os.WriteFile(testPath, []byte(testContent), 0644); err != nil {
		return err
	}

	fmt.Printf(`
✓ Project initialized successfully!

Next steps:
  cd %s
  sentra run main.sn

To build:
  sentra build

To add dependencies:
  sentra mod add <package>

Happy coding!
`, projectName)

	return nil
}