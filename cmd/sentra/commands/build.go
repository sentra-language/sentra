// cmd/sentra/commands/build.go
package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"sentra/internal/build"
)

// BuildCommand handles the build command
func BuildCommand(args []string) error {
	projectRoot := "."
	if len(args) > 0 {
		projectRoot = args[0]
	}
	
	// Convert to absolute path
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		return fmt.Errorf("failed to resolve project path: %w", err)
	}

	builder, err := build.NewBuilder(absRoot)
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

	// Get current user for personalized greeting
	currentUser := os.Getenv("USER")
	if currentUser == "" {
		currentUser = os.Getenv("USERNAME") // Windows
	}
	if currentUser == "" {
		currentUser = "friend"
	}
	
	// Create main.sn with an inspiring example
	mainContent := fmt.Sprintf(`#!/usr/bin/env sentra
// Welcome to Sentra! Code with Confidence! 🚀
// This example shows how easy and fun programming can be

// Main function - where the magic happens!
fn main() {
    // Log a beautiful welcome banner
    log("╔════════════════════════════════════════════════╗")
    log("║       SENTRA PROGRAMMING LANGUAGE              ║")
    log("║        Secure • Simple • Powerful 🚀           ║")
    log("╚════════════════════════════════════════════════╝")
    log("")
    
    // Greet the user personally
    let user = "%s"
    
    log("Hey " + user + "! Welcome to the future of secure coding!")
    log("Fun fact: In a parallel universe, all bugs are features!")
    log("")
    
    // Show off some cool Sentra features
    log("Let me show you what Sentra can do:")
    log("")
    
    // 1. Working with arrays and loops
    let tasks = ["🔒 Build secure apps", "🤖 Automate security", "🎯 Hack ethically", "🛡️ Protect systems", "✨ Write clean code"]
    
    log("Things you can do with Sentra:")
    let i = 0
    while i < 5 {
        log("  " + (i+1) + ". " + tasks[i])
        i = i + 1
    }
    
    // 2. Security-focused features
    log("")
    log("🔐 Security Features:")
    log("  • Built-in crypto functions")
    log("  • Network scanning capabilities")
    log("  • File system security checks")
    log("  • Memory-safe operations")
    
    // 3. Fun with strings and numbers
    log("")
    let message = "sentra rocks!"
    let msgLen = 13  // length of message
    log("Fun fact: '" + message + "' has " + msgLen + " characters!")
    
    // Simple calculation
    let x = 42
    let y = 1337
    let result = x + y
    log("Security calculation: " + x + " + " + y + " = " + result)
    
    log("")
    log("🎉 Happy coding! Build something amazing today!")
    log("")
    log("Try editing this file and run: sentra run main.sn")
    log("Or create a new file and explore Sentra's features!")
}

// Let's go! Run the main function
main()
`, currentUser)

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
// Sample test file for your Sentra project

log("🧪 Running example tests...")

// Test basic math operations
let result = 2 + 2
assert_equal(4, result, "Basic addition: 2 + 2 should equal 4")
log("✓ Math test passed")

// Test string operations
let greeting = "Hello, " + "Sentra!"
assert_equal("Hello, Sentra!", greeting, "String concatenation test")
log("✓ String test passed")

// Test boolean logic
assert_true(10 > 5, "10 should be greater than 5")
assert_false(5 > 10, "5 should not be greater than 10")
log("✓ Boolean tests passed")

// Test comparisons
let x = 42
let y = 42
assert_equal(x, y, "Variables should be equal")
assert_true(x == y, "Equality comparison should work")
log("✓ Comparison tests passed")

log("")
log("🎉 All tests passed successfully!")
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