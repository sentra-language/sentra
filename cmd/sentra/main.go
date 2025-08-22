// cmd/sentra/main.go
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sentra/cmd/sentra/commands"
	"sentra/internal/compiler"
	"sentra/internal/debugger"
	"sentra/internal/errors"
	"sentra/internal/lexer"
	"sentra/internal/parser"
	"sentra/internal/packages"
	"sentra/internal/repl"
	"sentra/internal/testing"
	"sentra/internal/vm"
	"time"
)

const VERSION = "1.0.0"

// Build variables - can be set during build with ldflags
var (
	BuildDate = time.Now().Format("2006-01-02")
	GitCommit = "unknown"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		showUsage()
		return
	}
	
	// Debug: print what we got
	// fmt.Printf("DEBUG: args[0] = %q\n", args[0])
	
	// Handle help, version, and update first - support all variations
	if args[0] == "--help" || args[0] == "-h" || args[0] == "help" || args[0] == "--h" || args[0] == "-help" {
		showUsage()
		return
	}
	
	if args[0] == "--version" || args[0] == "-v" || args[0] == "version" || args[0] == "--v" || args[0] == "-version" {
		showVersion()
		return
	}
	
	if args[0] == "update" || args[0] == "--update" {
		updateSentra()
		return
	}
	
	// Handle build commands
	switch args[0] {
	case "init":
		if err := commands.InitCommand(args[1:]); err != nil {
			log.Fatalf("Error: %v", err)
		}
		return
	case "build":
		if err := commands.BuildCommand(args[1:]); err != nil {
			log.Fatalf("Error: %v", err)
		}
		return
	case "watch":
		if err := commands.WatchCommand(args[1:]); err != nil {
			log.Fatalf("Error: %v", err)
		}
		return
	case "clean":
		if err := commands.CleanCommand(args[1:]); err != nil {
			log.Fatalf("Error: %v", err)
		}
		return
	}
	
	// Handle package management commands
	if args[0] == "mod" || args[0] == "get" {
		handlePackageCommands(args)
		return
	}
	
	if args[0] == "repl" {
		repl.Start()
		return
	}

	if args[0] == "debug" && len(args) > 1 {
		runWithDebugger(args[1:])
		return
	}

	if args[0] == "test" {
		runTests(args[1:])
		return
	}

	if args[0] == "run" && len(args) > 1 {
		source, err := os.ReadFile(args[1])
		if err != nil {
			log.Fatalf("Could not read file: %v", err)
		}

		// No prelude - standard library is implemented natively for performance
		fullSource := source

		// --- Add these lines here ---
		// fmt.Println("===== FULL SOURCE CODE =====")
		// fmt.Println(string(fullSource))
		// fmt.Println("============================")

		// Create scanner with file information
		scanner := lexer.NewScannerWithFile(string(fullSource), args[1])
		tokens := scanner.ScanTokens()

		// --- And here ---
		// fmt.Println("===== TOKENS =====")
		// for _, t := range tokens {
		// 	fmt.Println(t)
		// }
		// fmt.Println("==================")
		// -----------------------------

		// Create parser with source for error reporting
		p := parser.NewParserWithSource(tokens, string(fullSource), args[1])
		
		// Wrap parsing in error handler
		var stmts []interface{}
		func() {
			defer func() {
				if r := recover(); r != nil {
					if err, ok := r.(*errors.SentraError); ok {
						fmt.Fprintf(os.Stderr, "%s\n", err.Error())
						os.Exit(1)
					} else if err, ok := r.(error); ok {
						fmt.Fprintf(os.Stderr, "Error: %v\n", err)
						os.Exit(1)
					} else {
						fmt.Fprintf(os.Stderr, "Error: %v\n", r)
						os.Exit(1)
					}
				}
			}()
			parsed := p.Parse()
			for _, s := range parsed {
				stmts = append(stmts, s)
			}
		}()
		compiler := compiler.NewStmtCompilerWithDebug(args[1])
		chunk := compiler.Compile(stmts)

		// Use the enhanced VM for better performance and features
		enhancedVM := vm.NewEnhancedVM(chunk)
		result, err := enhancedVM.Run()
		if err != nil {
			if sentraErr, ok := err.(*errors.SentraError); ok {
				fmt.Fprintf(os.Stderr, "%s\n", sentraErr.Error())
				os.Exit(1)
			} else {
				log.Fatalf("Runtime error: %v", err)
			}
		}
		// Don't print the result unless it's meaningful
		_ = result		
		return
	}

	showUsage()
}

func runWithDebugger(args []string) {
	if len(args) == 0 {
		log.Fatal("Debug command requires a file to debug")
	}
	
	filename := args[0]
	source, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("Could not read file: %v", err)
	}

	// Create scanner with file information
	scanner := lexer.NewScannerWithFile(string(source), filename)
	tokens := scanner.ScanTokens()

	// Create parser with source for error reporting
	p := parser.NewParserWithSource(tokens, string(source), filename)
	
	// Wrap parsing in error handler
	var stmts []interface{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if err, ok := r.(*errors.SentraError); ok {
					fmt.Fprintf(os.Stderr, "%s\n", err.Error())
					os.Exit(1)
				} else if err, ok := r.(error); ok {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				} else {
					fmt.Fprintf(os.Stderr, "Error: %v\n", r)
					os.Exit(1)
				}
			}
		}()
		parsed := p.Parse()
		for _, s := range parsed {
			stmts = append(stmts, s)
		}
	}()
	
	// Compile with debug information
	compiler := compiler.NewStmtCompilerWithDebug(filename)
	chunk := compiler.Compile(stmts)

	// Create VM and debugger
	enhancedVM := vm.NewEnhancedVM(chunk)
	debug := debugger.NewDebugger(enhancedVM)
	
	// Load source for debugging
	debug.LoadSourceFile(filename, string(source))
	
	// Create debug hook and attach to VM
	hook := debugger.NewVMDebugHook(debug)
	enhancedVM.SetDebugHook(hook)
	
	fmt.Printf("🐛 Starting Sentra debugger for: %s\n", filename)
	fmt.Println("The program will start paused. Type 'help' for commands.")
	
	// Start in debug mode
	debug.SetState(debugger.Paused)
	debug.RunDebugger()
	
	// Run the program with debugging enabled
	result, err := enhancedVM.Run()
	if err != nil {
		if sentraErr, ok := err.(*errors.SentraError); ok {
			fmt.Fprintf(os.Stderr, "%s\n", sentraErr.Error())
			os.Exit(1)
		} else {
			log.Fatalf("Runtime error: %v", err)
		}
	}
	
	_ = result
	fmt.Println("\n🎯 Program execution completed")
}

func runTests(args []string) {
	var testFiles []string
	
	if len(args) == 0 {
		// Discover test files in current directory
		matches, err := testing.DiscoverTests(".", "*_test.sn")
		if err != nil {
			log.Fatalf("Error discovering tests: %v", err)
		}
		testFiles = matches
		
		if len(testFiles) == 0 {
			fmt.Println("No test files found (looking for *_test.sn)")
			return
		}
	} else {
		// Run specific test files
		for _, pattern := range args {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				log.Fatalf("Error finding test files: %v", err)
			}
			testFiles = append(testFiles, matches...)
		}
	}
	
	fmt.Printf("🧪 Running %d test file(s)...\n", len(testFiles))
	
	// Create test runner (not used in simplified version)
	// config := &testing.TestConfig{
	// 	Verbose:      true,
	// 	OutputFormat: "text",
	// 	FailFast:     false,
	// }
	// runner := testing.NewTestRunner(config)
	
	// Process each test file
	for _, testFile := range testFiles {
		fmt.Printf("\n📄 Loading test file: %s\n", testFile)
		
		source, err := os.ReadFile(testFile)
		if err != nil {
			log.Printf("Error reading test file %s: %v", testFile, err)
			continue
		}
		
		// Parse and compile the test file
		scanner := lexer.NewScannerWithFile(string(source), testFile)
		tokens := scanner.ScanTokens()
		p := parser.NewParserWithSource(tokens, string(source), testFile)
		
		var stmts []interface{}
		func() {
			defer func() {
				if r := recover(); r != nil {
					if err, ok := r.(*errors.SentraError); ok {
						fmt.Fprintf(os.Stderr, "Parse error in %s:\n%s\n", testFile, err.Error())
					} else {
						fmt.Fprintf(os.Stderr, "Parse error in %s: %v\n", testFile, r)
					}
				}
			}()
			parsed := p.Parse()
			for _, s := range parsed {
				stmts = append(stmts, s)
			}
		}()
		
		if len(stmts) == 0 {
			continue
		}
		
		// Compile with debug information
		c := compiler.NewStmtCompilerWithDebug(testFile)
		chunk := c.Compile(stmts)
		
		// Create VM (testing functions are already included in stdlib)
		enhancedVM := vm.NewEnhancedVM(chunk)
		
		// Run the test file
		_, err = enhancedVM.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error running tests in %s: %v\n", testFile, err)
		}
	}
	
	// Run all collected tests
	// Note: In a full implementation, tests would be collected during VM execution
	// and then run here. For now, we'll just show the summary.
	fmt.Println("\n✅ Test execution completed")
}

func showUsage() {
	fmt.Println("Sentra - Security Automation Language")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  sentra run <file.sn>       Run a Sentra script")
	fmt.Println("  sentra debug <file.sn>     Debug a Sentra script with breakpoints")
	fmt.Println("  sentra test [files...]     Run test files (*_test.sn)")
	fmt.Println("  sentra repl                Start interactive REPL")
	fmt.Println()
	fmt.Println("Project Management:")
	fmt.Println("  sentra init [name]         Initialize a new Sentra project")
	fmt.Println("  sentra build               Build the project")
	fmt.Println("  sentra watch               Watch and rebuild on changes")
	fmt.Println("  sentra clean               Clean build artifacts")
	fmt.Println()
	fmt.Println("Package Management:")
	fmt.Println("  sentra mod init <path>     Initialize a new module")
	fmt.Println("  sentra get <package>       Add a dependency")
	fmt.Println("  sentra get -u [packages]   Update dependencies")
	fmt.Println("  sentra mod download        Download all dependencies")
	fmt.Println("  sentra mod tidy            Clean up dependencies")
	fmt.Println("  sentra mod vendor          Copy dependencies to vendor/")
	fmt.Println("  sentra mod list            List all dependencies")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  sentra init my-scanner")
	fmt.Println("  sentra run scanner.sn")
	fmt.Println("  sentra build")
	fmt.Println("  sentra mod init github.com/user/project")
	fmt.Println("  sentra get github.com/sentra-security/network@latest")
}

func handlePackageCommands(args []string) {
	pm := packages.NewPackageManager("")
	
	if len(args) < 2 {
		showUsage()
		return
	}
	
	switch args[0] {
	case "mod":
		switch args[1] {
		case "init":
			if len(args) < 3 {
				fmt.Println("Error: module path required")
				fmt.Println("Usage: sentra mod init <module-path>")
				return
			}
			if err := pm.InitModule(args[2]); err != nil {
				log.Fatalf("Error: %v", err)
			}
			
		case "download":
			if err := pm.DownloadDependencies(); err != nil {
				log.Fatalf("Error: %v", err)
			}
			
		case "tidy":
			if err := pm.TidyModules(); err != nil {
				log.Fatalf("Error: %v", err)
			}
			
		case "vendor":
			if err := pm.VendorDependencies(); err != nil {
				log.Fatalf("Error: %v", err)
			}
			
		case "list":
			if err := pm.ListPackages(); err != nil {
				log.Fatalf("Error: %v", err)
			}
			
		default:
			fmt.Printf("Unknown mod command: %s\n", args[1])
			showUsage()
		}
		
	case "get":
		if args[1] == "-u" {
			// Update packages
			packages := args[2:]
			if err := pm.UpdatePackages(packages); err != nil {
				log.Fatalf("Error: %v", err)
			}
		} else {
			// Get package
			packagePath := args[1]
			version := "latest"
			
			// Check for version specification
			if strings.Contains(packagePath, "@") {
				parts := strings.Split(packagePath, "@")
				packagePath = parts[0]
				version = parts[1]
			}
			
			if err := pm.GetPackage(packagePath, version); err != nil {
				log.Fatalf("Error: %v", err)
			}
		}
	}
}

func showVersion() {
	fmt.Printf("Sentra Programming Language v%s\n", VERSION)
	fmt.Printf("Build Date: %s\n", BuildDate)
	
	// Try to get git commit if we're in a repo
	if gitCmd, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output(); err == nil {
		GitCommit = strings.TrimSpace(string(gitCmd))
	}
	
	if GitCommit != "unknown" {
		fmt.Printf("Git Commit: %s\n", GitCommit)
	}
	
	// Check for dev environment
	if devPath := os.Getenv("SENTRA_DEV_PATH"); devPath != "" {
		fmt.Printf("Dev Path: %s\n", devPath)
	}
	
	fmt.Println("Code with Confidence! 🚀")
}

func updateSentra() {
	fmt.Println("🔄 Updating Sentra to latest version...")
	
	// Check if using dev path
	if devPath := os.Getenv("SENTRA_DEV_PATH"); devPath != "" {
		fmt.Printf("📦 Using development version from: %s\n", devPath)
		fmt.Println("Please run 'git pull' in your development directory")
		return
	}
	
	// Determine installation directory
	installDir := os.Getenv("SENTRA_INSTALL_DIR")
	if installDir == "" {
		homeDir, _ := os.UserHomeDir()
		installDir = filepath.Join(homeDir, ".sentra")
	}
	
	// Check if it's a git repository
	gitDir := filepath.Join(installDir, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		fmt.Println("Please run the installer to update:")
		fmt.Println("  curl -sSL https://raw.githubusercontent.com/sentra-language/sentra/main/install.sh | bash")
		return
	}
	
	// Save current directory
	currentDir, _ := os.Getwd()
	defer os.Chdir(currentDir)
	
	// Change to install directory
	if err := os.Chdir(installDir); err != nil {
		log.Fatalf("Error: %v", err)
	}
	
	// Update from git
	fmt.Printf("📥 Fetching latest from: %s\n", installDir)
	cmd := exec.Command("git", "pull", "origin", "main")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Error: %s\n", output)
		return
	}
	
	// Rebuild
	fmt.Println("🔨 Building new version...")
	cmd = exec.Command("go", "build", "-o", "sentra", "./cmd/sentra")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Error: %s\n", output)
		return
	}
	
	fmt.Println("✅ Successfully updated Sentra!")
	showVersion()
}
