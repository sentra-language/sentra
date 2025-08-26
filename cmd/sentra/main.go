// cmd/sentra/main.go
package main

import (
	"fmt"
	"log"
	"os"
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
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		showUsage()
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
		// Filter out optimization flags from file arguments
		var filename string
		for _, arg := range args[1:] {
			if arg != "--production" && arg != "-p" && arg != "--fast" && arg != "-f" && 
			   arg != "--hotfix" && arg != "-h" && arg != "--super" && arg != "-s" &&
			   arg != "--stackfix" && arg != "--sf" {
				filename = arg
				break
			}
		}
		if filename == "" {
			log.Fatal("No filename provided to run command")
		}
		source, err := os.ReadFile(filename)
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
		scanner := lexer.NewScannerWithFile(string(fullSource), filename)
		tokens := scanner.ScanTokens()

		// --- And here ---
		// fmt.Println("===== TOKENS =====")
		// for _, t := range tokens {
		// 	fmt.Println(t)
		// }
		// fmt.Println("==================")
		// -----------------------------

		// Create parser with source for error reporting
		p := parser.NewParserWithSource(tokens, string(fullSource), filename)
		
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
		compiler := compiler.NewStmtCompilerWithDebug(filename)
		chunk := compiler.Compile(stmts)

		// Check for optimization flags
		useFastVM := false
		useHotfixVM := false
		useSuperVM := false
		useStackFixVM := false
		
		for _, arg := range os.Args {
			if arg == "--fast" || arg == "-f" {
				useFastVM = true
				break
			}
			if arg == "--hotfix" || arg == "-h" {
				useHotfixVM = true
				break
			}
			if arg == "--super" || arg == "-s" {
				useSuperVM = true
				break
			}
			if arg == "--stackfix" || arg == "--sf" {
				useStackFixVM = true
				break
			}
		}
		
		// Use optimized VM variants or enhanced VM for full features
		var result interface{}
		
		if useStackFixVM {
			stackFixVM := vm.NewStackFixVM(chunk)
			result, err = stackFixVM.StackFixRun()
		} else if useSuperVM {
			superVM := vm.NewSuperVM(chunk)
			result, err = superVM.SuperRun()
		} else if useHotfixVM {
			hotfixVM := vm.NewHotfixVM(chunk)
			result, err = hotfixVM.HotfixRun()
		} else if useFastVM {
			fastVM := vm.NewFastVM(chunk)
			result, err = fastVM.OptimizedRun()
		} else {
			enhancedVM := vm.NewEnhancedVM(chunk)
			result, err = enhancedVM.Run()
		}
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
		
		// Create VM with testing module
		enhancedVM := vm.NewEnhancedVM(chunk)
		
		// Add testing functions to VM
		for name, fn := range testing.GetSimpleTestFunctions() {
			enhancedVM.AddBuiltinFunction(name, fn)
		}
		
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
