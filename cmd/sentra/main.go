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
	"sentra/internal/formatter"
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

	if args[0] == "check" && len(args) > 1 {
		checkSyntax(args[1])
		return
	}

	if args[0] == "fmt" && len(args) > 1 {
		formatCode(args[1])
		return
	}

	if args[0] == "lint" && len(args) > 1 {
		lintCode(args[1])
		return
	}

	if args[0] == "doc" {
		generateDocs(args[1:])
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
		var stmts []parser.Stmt
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
			stmts = p.Parse()
		}()
		// Use hoisting compiler for proper function hoisting
		hc := compiler.NewHoistingCompilerWithDebug(filename)
		chunk := hc.CompileWithHoisting(stmts)

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
			enhancedVM.SetFilePath(filename)
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

func checkSyntax(filename string) {
	source, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Create scanner with file information
	scanner := lexer.NewScannerWithFile(string(source), filename)
	tokens := scanner.ScanTokens()

	// Check for lexer errors
	if scanner.HadError() {
		fmt.Fprintf(os.Stderr, "Syntax errors found in %s\n", filename)
		os.Exit(1)
	}

	// Create parser with source for error reporting
	p := parser.NewParserWithSource(tokens, string(source), filename)
	
	// Try to parse
	func() {
		defer func() {
			if r := recover(); r != nil {
				if err, ok := r.(*errors.SentraError); ok {
					fmt.Fprintf(os.Stderr, "%s\n", err.Error())
					os.Exit(1)
				} else if err, ok := r.(error); ok {
					fmt.Fprintf(os.Stderr, "Syntax error: %v\n", err)
					os.Exit(1)
				} else {
					fmt.Fprintf(os.Stderr, "Syntax error: %v\n", r)
					os.Exit(1)
				}
			}
		}()
		p.Parse()
	}()

	// If we get here, syntax is valid
	fmt.Printf("%s: syntax is valid\n", filename)
	os.Exit(0)
}

func lintCode(filename string) {
	source, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Parse the code
	scanner := lexer.NewScannerWithFile(string(source), filename)
	tokens := scanner.ScanTokens()
	
	if scanner.HadError() {
		fmt.Fprintf(os.Stderr, "Syntax errors found, cannot lint\n")
		os.Exit(1)
	}

	p := parser.NewParserWithSource(tokens, string(source), filename)
	
	var stmts []parser.Stmt
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Parse error: %v\n", r)
				os.Exit(1)
			}
		}()
		stmts = p.Parse()
	}()

	// Perform linting checks
	warnings := 0
	errors := 0
	
	// Check for unused variables (simplified)
	declaredVars := make(map[string]bool)
	usedVars := make(map[string]bool)
	
	// Walk through statements to find declarations and usage
	var walkStmt func(parser.Stmt)
	var walkExpr func(parser.Expr)
	
	walkExpr = func(expr parser.Expr) {
		if expr == nil {
			return
		}
		switch e := expr.(type) {
		case *parser.Variable:
			usedVars[e.Name] = true
		case *parser.Binary:
			walkExpr(e.Left)
			walkExpr(e.Right)
		case *parser.CallExpr:
			walkExpr(e.Callee)
			for _, arg := range e.Args {
				walkExpr(arg)
			}
		case *parser.Assign:
			// Assignment uses the variable
			usedVars[e.Name] = true
			walkExpr(e.Value)
		}
	}
	
	walkStmt = func(stmt parser.Stmt) {
		switch s := stmt.(type) {
		case *parser.LetStmt:
			declaredVars[s.Name] = true
			walkExpr(s.Expr)
		case *parser.FunctionStmt:
			// Don't check function names as unused
			for _, bodyStmt := range s.Body {
				walkStmt(bodyStmt)
			}
		case *parser.ExpressionStmt:
			walkExpr(s.Expr)
		case *parser.IfStmt:
			walkExpr(s.Condition)
			for _, thenStmt := range s.Then {
				walkStmt(thenStmt)
			}
			for _, elseStmt := range s.Else {
				walkStmt(elseStmt)
			}
		case *parser.WhileStmt:
			walkExpr(s.Condition)
			for _, bodyStmt := range s.Body {
				walkStmt(bodyStmt)
			}
		case *parser.ReturnStmt:
			walkExpr(s.Value)
		}
	}
	
	for _, stmt := range stmts {
		walkStmt(stmt)
	}
	
	// Report unused variables
	for varName := range declaredVars {
		if !usedVars[varName] && !strings.HasPrefix(varName, "_") {
			fmt.Printf("Warning: Variable '%s' is declared but never used\n", varName)
			warnings++
		}
	}
	
	// Check for other issues
	// TODO: Add more linting rules
	
	if errors > 0 {
		fmt.Printf("\n%s: %d errors, %d warnings\n", filename, errors, warnings)
		os.Exit(1)
	} else if warnings > 0 {
		fmt.Printf("\n%s: %d warnings\n", filename, warnings)
	} else {
		fmt.Printf("%s: no issues found\n", filename)
	}
}

func generateDocs(args []string) {
	// Parse options
	outputDir := "./docs"
	var files []string
	
	for i := 0; i < len(args); i++ {
		if args[i] == "-o" || args[i] == "--output" {
			if i+1 < len(args) {
				outputDir = args[i+1]
				i++ // Skip next arg
			}
		} else if strings.HasSuffix(args[i], ".sn") {
			files = append(files, args[i])
		}
	}
	
	// If no files specified, find all .sn files
	if len(files) == 0 {
		matches, err := filepath.Glob("*.sn")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error finding files: %v\n", err)
			os.Exit(1)
		}
		files = matches
	}
	
	if len(files) == 0 {
		fmt.Println("No Sentra files found to document")
		return
	}
	
	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}
	
	// Generate documentation for each file
	for _, file := range files {
		generateFileDoc(file, outputDir)
	}
	
	// Generate index
	generateIndexDoc(files, outputDir)
	
	fmt.Printf("Documentation generated in %s\n", outputDir)
}

func generateFileDoc(filename, outputDir string) {
	source, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", filename, err)
		return
	}
	
	scanner := lexer.NewScannerWithFile(string(source), filename)
	tokens := scanner.ScanTokens()
	
	if scanner.HadError() {
		fmt.Fprintf(os.Stderr, "Syntax errors in %s, skipping\n", filename)
		return
	}
	
	p := parser.NewParserWithSource(tokens, string(source), filename)
	
	var stmts []parser.Stmt
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Parse error in %s: %v\n", filename, r)
			}
		}()
		stmts = p.Parse()
	}()
	
	// Extract documentation
	var doc strings.Builder
	doc.WriteString("# " + filepath.Base(filename) + "\n\n")
	
	// Extract functions
	var functions []string
	var walkStmt func(parser.Stmt)
	
	walkStmt = func(stmt parser.Stmt) {
		switch s := stmt.(type) {
		case *parser.FunctionStmt:
			sig := fmt.Sprintf("fn %s(%s)", s.Name, strings.Join(s.Params, ", "))
			functions = append(functions, sig)
		}
	}
	
	for _, stmt := range stmts {
		walkStmt(stmt)
	}
	
	if len(functions) > 0 {
		doc.WriteString("## Functions\n\n")
		for _, fn := range functions {
			doc.WriteString("- `" + fn + "`\n")
		}
		doc.WriteString("\n")
	}
	
	// Write to file
	outFile := filepath.Join(outputDir, strings.TrimSuffix(filepath.Base(filename), ".sn") + ".md")
	if err := os.WriteFile(outFile, []byte(doc.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing doc for %s: %v\n", filename, err)
	}
}

func generateIndexDoc(files []string, outputDir string) {
	var doc strings.Builder
	doc.WriteString("# Sentra Documentation\n\n")
	doc.WriteString("## Files\n\n")
	
	for _, file := range files {
		base := filepath.Base(file)
		mdFile := strings.TrimSuffix(base, ".sn") + ".md"
		doc.WriteString(fmt.Sprintf("- [%s](%s)\n", base, mdFile))
	}
	
	indexFile := filepath.Join(outputDir, "index.md")
	if err := os.WriteFile(indexFile, []byte(doc.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing index: %v\n", err)
	}
}

func formatCode(filename string) {
	source, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Parse the code first to ensure it's valid
	scanner := lexer.NewScannerWithFile(string(source), filename)
	tokens := scanner.ScanTokens()
	
	if scanner.HadError() {
		fmt.Fprintf(os.Stderr, "Cannot format file with syntax errors\n")
		os.Exit(1)
	}

	p := parser.NewParserWithSource(tokens, string(source), filename)
	
	var stmts []parser.Stmt
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Cannot format file with syntax errors: %v\n", r)
				os.Exit(1)
			}
		}()
		stmts = p.Parse()
	}()

	// Format the code
	formatter := formatter.NewFormatter()
	formatted := formatter.Format(stmts)
	
	// Write the formatted code back to the file
	if err := os.WriteFile(filename, []byte(formatted), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing formatted file: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("%s: formatted successfully\n", filename)
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
	enhancedVM.SetFilePath(filename)
	debug := debugger.NewDebugger(enhancedVM)
	
	// Load source for debugging
	debug.LoadSourceFile(filename, string(source))
	
	// Create debug hook and attach to VM
	hook := debugger.NewVMDebugHook(debug)
	enhancedVM.SetDebugHook(hook)
	
	fmt.Printf("Starting Sentra debugger for: %s\n", filename)
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
	fmt.Println("\nProgram execution completed")
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
	
	fmt.Printf("Running %d test file(s)...\n", len(testFiles))
	
	// Create test runner (not used in simplified version)
	// config := &testing.TestConfig{
	// 	Verbose:      true,
	// 	OutputFormat: "text",
	// 	FailFast:     false,
	// }
	// runner := testing.NewTestRunner(config)
	
	// Process each test file
	for _, testFile := range testFiles {
		fmt.Printf("\nLoading test file: %s\n", testFile)
		
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
		enhancedVM.SetFilePath(testFile)
		
		// Run the test file
		_, err = enhancedVM.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error running tests in %s: %v\n", testFile, err)
		}
	}
	
	// Run all collected tests
	// Note: In a full implementation, tests would be collected during VM execution
	// and then run here. For now, we'll just show the summary.
	fmt.Println("\nTest execution completed")
}

func showUsage() {
	fmt.Println("Sentra - Security Automation Language")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  sentra run <file.sn>       Run a Sentra script")
	fmt.Println("  sentra check <file.sn>     Check syntax without running")
	fmt.Println("  sentra lint <file.sn>      Check for code quality issues")
	fmt.Println("  sentra fmt <file.sn>       Format Sentra code")
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
	
	fmt.Println("Code with Confidence!")
}

func updateSentra() {
	fmt.Println("Updating Sentra to latest version...")
	
	// Check if using dev path
	if devPath := os.Getenv("SENTRA_DEV_PATH"); devPath != "" {
		fmt.Printf("Using development version from: %s\n", devPath)
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
	fmt.Printf("Fetching latest from: %s\n", installDir)
	cmd := exec.Command("git", "pull", "origin", "main")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Error: %s\n", output)
		return
	}
	
	// Rebuild
	fmt.Println("Building new version...")
	cmd = exec.Command("go", "build", "-o", "sentra", "./cmd/sentra")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Error: %s\n", output)
		return
	}
	
	fmt.Println("Successfully updated Sentra!")
	showVersion()
}
