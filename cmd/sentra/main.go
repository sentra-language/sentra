// cmd/sentra/main.go
package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sentra/cmd/sentra/commands"
	"sentra/internal/compiler"
	"sentra/internal/errors"
	"sentra/internal/lexer"
	"sentra/internal/parser"
	"sentra/internal/packages"
	"sentra/internal/repl"
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
		compiler := compiler.NewStmtCompiler()
		chunk := compiler.Compile(stmts)

		// Use the enhanced VM for better performance and features
		enhancedVM := vm.NewEnhancedVM(chunk)
		result, err := enhancedVM.Run()
		if err != nil {
			log.Fatalf("Runtime error: %v", err)
		}
		// Don't print the result unless it's meaningful
		_ = result		
		return
	}

	showUsage()
}

func showUsage() {
	fmt.Println("Sentra - Security Automation Language")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  sentra run <file.sn>       Run a Sentra script")
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
