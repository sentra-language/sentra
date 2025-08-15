// internal/build/linker.go
package build

import (
	"fmt"
	"os"
	"path/filepath"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
	"strings"
)

// ModuleGraph represents the dependency graph of modules
type ModuleGraph struct {
	Modules      map[string]*ModuleNode
	EntryPoint   string
	ResolveOrder []string
}

// ModuleNode represents a module in the dependency graph
type ModuleNode struct {
	Path         string
	FullPath     string
	Source       string
	AST          []parser.Stmt
	Dependencies []string
	Exports      map[string]parser.Stmt
	Compiled     bool
	Bytecode     []byte
}

// ImportResolver resolves and links imports
type ImportResolver struct {
	projectRoot string
	graph       *ModuleGraph
	visited     map[string]bool
	resolving   map[string]bool // For circular dependency detection
}

// NewImportResolver creates a new import resolver
func NewImportResolver(projectRoot string) *ImportResolver {
	return &ImportResolver{
		projectRoot: projectRoot,
		graph: &ModuleGraph{
			Modules: make(map[string]*ModuleNode),
		},
		visited:   make(map[string]bool),
		resolving: make(map[string]bool),
	}
}

// ResolveProject resolves all imports starting from the entry point
func (r *ImportResolver) ResolveProject(entryPoint string) (*ModuleGraph, error) {
	r.graph.EntryPoint = entryPoint
	
	// Start resolution from entry point
	if err := r.resolveModule(entryPoint, nil); err != nil {
		return nil, fmt.Errorf("failed to resolve entry point: %w", err)
	}
	
	// Perform topological sort to get compilation order
	if err := r.topologicalSort(); err != nil {
		return nil, fmt.Errorf("failed to sort modules: %w", err)
	}
	
	return r.graph, nil
}

// resolveModule recursively resolves a module and its dependencies
func (r *ImportResolver) resolveModule(modulePath string, importedFrom *ModuleNode) error {
	// Normalize the module path
	normalizedPath := r.normalizeModulePath(modulePath, importedFrom)
	
	// Check for circular dependencies
	if r.resolving[normalizedPath] {
		return fmt.Errorf("circular dependency detected: %s", normalizedPath)
	}
	
	// Skip if already resolved
	if r.visited[normalizedPath] {
		return nil
	}
	
	r.resolving[normalizedPath] = true
	defer func() { delete(r.resolving, normalizedPath) }()
	
	// Load the module
	module, err := r.loadModule(normalizedPath)
	if err != nil {
		return fmt.Errorf("failed to load module %s: %w", normalizedPath, err)
	}
	
	// Parse the module
	if err := r.parseModule(module); err != nil {
		return fmt.Errorf("failed to parse module %s: %w", normalizedPath, err)
	}
	
	// Extract imports and exports
	r.extractImportsAndExports(module)
	
	// Add to graph
	r.graph.Modules[normalizedPath] = module
	r.visited[normalizedPath] = true
	
	// Recursively resolve dependencies
	for _, dep := range module.Dependencies {
		if err := r.resolveModule(dep, module); err != nil {
			return fmt.Errorf("failed to resolve dependency %s: %w", dep, err)
		}
	}
	
	return nil
}

// normalizeModulePath converts a module path to an absolute path
func (r *ImportResolver) normalizeModulePath(modulePath string, importedFrom *ModuleNode) string {
	// Handle built-in modules
	if strings.HasPrefix(modulePath, "sentra/") {
		return modulePath
	}
	
	// Handle relative imports
	if strings.HasPrefix(modulePath, "./") || strings.HasPrefix(modulePath, "../") {
		if importedFrom != nil {
			base := filepath.Dir(importedFrom.FullPath)
			resolved := filepath.Join(base, modulePath)
			resolved = filepath.Clean(resolved)
			
			// Make relative to project root
			rel, _ := filepath.Rel(r.projectRoot, resolved)
			return rel
		}
	}
	
	// Handle absolute imports from project root
	if !strings.HasSuffix(modulePath, ".sn") {
		modulePath += ".sn"
	}
	
	return modulePath
}

// loadModule loads a module from disk
func (r *ImportResolver) loadModule(modulePath string) (*ModuleNode, error) {
	// Check if it's a built-in module
	if strings.HasPrefix(modulePath, "sentra/") {
		return r.loadBuiltinModule(modulePath)
	}
	
	// Construct full path
	fullPath := filepath.Join(r.projectRoot, modulePath)
	
	// Try with .sn extension if not present
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		if !strings.HasSuffix(fullPath, ".sn") {
			fullPath += ".sn"
			modulePath += ".sn"
		}
	}
	
	// Read the source file
	source, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}
	
	return &ModuleNode{
		Path:     modulePath,
		FullPath: fullPath,
		Source:   string(source),
		Exports:  make(map[string]parser.Stmt),
	}, nil
}

// loadBuiltinModule loads a built-in module (stub for now)
func (r *ImportResolver) loadBuiltinModule(modulePath string) (*ModuleNode, error) {
	// Built-in modules are provided by the runtime
	// We create a stub module that the VM will recognize
	
	builtinSource := fmt.Sprintf("// Built-in module: %s\n// Provided by runtime", modulePath)
	
	return &ModuleNode{
		Path:     modulePath,
		FullPath: modulePath,
		Source:   builtinSource,
		Exports:  make(map[string]parser.Stmt),
		Compiled: true, // Built-ins are pre-compiled
	}, nil
}

// parseModule parses a module's source code
func (r *ImportResolver) parseModule(module *ModuleNode) error {
	// Skip built-in modules
	if strings.HasPrefix(module.Path, "sentra/") {
		return nil
	}
	
	// Lex the source
	scanner := lexer.NewScanner(module.Source)
	tokens := scanner.ScanTokens()
	
	// Parse to AST
	p := parser.NewParser(tokens)
	module.AST = p.Parse()
	
	if len(p.Errors) > 0 {
		return fmt.Errorf("parse errors: %v", p.Errors)
	}
	
	return nil
}

// extractImportsAndExports extracts import and export information from AST
func (r *ImportResolver) extractImportsAndExports(module *ModuleNode) {
	module.Dependencies = []string{}
	
	for _, stmt := range module.AST {
		switch s := stmt.(type) {
		case *parser.ImportStmt:
			// Add to dependencies
			module.Dependencies = append(module.Dependencies, s.Path)
			
		case *parser.FunctionStmt:
			// Functions are automatically exported if they start with uppercase
			if len(s.Name) > 0 && s.Name[0] >= 'A' && s.Name[0] <= 'Z' {
				module.Exports[s.Name] = s
			}
			// Or if explicitly marked with export comment
			// TODO: Add export annotation support
		}
	}
}

// topologicalSort performs a topological sort on the module graph
func (r *ImportResolver) topologicalSort() error {
	sorted := []string{}
	visited := make(map[string]bool)
	visiting := make(map[string]bool)
	
	var visit func(string) error
	visit = func(path string) error {
		if visited[path] {
			return nil
		}
		
		if visiting[path] {
			return fmt.Errorf("circular dependency detected during sort: %s", path)
		}
		
		visiting[path] = true
		
		module := r.graph.Modules[path]
		if module != nil {
			for _, dep := range module.Dependencies {
				normalizedDep := r.normalizeModulePath(dep, module)
				if err := visit(normalizedDep); err != nil {
					return err
				}
			}
		}
		
		visiting[path] = false
		visited[path] = true
		sorted = append(sorted, path)
		
		return nil
	}
	
	// Start with entry point
	if err := visit(r.graph.EntryPoint); err != nil {
		return err
	}
	
	// Visit any remaining modules
	for path := range r.graph.Modules {
		if err := visit(path); err != nil {
			return err
		}
	}
	
	r.graph.ResolveOrder = sorted
	return nil
}

// LinkModules links all modules into a single bytecode bundle
func LinkModules(graph *ModuleGraph) ([]byte, error) {
	// Create a combined AST with imports resolved
	combinedAST := []parser.Stmt{}
	
	// Track what has been imported
	imported := make(map[string]bool)
	
	// Process modules in dependency order
	for _, modulePath := range graph.ResolveOrder {
		module := graph.Modules[modulePath]
		
		// Skip built-in modules
		if strings.HasPrefix(module.Path, "sentra/") {
			continue
		}
		
		// Skip if already imported
		if imported[modulePath] {
			continue
		}
		
		// Process the module's AST
		for _, stmt := range module.AST {
			// Skip import statements as they're being resolved
			if _, isImport := stmt.(*parser.ImportStmt); isImport {
				continue
			}
			
			// Add all other statements
			combinedAST = append(combinedAST, stmt)
		}
		
		imported[modulePath] = true
	}
	
	// Compile the combined AST
	c := compiler.NewStmtCompiler()
	for _, stmt := range combinedAST {
		stmt.Accept(c)
	}
	c.Chunk.WriteOp(0) // EOF marker
	
	return c.Chunk.Code, nil
}

// ResolveImportPath resolves an import path to actual file path
func ResolveImportPath(importPath string, currentFile string, projectRoot string) string {
	// Handle built-in modules
	if strings.HasPrefix(importPath, "sentra/") {
		return importPath
	}
	
	// Handle relative imports
	if strings.HasPrefix(importPath, "./") || strings.HasPrefix(importPath, "../") {
		base := filepath.Dir(currentFile)
		resolved := filepath.Join(base, importPath)
		resolved = filepath.Clean(resolved)
		
		// Add .sn extension if not present
		if !strings.HasSuffix(resolved, ".sn") {
			resolved += ".sn"
		}
		
		return resolved
	}
	
	// Handle absolute imports from src directory
	srcPath := filepath.Join(projectRoot, "src", importPath)
	if !strings.HasSuffix(srcPath, ".sn") {
		srcPath += ".sn"
	}
	
	// Check if file exists in src
	if _, err := os.Stat(srcPath); err == nil {
		return srcPath
	}
	
	// Try in project root
	rootPath := filepath.Join(projectRoot, importPath)
	if !strings.HasSuffix(rootPath, ".sn") {
		rootPath += ".sn"
	}
	
	return rootPath
}