package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
)

// ModuleLoader handles loading and caching of file-based modules
type ModuleLoader struct {
	cache       map[string]*Module // Cache of loaded modules
	loading     map[string]bool    // Track modules being loaded (for circular dependency detection)
	searchPaths []string           // Paths to search for modules
	parentVM    *EnhancedVM        // Parent VM for accessing built-in functions
	currentDir  string             // Current directory for relative imports
	mu          sync.RWMutex       // Mutex for thread safety
}

// NewModuleLoader creates a new module loader
func NewModuleLoader(vm *EnhancedVM) *ModuleLoader {
	return &ModuleLoader{
		cache:       make(map[string]*Module),
		loading:     make(map[string]bool),
		searchPaths: []string{".", "./lib", "./node_modules"},
		parentVM:    vm,
		currentDir:  ".", // Default to current working directory
	}
}

// SetCurrentDirectory sets the base directory for relative imports
func (ml *ModuleLoader) SetCurrentDirectory(dir string) {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	ml.currentDir = dir
}

// LoadFileModule loads a .sn file as a module
func (ml *ModuleLoader) LoadFileModule(path string) (*Module, error) {
	
	// Resolve the module path
	resolvedPath, err := ml.resolvePath(path)
	if err != nil {
		return nil, err
	}
	
	// Check if already cached (use read lock for this)
	ml.mu.RLock()
	if mod, exists := ml.cache[resolvedPath]; exists {
		ml.mu.RUnlock()
		return mod, nil
	}
	ml.mu.RUnlock()
	
	// Need write lock for the rest
	ml.mu.Lock()
	// Note: We manually manage unlock/relock during execution
	
	// Check again in case another goroutine loaded it
	if mod, exists := ml.cache[resolvedPath]; exists {
		ml.mu.Unlock()
		return mod, nil
	}
	
	// Check for circular dependencies
	if ml.loading[resolvedPath] {
		ml.mu.Unlock()
		return nil, fmt.Errorf("circular dependency detected: %s", path)
	}
	
	// Mark as loading
	ml.loading[resolvedPath] = true
	defer delete(ml.loading, resolvedPath)
	
	// Read the file
	source, err := os.ReadFile(resolvedPath)
	if err != nil {
		ml.mu.Unlock()
		return nil, fmt.Errorf("failed to read module %s: %v", path, err)
	}
	
	// Parse the source
	scanner := lexer.NewScannerWithFile(string(source), resolvedPath)
	tokens := scanner.ScanTokens()
	
	if scanner.HadError() {
		ml.mu.Unlock()
		return nil, fmt.Errorf("syntax errors in module %s", path)
	}
	
	p := parser.NewParserWithSource(tokens, string(source), resolvedPath)
	
	var stmts []parser.Stmt
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("parse error in module %s: %v", path, r)
			}
		}()
		stmts = p.Parse()
	}()
	
	if err != nil {
		ml.mu.Unlock()
		return nil, err
	}
	
	// Compile the module with function hoisting
	c := compiler.NewHoistingCompilerWithDebug(resolvedPath)
	chunk := c.CompileWithHoisting(stmts)
	
	// Create a new VM instance for the module (isolated context)
	moduleVM := NewEnhancedVM(chunk)
	
	// Module VM will have access to the same built-in functions
	// They are registered in registerBuiltins() during NewEnhancedVM
	
	// Set up module loader for nested imports
	moduleVM.moduleLoader = ml
	
	// Set the current directory for nested imports to the directory of this module
	oldDir := ml.currentDir
	ml.currentDir = filepath.Dir(resolvedPath)
	
	// Create the module
	module := &Module{
		Name:    filepath.Base(resolvedPath),
		Path:    resolvedPath,
		Exports: make(map[string]Value),
		Loaded:  false,
	}
	
	// Set up export tracking in the module VM
	moduleVM.currentModule = module
	
	// Cache the module early (before execution) to prevent circular dependencies
	ml.cache[resolvedPath] = module
	
	// Release the lock during execution (modules might import other modules)
	ml.mu.Unlock()
	
	// Execute the module
	_, err = moduleVM.Run()
	
	// Re-acquire the lock
	ml.mu.Lock()
	
	// Restore the directory
	ml.currentDir = oldDir
	
	if err != nil {
		// Remove from cache on error
		delete(ml.cache, resolvedPath)
		ml.mu.Unlock()
		return nil, fmt.Errorf("error executing module %s: %v", path, err)
	}
	
	// Store module's globals and global map for function context switching
	module.Globals = make([]Value, len(moduleVM.globals))
	copy(module.Globals, moduleVM.globals)
	module.GlobalMap = make(map[string]int)
	for k, v := range moduleVM.globalMap {
		module.GlobalMap[k] = v
	}
	
	for _, value := range module.Exports {
		if fn, ok := value.(*Function); ok {
			fn.Module = module
		}
	}
	
	module.Loaded = true
	
	ml.mu.Unlock() // Final unlock
	return module, nil
}

// resolvePath resolves a module path to an absolute file path
func (ml *ModuleLoader) resolvePath(path string) (string, error) {
	// If path doesn't end with .sn, add it
	if !strings.HasSuffix(path, ".sn") {
		path = path + ".sn"
	}
	
	// Check if it's a relative path
	if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		// Resolve relative to current directory (directory of the executing file)
		relativePath := filepath.Join(ml.currentDir, path)
		absPath, err := filepath.Abs(relativePath)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(absPath); err == nil {
			return absPath, nil
		}
		return "", fmt.Errorf("module not found: %s (resolved to %s)", path, absPath)
	}
	
	// Search in search paths
	for _, searchPath := range ml.searchPaths {
		fullPath := filepath.Join(searchPath, path)
		absPath, err := filepath.Abs(fullPath)
		if err != nil {
			continue
		}
		if _, err := os.Stat(absPath); err == nil {
			return absPath, nil
		}
	}
	
	return "", fmt.Errorf("module not found: %s (searched in %v)", path, ml.searchPaths)
}

// AddSearchPath adds a directory to the module search paths
func (ml *ModuleLoader) AddSearchPath(path string) {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	ml.searchPaths = append(ml.searchPaths, path)
}

// ClearCache clears the module cache
func (ml *ModuleLoader) ClearCache() {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	ml.cache = make(map[string]*Module)
}