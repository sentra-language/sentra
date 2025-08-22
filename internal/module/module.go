package module

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"
	"sentra/internal/parser"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/vm"
	// "sentra/internal/bytecode" // Unused import
)

// ModuleLoader handles loading and caching of modules
type ModuleLoader struct {
	cache      map[string]*vm.Module
	searchPath []string
	mu         sync.RWMutex
	stdlib     map[string]*vm.NativeFunction
}

// NewModuleLoader creates a new module loader
func NewModuleLoader() *ModuleLoader {
	return &ModuleLoader{
		cache:      make(map[string]*vm.Module),
		searchPath: getDefaultSearchPath(),
		stdlib:     make(map[string]*vm.NativeFunction), // Initialize empty for now
	}
}

// getDefaultSearchPath returns the default module search paths
func getDefaultSearchPath() []string {
	return []string{
		".",                    // Current directory
		"./lib",                // Local lib directory
		"./modules",            // Local modules directory
		getStandardLibPath(),   // System standard library
	}
}

// getStandardLibPath returns the path to the standard library
func getStandardLibPath() string {
	// In production, this would be determined by installation location
	return filepath.Join(".", "stdlib")
}

// LoadModule loads a module by name or path
func (ml *ModuleLoader) LoadModule(name string) (*vm.Module, error) {
	// Check if it's a built-in module
	if mod := ml.loadBuiltinModule(name); mod != nil {
		return mod, nil
	}
	
	// Check cache first
	ml.mu.RLock()
	if cached, exists := ml.cache[name]; exists {
		ml.mu.RUnlock()
		return cached, nil
	}
	ml.mu.RUnlock()
	
	// Find the module file
	modulePath, err := ml.findModule(name)
	if err != nil {
		return nil, err
	}
	
	// Load and compile the module
	mod, err := ml.loadAndCompile(name, modulePath)
	if err != nil {
		return nil, err
	}
	
	// Cache the module
	ml.mu.Lock()
	ml.cache[name] = mod
	ml.mu.Unlock()
	
	return mod, nil
}

// loadBuiltinModule loads a built-in module
func (ml *ModuleLoader) loadBuiltinModule(name string) *vm.Module {
	switch name {
	case "math":
		return ml.createMathModule()
	case "string":
		return ml.createStringModule()
	case "array":
		return ml.createArrayModule()
	case "io":
		return ml.createIOModule()
	case "os":
		return ml.createOSModule()
	case "json":
		return ml.createJSONModule()
	case "http":
		return ml.createHTTPModule()
	case "time":
		return ml.createTimeModule()
	case "regex":
		return ml.createRegexModule()
	default:
		return nil
	}
}

// createMathModule creates the math module
func (ml *ModuleLoader) createMathModule() *vm.Module {
	exports := make(map[string]vm.Value)
	
	// Math constants
	exports["PI"] = 3.141592653589793
	exports["E"] = 2.718281828459045
	exports["TAU"] = 6.283185307179586
	
	// Math functions
	mathFuncs := []string{
		"abs", "ceil", "floor", "round", "sqrt", "pow",
		"sin", "cos", "tan", "min", "max", "random", "randint",
	}
	
	for _, fn := range mathFuncs {
		if nativeFn, exists := ml.stdlib[fn]; exists {
			exports[fn] = nativeFn
		}
	}
	
	return &vm.Module{
		Name:    "math",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}
}

// createStringModule creates the string module
func (ml *ModuleLoader) createStringModule() *vm.Module {
	exports := make(map[string]vm.Value)
	
	stringFuncs := []string{
		"upper", "lower", "trim", "split", "join", "replace",
		"contains", "startswith", "endswith", "substring",
	}
	
	for _, fn := range stringFuncs {
		if nativeFn, exists := ml.stdlib[fn]; exists {
			exports[fn] = nativeFn
		}
	}
	
	return &vm.Module{
		Name:    "string",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}
}

// createArrayModule creates the array module
func (ml *ModuleLoader) createArrayModule() *vm.Module {
	exports := make(map[string]vm.Value)
	
	arrayFuncs := []string{
		"push", "pop", "shift", "unshift", "slice",
		"reverse", "sort", "map", "filter",
	}
	
	for _, fn := range arrayFuncs {
		if nativeFn, exists := ml.stdlib[fn]; exists {
			exports[fn] = nativeFn
		}
	}
	
	return &vm.Module{
		Name:    "array",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}
}

// createIOModule creates the I/O module
func (ml *ModuleLoader) createIOModule() *vm.Module {
	exports := make(map[string]vm.Value)
	
	ioFuncs := []string{
		"readfile", "writefile", "appendfile", "exists",
		"isdir", "listdir", "mkdir", "remove", "rename", "abspath",
	}
	
	for _, fn := range ioFuncs {
		if nativeFn, exists := ml.stdlib[fn]; exists {
			exports[fn] = nativeFn
		}
	}
	
	return &vm.Module{
		Name:    "io",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}
}

// createOSModule creates the OS module
func (ml *ModuleLoader) createOSModule() *vm.Module {
	exports := make(map[string]vm.Value)
	
	osFuncs := []string{
		"exit", "getenv", "setenv",
	}
	
	for _, fn := range osFuncs {
		if nativeFn, exists := ml.stdlib[fn]; exists {
			exports[fn] = nativeFn
		}
	}
	
	return &vm.Module{
		Name:    "os",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}
}

// createJSONModule creates the JSON module
func (ml *ModuleLoader) createJSONModule() *vm.Module {
	exports := make(map[string]vm.Value)
	
	jsonFuncs := []string{
		"json_encode", "json_decode",
	}
	
	for _, fn := range jsonFuncs {
		if nativeFn, exists := ml.stdlib[fn]; exists {
			exports[fn] = nativeFn
		}
	}
	
	// Rename for cleaner API
	if encode, exists := exports["json_encode"]; exists {
		exports["encode"] = encode
		delete(exports, "json_encode")
	}
	if decode, exists := exports["json_decode"]; exists {
		exports["decode"] = decode
		delete(exports, "json_decode")
	}
	
	return &vm.Module{
		Name:    "json",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}
}

// createHTTPModule creates the HTTP module
func (ml *ModuleLoader) createHTTPModule() *vm.Module {
	exports := make(map[string]vm.Value)
	
	httpFuncs := []string{
		"http_get", "http_post",
	}
	
	for _, fn := range httpFuncs {
		if nativeFn, exists := ml.stdlib[fn]; exists {
			exports[fn] = nativeFn
		}
	}
	
	// Rename for cleaner API
	if get, exists := exports["http_get"]; exists {
		exports["get"] = get
		delete(exports, "http_get")
	}
	if post, exists := exports["http_post"]; exists {
		exports["post"] = post
		delete(exports, "http_post")
	}
	
	return &vm.Module{
		Name:    "http",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}
}

// createTimeModule creates the time module
func (ml *ModuleLoader) createTimeModule() *vm.Module {
	exports := make(map[string]vm.Value)
	
	timeFuncs := []string{
		"time", "sleep", "date", "datetime",
	}
	
	for _, fn := range timeFuncs {
		if nativeFn, exists := ml.stdlib[fn]; exists {
			exports[fn] = nativeFn
		}
	}
	
	return &vm.Module{
		Name:    "time",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}
}

// createRegexModule creates the regex module
func (ml *ModuleLoader) createRegexModule() *vm.Module {
	exports := make(map[string]vm.Value)
	
	regexFuncs := []string{
		"regex_match", "regex_find", "regex_replace",
	}
	
	for _, fn := range regexFuncs {
		if nativeFn, exists := ml.stdlib[fn]; exists {
			exports[fn] = nativeFn
		}
	}
	
	// Rename for cleaner API
	if match, exists := exports["regex_match"]; exists {
		exports["match"] = match
		delete(exports, "regex_match")
	}
	if find, exists := exports["regex_find"]; exists {
		exports["find"] = find
		delete(exports, "regex_find")
	}
	if replace, exists := exports["regex_replace"]; exists {
		exports["replace"] = replace
		delete(exports, "regex_replace")
	}
	
	return &vm.Module{
		Name:    "regex",
		Path:    "<builtin>",
		Exports: exports,
		Loaded:  true,
	}
}

// findModule finds a module file in the search path
func (ml *ModuleLoader) findModule(name string) (string, error) {
	// Direct file path
	if strings.HasSuffix(name, ".sn") {
		if fileExists(name) {
			return name, nil
		}
		return "", fmt.Errorf("module file not found: %s", name)
	}
	
	// Search in paths
	for _, searchDir := range ml.searchPath {
		// Try as direct file
		path := filepath.Join(searchDir, name+".sn")
		if fileExists(path) {
			return path, nil
		}
		
		// Try as directory with index.sn
		path = filepath.Join(searchDir, name, "index.sn")
		if fileExists(path) {
			return path, nil
		}
		
		// Try as nested module path (e.g., "collections/list" -> "collections/list.sn")
		parts := strings.Split(name, "/")
		path = filepath.Join(searchDir, filepath.Join(parts...)+".sn")
		if fileExists(path) {
			return path, nil
		}
	}
	
	return "", fmt.Errorf("module not found: %s", name)
}

// loadAndCompile loads and compiles a module file
func (ml *ModuleLoader) loadAndCompile(name, path string) (*vm.Module, error) {
	// Read the file
	source, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read module %s: %w", name, err)
	}
	
	// Parse the source
	scanner := lexer.NewScanner(string(source))
	tokens := scanner.ScanTokens()
	
	p := parser.NewParser(tokens)
	stmts := p.Parse()
	
	if len(p.Errors) > 0 {
		return nil, fmt.Errorf("parse errors in module %s: %v", name, p.Errors)
	}
	
	// Convert []Stmt to []interface{} for compiler
	stmtInterfaces := make([]interface{}, len(stmts))
	for i, stmt := range stmts {
		stmtInterfaces[i] = stmt
	}
	
	// Compile to bytecode
	comp := compiler.NewStmtCompiler()
	chunk := comp.Compile(stmtInterfaces)
	
	// Create module
	mod := &vm.Module{
		Name:    name,
		Path:    path,
		Exports: make(map[string]vm.Value),
		Globals: make([]vm.Value, 0),
		Loaded:  false,
	}
	
	// Execute module to populate exports
	// This would require running the module in a special context
	// For now, we'll mark it as loaded
	mod.Loaded = true
	
	// Store the compiled chunk for later execution
	if fn, ok := chunk.Constants[0].(*compiler.Function); ok {
		mod.Exports["__init__"] = &vm.Function{
			Name:  "__init__",
			Arity: 0,
			Chunk: fn.Chunk,
		}
	}
	
	return mod, nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := ioutil.ReadFile(path)
	return err == nil
}

// AddSearchPath adds a directory to the module search path
func (ml *ModuleLoader) AddSearchPath(path string) {
	ml.searchPath = append(ml.searchPath, path)
}

// GetSearchPath returns the current search path
func (ml *ModuleLoader) GetSearchPath() []string {
	return ml.searchPath
}

// ClearCache clears the module cache
func (ml *ModuleLoader) ClearCache() {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	ml.cache = make(map[string]*vm.Module)
}