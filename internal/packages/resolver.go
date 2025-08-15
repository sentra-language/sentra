package packages

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// ImportResolver handles import resolution for Sentra modules
type ImportResolver struct {
	cache       *ModuleCache
	currentMod  *Module
	searchPaths []string
	imports     map[string]*ResolvedImport
}

// ResolvedImport represents a resolved import
type ResolvedImport struct {
	Path       string
	Alias      string
	SourceFile string
	Module     *CachedModule
	Exports    map[string]interface{}
}

// NewImportResolver creates a new import resolver
func NewImportResolver(cache *ModuleCache) *ImportResolver {
	return &ImportResolver{
		cache:       cache,
		searchPaths: getDefaultSearchPaths(),
		imports:     make(map[string]*ResolvedImport),
	}
}

// getDefaultSearchPaths returns default module search paths
func getDefaultSearchPaths() []string {
	var paths []string
	
	// Current directory
	paths = append(paths, ".")
	
	// Local sentra_modules
	paths = append(paths, "sentra_modules")
	
	// Global modules directory
	if homeDir, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(homeDir, ".sentra", "pkg", "mod"))
	}
	
	// Standard library
	paths = append(paths, getStdlibPath())
	
	return paths
}

// getStdlibPath returns the standard library path
func getStdlibPath() string {
	// This could be bundled with the interpreter or in a known location
	if execPath, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(execPath), "stdlib")
	}
	return "stdlib"
}

// SetCurrentModule sets the current module context
func (r *ImportResolver) SetCurrentModule(mod *Module) {
	r.currentMod = mod
}

// ResolveImport resolves an import statement
func (r *ImportResolver) ResolveImport(importPath string, alias string) (*ResolvedImport, error) {
	// Check if already resolved
	if resolved, ok := r.imports[importPath]; ok {
		if alias != "" {
			resolved.Alias = alias
		}
		return resolved, nil
	}
	
	// Determine import type
	var resolved *ResolvedImport
	var err error
	
	if strings.HasPrefix(importPath, "./") || strings.HasPrefix(importPath, "../") {
		// Local import
		resolved, err = r.resolveLocalImport(importPath, alias)
	} else if strings.Contains(importPath, "/") {
		// Remote module import (e.g., github.com/user/package)
		resolved, err = r.resolveRemoteImport(importPath, alias)
	} else {
		// Standard library import
		resolved, err = r.resolveStdlibImport(importPath, alias)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Cache the resolved import
	r.imports[importPath] = resolved
	return resolved, nil
}

// resolveLocalImport resolves a local file import
func (r *ImportResolver) resolveLocalImport(importPath string, alias string) (*ResolvedImport, error) {
	// Try with .sn extension
	possiblePaths := []string{
		importPath + ".sn",
		importPath + ".sentra",
		filepath.Join(importPath, "index.sn"),
		filepath.Join(importPath, "main.sn"),
	}
	
	for _, path := range possiblePaths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		
		if _, err := os.Stat(absPath); err == nil {
			// File exists
			resolved := &ResolvedImport{
				Path:       importPath,
				Alias:      alias,
				SourceFile: absPath,
				Exports:    make(map[string]interface{}),
			}
			
			// Load and parse the file to extract exports
			if err := r.loadExports(resolved); err != nil {
				return nil, fmt.Errorf("failed to load exports from %s: %w", absPath, err)
			}
			
			return resolved, nil
		}
	}
	
	return nil, fmt.Errorf("cannot resolve local import: %s", importPath)
}

// resolveRemoteImport resolves a remote module import
func (r *ImportResolver) resolveRemoteImport(importPath string, alias string) (*ResolvedImport, error) {
	// Check current module's requirements
	version := "latest"
	if r.currentMod != nil {
		for _, req := range r.currentMod.Require {
			if req.Path == importPath {
				version = req.Version
				break
			}
		}
		
		// Check replacements
		if repl, ok := r.currentMod.Replace[importPath]; ok {
			importPath = repl.New
			if repl.Version != "" {
				version = repl.Version
			}
		}
	}
	
	// Fetch the module
	cached, err := r.cache.FetchModule(importPath, version)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch module %s@%s: %w", importPath, version, err)
	}
	
	// Find main source file
	mainFile := r.findMainFile(cached.SourceDir)
	if mainFile == "" {
		return nil, fmt.Errorf("no main file found in module %s", importPath)
	}
	
	resolved := &ResolvedImport{
		Path:       importPath,
		Alias:      alias,
		SourceFile: mainFile,
		Module:     cached,
		Exports:    make(map[string]interface{}),
	}
	
	// Load exports
	if err := r.loadExports(resolved); err != nil {
		return nil, fmt.Errorf("failed to load exports from module %s: %w", importPath, err)
	}
	
	return resolved, nil
}

// resolveStdlibImport resolves a standard library import
func (r *ImportResolver) resolveStdlibImport(importPath string, alias string) (*ResolvedImport, error) {
	stdlibPath := getStdlibPath()
	
	possiblePaths := []string{
		filepath.Join(stdlibPath, importPath+".sn"),
		filepath.Join(stdlibPath, importPath, "index.sn"),
		filepath.Join(stdlibPath, importPath, importPath+".sn"),
	}
	
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			resolved := &ResolvedImport{
				Path:       importPath,
				Alias:      alias,
				SourceFile: path,
				Exports:    make(map[string]interface{}),
			}
			
			// Standard library modules have predefined exports
			r.loadStdlibExports(resolved)
			
			return resolved, nil
		}
	}
	
	return nil, fmt.Errorf("standard library module not found: %s", importPath)
}

// findMainFile finds the main source file in a module directory
func (r *ImportResolver) findMainFile(dir string) string {
	candidates := []string{
		"main.sn",
		"index.sn",
		"src/main.sn",
		"src/index.sn",
	}
	
	for _, candidate := range candidates {
		path := filepath.Join(dir, candidate)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	
	// Look for any .sn file
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return ""
	}
	
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".sn") {
			return filepath.Join(dir, file.Name())
		}
	}
	
	return ""
}

// loadExports loads exported symbols from a source file
func (r *ImportResolver) loadExports(resolved *ResolvedImport) error {
	// Read the source file
	content, err := ioutil.ReadFile(resolved.SourceFile)
	if err != nil {
		return err
	}
	
	// Parse for export statements
	// This is a simplified version - full implementation would use the parser
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Look for export statements
		if strings.HasPrefix(line, "export fn ") {
			// Export function
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				fnName := strings.TrimSuffix(parts[2], "(")
				resolved.Exports[fnName] = "function"
			}
		} else if strings.HasPrefix(line, "export let ") || strings.HasPrefix(line, "export var ") {
			// Export variable
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				varName := strings.TrimSuffix(parts[2], "=")
				resolved.Exports[varName] = "variable"
			}
		} else if strings.HasPrefix(line, "export const ") {
			// Export constant
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				constName := strings.TrimSuffix(parts[2], "=")
				resolved.Exports[constName] = "constant"
			}
		}
	}
	
	return nil
}

// loadStdlibExports loads standard library exports
func (r *ImportResolver) loadStdlibExports(resolved *ResolvedImport) {
	// Define standard library exports
	stdlibExports := map[string]map[string]string{
		"io": {
			"read_file":  "function",
			"write_file": "function",
			"append_file": "function",
			"file_exists": "function",
			"delete_file": "function",
		},
		"net": {
			"http_get": "function",
			"http_post": "function",
			"tcp_connect": "function",
			"udp_connect": "function",
		},
		"crypto": {
			"hash": "function",
			"encrypt": "function",
			"decrypt": "function",
			"sign": "function",
			"verify": "function",
		},
		"fmt": {
			"sprintf": "function",
			"printf": "function",
			"println": "function",
		},
		"strings": {
			"split": "function",
			"join": "function",
			"replace": "function",
			"contains": "function",
			"trim": "function",
		},
		"time": {
			"now": "function",
			"sleep": "function",
			"parse": "function",
			"format": "function",
		},
		"json": {
			"encode": "function",
			"decode": "function",
			"marshal": "function",
			"unmarshal": "function",
		},
		"os": {
			"getenv": "function",
			"setenv": "function",
			"exec": "function",
			"exit": "function",
		},
	}
	
	if exports, ok := stdlibExports[resolved.Path]; ok {
		for name, typ := range exports {
			resolved.Exports[name] = typ
		}
	}
}

// GetExport retrieves an exported symbol from a resolved import
func (r *ImportResolver) GetExport(importPath string, symbolName string) (interface{}, error) {
	resolved, ok := r.imports[importPath]
	if !ok {
		return nil, fmt.Errorf("import not resolved: %s", importPath)
	}
	
	if export, ok := resolved.Exports[symbolName]; ok {
		return export, nil
	}
	
	return nil, fmt.Errorf("symbol %s not exported from %s", symbolName, importPath)
}

// GetAllExports returns all exports from a resolved import
func (r *ImportResolver) GetAllExports(importPath string) (map[string]interface{}, error) {
	resolved, ok := r.imports[importPath]
	if !ok {
		return nil, fmt.Errorf("import not resolved: %s", importPath)
	}
	
	return resolved.Exports, nil
}

// LoadSourceFile loads and returns the source code for an import
func (r *ImportResolver) LoadSourceFile(importPath string) (string, error) {
	resolved, ok := r.imports[importPath]
	if !ok {
		return "", fmt.Errorf("import not resolved: %s", importPath)
	}
	
	content, err := ioutil.ReadFile(resolved.SourceFile)
	if err != nil {
		return "", fmt.Errorf("failed to read source file: %w", err)
	}
	
	return string(content), nil
}