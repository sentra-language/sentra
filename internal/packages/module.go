package packages

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Module represents a Sentra module with its dependencies
type Module struct {
	Module   string                 `json:"module"`
	Sentra   string                 `json:"sentra"`
	Require  []Requirement          `json:"require"`
	Replace  map[string]Replacement `json:"replace"`
	Exclude  []string               `json:"exclude"`
	Metadata ModuleMetadata         `json:"metadata,omitempty"`
}

// Requirement represents a module dependency
type Requirement struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// Replacement represents a module replacement directive
type Replacement struct {
	Old     string `json:"old"`
	New     string `json:"new"`
	Version string `json:"version"`
}

// ModuleMetadata contains additional module information
type ModuleMetadata struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Author      string   `json:"author"`
	License     string   `json:"license"`
	Homepage    string   `json:"homepage"`
	Keywords    []string `json:"keywords"`
}

// ModuleCache manages downloaded modules
type ModuleCache struct {
	BaseDir string
	modules map[string]*CachedModule
}

// CachedModule represents a cached module
type CachedModule struct {
	Path      string
	Version   string
	Module    *Module
	LoadTime  time.Time
	SourceDir string
}

// NewModuleCache creates a new module cache
func NewModuleCache(baseDir string) *ModuleCache {
	if baseDir == "" {
		homeDir, _ := os.UserHomeDir()
		baseDir = filepath.Join(homeDir, ".sentra", "pkg", "mod")
	}
	
	return &ModuleCache{
		BaseDir: baseDir,
		modules: make(map[string]*CachedModule),
	}
}

// ParseModFile parses a sentra.mod file
func ParseModFile(path string) (*Module, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open mod file: %w", err)
	}
	defer file.Close()
	
	mod := &Module{
		Require: []Requirement{},
		Replace: make(map[string]Replacement),
		Exclude: []string{},
	}
	
	scanner := bufio.NewScanner(file)
	var inRequire, inReplace, inExclude bool
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		
		// Handle module declaration
		if strings.HasPrefix(line, "module ") {
			mod.Module = strings.TrimSpace(strings.TrimPrefix(line, "module"))
			continue
		}
		
		// Handle sentra version
		if strings.HasPrefix(line, "sentra ") {
			mod.Sentra = strings.TrimSpace(strings.TrimPrefix(line, "sentra"))
			continue
		}
		
		// Handle require block
		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire {
			if line == ")" {
				inRequire = false
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				mod.Require = append(mod.Require, Requirement{
					Path:    parts[0],
					Version: parts[1],
				})
			}
			continue
		}
		
		// Handle single require
		if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				mod.Require = append(mod.Require, Requirement{
					Path:    parts[0],
					Version: parts[1],
				})
			}
			continue
		}
		
		// Handle replace block
		if line == "replace (" {
			inReplace = true
			continue
		}
		if inReplace {
			if line == ")" {
				inReplace = false
				continue
			}
			parts := strings.Split(line, "=>")
			if len(parts) == 2 {
				old := strings.TrimSpace(parts[0])
				newParts := strings.Fields(strings.TrimSpace(parts[1]))
				if len(newParts) >= 1 {
					version := ""
					if len(newParts) >= 2 {
						version = newParts[1]
					}
					mod.Replace[old] = Replacement{
						Old:     old,
						New:     newParts[0],
						Version: version,
					}
				}
			}
			continue
		}
		
		// Handle exclude block
		if line == "exclude (" {
			inExclude = true
			continue
		}
		if inExclude {
			if line == ")" {
				inExclude = false
				continue
			}
			mod.Exclude = append(mod.Exclude, strings.TrimSpace(line))
			continue
		}
	}
	
	return mod, scanner.Err()
}

// WriteModFile writes a module to a sentra.mod file
func WriteModFile(path string, mod *Module) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create mod file: %w", err)
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	
	// Write module declaration
	fmt.Fprintf(writer, "module %s\n\n", mod.Module)
	
	// Write sentra version if specified
	if mod.Sentra != "" {
		fmt.Fprintf(writer, "sentra %s\n\n", mod.Sentra)
	}
	
	// Write requirements
	if len(mod.Require) > 0 {
		if len(mod.Require) == 1 {
			fmt.Fprintf(writer, "require %s %s\n\n", mod.Require[0].Path, mod.Require[0].Version)
		} else {
			fmt.Fprintln(writer, "require (")
			for _, req := range mod.Require {
				fmt.Fprintf(writer, "\t%s %s\n", req.Path, req.Version)
			}
			fmt.Fprintln(writer, ")\n")
		}
	}
	
	// Write replacements
	if len(mod.Replace) > 0 {
		fmt.Fprintln(writer, "replace (")
		for old, repl := range mod.Replace {
			if repl.Version != "" {
				fmt.Fprintf(writer, "\t%s => %s %s\n", old, repl.New, repl.Version)
			} else {
				fmt.Fprintf(writer, "\t%s => %s\n", old, repl.New)
			}
		}
		fmt.Fprintln(writer, ")\n")
	}
	
	// Write excludes
	if len(mod.Exclude) > 0 {
		fmt.Fprintln(writer, "exclude (")
		for _, excl := range mod.Exclude {
			fmt.Fprintf(writer, "\t%s\n", excl)
		}
		fmt.Fprintln(writer, ")")
	}
	
	return writer.Flush()
}

// FetchModule downloads a module from GitHub or other sources
func (mc *ModuleCache) FetchModule(path, version string) (*CachedModule, error) {
	// Check if already cached
	cacheKey := fmt.Sprintf("%s@%s", path, version)
	if cached, ok := mc.modules[cacheKey]; ok {
		return cached, nil
	}
	
	// Determine source URL
	sourceURL := ""
	if strings.HasPrefix(path, "github.com/") {
		// GitHub repository
		parts := strings.Split(path, "/")
		if len(parts) >= 3 {
			user := parts[1]
			repo := strings.Join(parts[2:], "/")
			if version == "latest" || version == "" {
				sourceURL = fmt.Sprintf("https://github.com/%s/%s/archive/refs/heads/main.zip", user, repo)
			} else {
				sourceURL = fmt.Sprintf("https://github.com/%s/%s/archive/refs/tags/%s.zip", user, repo, version)
			}
		}
	} else if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "http://") {
		sourceURL = path
	} else {
		// Local path
		return mc.loadLocalModule(path, version)
	}
	
	if sourceURL == "" {
		return nil, fmt.Errorf("unable to determine source URL for %s", path)
	}
	
	// Download module
	destDir := filepath.Join(mc.BaseDir, strings.ReplaceAll(path, "/", "_"), version)
	if err := mc.downloadAndExtract(sourceURL, destDir); err != nil {
		return nil, fmt.Errorf("failed to download module: %w", err)
	}
	
	// Parse module file
	modFile := filepath.Join(destDir, "sentra.mod")
	mod, err := ParseModFile(modFile)
	if err != nil {
		// Create default module if no mod file exists
		mod = &Module{
			Module: path,
			Sentra: "1.0",
		}
	}
	
	// Cache the module
	cached := &CachedModule{
		Path:      path,
		Version:   version,
		Module:    mod,
		LoadTime:  time.Now(),
		SourceDir: destDir,
	}
	mc.modules[cacheKey] = cached
	
	return cached, nil
}

// downloadAndExtract downloads and extracts a module archive
func (mc *ModuleCache) downloadAndExtract(url, destDir string) error {
	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}
	
	// Download file
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download: HTTP %d", resp.StatusCode)
	}
	
	// Save to temporary file
	tempFile := filepath.Join(destDir, "download.tmp")
	out, err := os.Create(tempFile)
	if err != nil {
		return err
	}
	defer out.Close()
	
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	
	// Extract based on file type
	if strings.HasSuffix(url, ".zip") {
		return extractZip(tempFile, destDir)
	} else if strings.HasSuffix(url, ".tar.gz") || strings.HasSuffix(url, ".tgz") {
		return extractTarGz(tempFile, destDir)
	}
	
	return fmt.Errorf("unsupported archive format")
}

// loadLocalModule loads a module from local filesystem
func (mc *ModuleCache) loadLocalModule(path, version string) (*CachedModule, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	
	// Check if path exists
	if _, err := os.Stat(absPath); err != nil {
		return nil, fmt.Errorf("local module not found: %s", path)
	}
	
	// Parse module file
	modFile := filepath.Join(absPath, "sentra.mod")
	mod, err := ParseModFile(modFile)
	if err != nil {
		// Create default module if no mod file exists
		mod = &Module{
			Module: path,
			Sentra: "1.0",
		}
	}
	
	// Cache the module
	cacheKey := fmt.Sprintf("%s@%s", path, version)
	cached := &CachedModule{
		Path:      path,
		Version:   version,
		Module:    mod,
		LoadTime:  time.Now(),
		SourceDir: absPath,
	}
	mc.modules[cacheKey] = cached
	
	return cached, nil
}

// ResolveDependencies resolves all dependencies for a module
func (mc *ModuleCache) ResolveDependencies(mod *Module) ([]*CachedModule, error) {
	var resolved []*CachedModule
	visited := make(map[string]bool)
	
	var resolve func(*Module) error
	resolve = func(m *Module) error {
		for _, req := range m.Require {
			key := fmt.Sprintf("%s@%s", req.Path, req.Version)
			if visited[key] {
				continue
			}
			visited[key] = true
			
			// Check for replacements
			if repl, ok := m.Replace[req.Path]; ok {
				req.Path = repl.New
				if repl.Version != "" {
					req.Version = repl.Version
				}
			}
			
			// Fetch the dependency
			cached, err := mc.FetchModule(req.Path, req.Version)
			if err != nil {
				return fmt.Errorf("failed to fetch %s@%s: %w", req.Path, req.Version, err)
			}
			
			resolved = append(resolved, cached)
			
			// Recursively resolve dependencies
			if err := resolve(cached.Module); err != nil {
				return err
			}
		}
		return nil
	}
	
	if err := resolve(mod); err != nil {
		return nil, err
	}
	
	return resolved, nil
}

// GetModulePath returns the filesystem path for a cached module
func (mc *ModuleCache) GetModulePath(path, version string) string {
	cacheKey := fmt.Sprintf("%s@%s", path, version)
	if cached, ok := mc.modules[cacheKey]; ok {
		return cached.SourceDir
	}
	return ""
}

// Note: extractZip and extractTarGz are implemented in commands.go