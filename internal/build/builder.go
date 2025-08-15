// internal/build/builder.go
package build

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BuildConfig represents the build configuration
type BuildConfig struct {
	EntryPoint   string            `json:"entry_point"`
	OutputPath   string            `json:"output_path"`
	Optimize     bool              `json:"optimize"`
	IncludeDebug bool              `json:"include_debug"`
	Dependencies map[string]string `json:"dependencies"`
	BuildFlags   []string          `json:"build_flags"`
}

// Builder handles the build process for Sentra projects
type Builder struct {
	config      *BuildConfig
	projectRoot string
	manifest    *ProjectManifest
}

// ProjectManifest represents a Sentra project manifest (sentra.json)
type ProjectManifest struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Author       string            `json:"author"`
	License      string            `json:"license"`
	EntryPoint   string            `json:"entry_point"`
	Dependencies map[string]string `json:"dependencies"`
	Scripts      map[string]string `json:"scripts"`
	BuildConfig  BuildConfig       `json:"build"`
}

// NewBuilder creates a new builder instance
func NewBuilder(projectRoot string) (*Builder, error) {
	manifest, err := loadManifest(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to load manifest: %w", err)
	}

	return &Builder{
		projectRoot: projectRoot,
		manifest:    manifest,
		config:      &manifest.BuildConfig,
	}, nil
}

// Build compiles the Sentra project
func (b *Builder) Build() error {
	fmt.Printf("Building %s v%s...\n", b.manifest.Name, b.manifest.Version)

	// Resolve dependencies
	if err := b.resolveDependencies(); err != nil {
		return fmt.Errorf("failed to resolve dependencies: %w", err)
	}

	// Create import resolver
	resolver := NewImportResolver(b.projectRoot)
	
	// Resolve all imports starting from entry point
	entryPoint := b.manifest.EntryPoint
	if entryPoint == "" {
		entryPoint = "main.sn"
	}
	
	fmt.Printf("Resolving imports from %s...\n", entryPoint)
	moduleGraph, err := resolver.ResolveProject(entryPoint)
	if err != nil {
		return fmt.Errorf("failed to resolve imports: %w", err)
	}
	
	fmt.Printf("Found %d modules\n", len(moduleGraph.Modules))
	
	// Link all modules into single bytecode
	fmt.Println("Linking modules...")
	bytecode, err := LinkModules(moduleGraph)
	if err != nil {
		return fmt.Errorf("failed to link modules: %w", err)
	}
	
	// Create bundle
	bundle := &Bundle{
		Version:    "1.0",
		Timestamp:  time.Now(),
		EntryPoint: entryPoint,
		Modules: map[string]*CompiledModule{
			"main": {
				Path:     entryPoint,
				Bytecode: bytecode,
				Metadata: map[string]interface{}{
					"linked":      true,
					"module_count": len(moduleGraph.Modules),
				},
			},
		},
		Dependencies: b.manifest.Dependencies,
	}
	
	// Calculate checksum
	checksum := sha256.New()
	checksum.Write(bytecode)
	bundle.Checksum = hex.EncodeToString(checksum.Sum(nil))

	// Optimize if requested
	if b.config.Optimize {
		bundle = b.optimizeBundle(bundle)
	}

	// Write output
	outputPath := b.config.OutputPath
	if outputPath == "" {
		outputPath = filepath.Join(b.projectRoot, "dist", b.manifest.Name+".snb")
	} else {
		// If output path is relative, make it relative to project root
		if !filepath.IsAbs(outputPath) {
			outputPath = filepath.Join(b.projectRoot, outputPath)
		}
	}
	
	if err := b.writeBundle(bundle, outputPath); err != nil {
		return fmt.Errorf("failed to write bundle: %w", err)
	}

	fmt.Printf("Build complete: %s (%d bytes)\n", outputPath, len(bytecode))
	return nil
}

// CompiledModule represents a compiled Sentra module
type CompiledModule struct {
	Path         string
	Bytecode     []byte
	Dependencies []string
	Exports      []string
	Metadata     map[string]interface{}
}

// Bundle represents a compiled Sentra bundle
type Bundle struct {
	Version      string                     `json:"version"`
	Timestamp    time.Time                  `json:"timestamp"`
	EntryPoint   string                     `json:"entry_point"`
	Modules      map[string]*CompiledModule `json:"modules"`
	Dependencies map[string]string          `json:"dependencies"`
	Checksum     string                     `json:"checksum"`
}

// resolveDependencies downloads and caches dependencies
func (b *Builder) resolveDependencies() error {
	if len(b.manifest.Dependencies) == 0 {
		return nil
	}

	fmt.Println("Resolving dependencies...")
	
	// Create vendor directory
	vendorDir := filepath.Join(b.projectRoot, "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		return err
	}

	// Download each dependency
	for name, version := range b.manifest.Dependencies {
		if err := b.downloadDependency(name, version, vendorDir); err != nil {
			return fmt.Errorf("failed to download %s@%s: %w", name, version, err)
		}
	}

	return nil
}

// downloadDependency downloads a dependency from the registry
func (b *Builder) downloadDependency(name, version, vendorDir string) error {
	// This would normally download from a registry
	// For now, we'll simulate it
	depPath := filepath.Join(vendorDir, name)
	if _, err := os.Stat(depPath); err == nil {
		fmt.Printf("  ✓ %s@%s (cached)\n", name, version)
		return nil
	}

	fmt.Printf("  ↓ Downloading %s@%s...\n", name, version)
	
	// Create dependency directory
	if err := os.MkdirAll(depPath, 0755); err != nil {
		return err
	}

	// Write a placeholder manifest
	manifest := ProjectManifest{
		Name:    name,
		Version: version,
	}
	
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(depPath, "sentra.json"), data, 0644)
}

// collectSourceFiles collects all source files in the project
func (b *Builder) collectSourceFiles() ([]string, error) {
	var files []string
	
	err := filepath.Walk(b.projectRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Skip vendor and build directories
		if strings.Contains(path, "vendor") || strings.Contains(path, "dist") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		
		// Collect .sn files
		if strings.HasSuffix(path, ".sn") {
			rel, err := filepath.Rel(b.projectRoot, path)
			if err != nil {
				return err
			}
			files = append(files, rel)
		}
		
		return nil
	})
	
	return files, err
}



// optimizeBundle applies optimizations to the bundle
func (b *Builder) optimizeBundle(bundle *Bundle) *Bundle {
	fmt.Println("Optimizing bundle...")
	
	// Dead code elimination
	// Constant folding
	// Bytecode compression
	// etc.
	
	return bundle
}

// writeBundle writes the bundle to disk
func (b *Builder) writeBundle(bundle *Bundle, outputPath string) error {
	// Create output directory
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create gzip writer
	gzWriter := gzip.NewWriter(file)
	defer gzWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// Write manifest
	manifestData, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    "manifest.json",
		Mode:    0644,
		Size:    int64(len(manifestData)),
		ModTime: bundle.Timestamp,
	}
	
	if err := tarWriter.WriteHeader(header); err != nil {
		return err
	}
	
	if _, err := tarWriter.Write(manifestData); err != nil {
		return err
	}

	// Write each module
	for path, module := range bundle.Modules {
		header := &tar.Header{
			Name:    "modules/" + strings.ReplaceAll(path, "\\", "/"),
			Mode:    0644,
			Size:    int64(len(module.Bytecode)),
			ModTime: bundle.Timestamp,
		}
		
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		
		if _, err := tarWriter.Write(module.Bytecode); err != nil {
			return err
		}
	}

	return nil
}

// loadManifest loads the project manifest
func loadManifest(projectRoot string) (*ProjectManifest, error) {
	manifestPath := filepath.Join(projectRoot, "sentra.json")
	
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default manifest
			return &ProjectManifest{
				Name:        filepath.Base(projectRoot),
				Version:     "0.1.0",
				EntryPoint:  "main.sn",
				BuildConfig: BuildConfig{},
			}, nil
		}
		return nil, err
	}

	var manifest ProjectManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}


// Watch watches for file changes and rebuilds
func (b *Builder) Watch() error {
	fmt.Println("Watching for changes...")
	
	// This would implement file watching
	// For now, just build once
	return b.Build()
}

// Clean removes build artifacts
func (b *Builder) Clean() error {
	distDir := filepath.Join(b.projectRoot, "dist")
	return os.RemoveAll(distDir)
}