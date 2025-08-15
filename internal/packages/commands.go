package packages

import (
	"archive/zip"
	"compress/gzip"
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// PackageManager handles package management operations
type PackageManager struct {
	cache    *ModuleCache
	resolver *ImportResolver
	workDir  string
}

// NewPackageManager creates a new package manager
func NewPackageManager(workDir string) *PackageManager {
	cache := NewModuleCache("")
	resolver := NewImportResolver(cache)
	
	if workDir == "" {
		workDir, _ = os.Getwd()
	}
	
	return &PackageManager{
		cache:    cache,
		resolver: resolver,
		workDir:  workDir,
	}
}

// InitModule initializes a new Sentra module
func (pm *PackageManager) InitModule(modulePath string) error {
	if modulePath == "" {
		return fmt.Errorf("module path is required")
	}
	
	// Check if sentra.mod already exists
	modFile := filepath.Join(pm.workDir, "sentra.mod")
	if _, err := os.Stat(modFile); err == nil {
		return fmt.Errorf("sentra.mod already exists")
	}
	
	// Create new module
	mod := &Module{
		Module: modulePath,
		Sentra: "1.0",
	}
	
	// Write module file
	if err := WriteModFile(modFile, mod); err != nil {
		return fmt.Errorf("failed to write sentra.mod: %w", err)
	}
	
	fmt.Printf("Module initialized: %s\n", modulePath)
	return nil
}

// GetPackage downloads and installs a package
func (pm *PackageManager) GetPackage(packagePath string, version string) error {
	if version == "" {
		version = "latest"
	}
	
	// Load current module
	modFile := filepath.Join(pm.workDir, "sentra.mod")
	mod, err := ParseModFile(modFile)
	if err != nil {
		return fmt.Errorf("failed to parse sentra.mod: %w", err)
	}
	
	// Add to requirements if not already present
	found := false
	for i, req := range mod.Require {
		if req.Path == packagePath {
			mod.Require[i].Version = version
			found = true
			break
		}
	}
	
	if !found {
		mod.Require = append(mod.Require, Requirement{
			Path:    packagePath,
			Version: version,
		})
	}
	
	// Fetch the package
	cached, err := pm.cache.FetchModule(packagePath, version)
	if err != nil {
		return fmt.Errorf("failed to fetch package: %w", err)
	}
	
	// Update module file
	if err := WriteModFile(modFile, mod); err != nil {
		return fmt.Errorf("failed to update sentra.mod: %w", err)
	}
	
	fmt.Printf("Added %s %s\n", packagePath, version)
	fmt.Printf("Downloaded to: %s\n", cached.SourceDir)
	
	// Resolve dependencies
	deps, err := pm.cache.ResolveDependencies(cached.Module)
	if err != nil {
		return fmt.Errorf("failed to resolve dependencies: %w", err)
	}
	
	if len(deps) > 0 {
		fmt.Printf("Downloaded %d dependencies\n", len(deps))
	}
	
	return nil
}

// UpdatePackages updates all or specified packages
func (pm *PackageManager) UpdatePackages(packages []string) error {
	// Load current module
	modFile := filepath.Join(pm.workDir, "sentra.mod")
	mod, err := ParseModFile(modFile)
	if err != nil {
		return fmt.Errorf("failed to parse sentra.mod: %w", err)
	}
	
	// Determine which packages to update
	var toUpdate []Requirement
	if len(packages) == 0 {
		// Update all
		toUpdate = mod.Require
	} else {
		// Update specified packages
		for _, pkg := range packages {
			for _, req := range mod.Require {
				if strings.HasPrefix(req.Path, pkg) {
					toUpdate = append(toUpdate, req)
				}
			}
		}
	}
	
	// Update each package
	updated := 0
	for _, req := range toUpdate {
		fmt.Printf("Updating %s...\n", req.Path)
		
		// Fetch latest version
		cached, err := pm.cache.FetchModule(req.Path, "latest")
		if err != nil {
			fmt.Printf("  Failed: %v\n", err)
			continue
		}
		
		// Update version in requirements
		for i, r := range mod.Require {
			if r.Path == req.Path {
				mod.Require[i].Version = cached.Version
				updated++
				fmt.Printf("  Updated to %s\n", cached.Version)
				break
			}
		}
	}
	
	// Write updated module file
	if updated > 0 {
		if err := WriteModFile(modFile, mod); err != nil {
			return fmt.Errorf("failed to update sentra.mod: %w", err)
		}
		fmt.Printf("Updated %d packages\n", updated)
	} else {
		fmt.Println("All packages are up to date")
	}
	
	return nil
}

// DownloadDependencies downloads all module dependencies
func (pm *PackageManager) DownloadDependencies() error {
	// Load current module
	modFile := filepath.Join(pm.workDir, "sentra.mod")
	mod, err := ParseModFile(modFile)
	if err != nil {
		return fmt.Errorf("failed to parse sentra.mod: %w", err)
	}
	
	// Resolve all dependencies
	deps, err := pm.cache.ResolveDependencies(mod)
	if err != nil {
		return fmt.Errorf("failed to resolve dependencies: %w", err)
	}
	
	fmt.Printf("Downloaded %d modules\n", len(deps))
	for _, dep := range deps {
		fmt.Printf("  %s@%s\n", dep.Path, dep.Version)
	}
	
	return nil
}

// TidyModules removes unused dependencies and adds missing ones
func (pm *PackageManager) TidyModules() error {
	// Load current module
	modFile := filepath.Join(pm.workDir, "sentra.mod")
	mod, err := ParseModFile(modFile)
	if err != nil {
		return fmt.Errorf("failed to parse sentra.mod: %w", err)
	}
	
	// Scan source files for imports
	imports, err := pm.scanImports(pm.workDir)
	if err != nil {
		return fmt.Errorf("failed to scan imports: %w", err)
	}
	
	// Build new requirements list
	var newRequirements []Requirement
	for imp := range imports {
		// Skip local and stdlib imports
		if strings.HasPrefix(imp, "./") || strings.HasPrefix(imp, "../") || !strings.Contains(imp, "/") {
			continue
		}
		
		// Check if already in requirements
		found := false
		for _, req := range mod.Require {
			if req.Path == imp {
				newRequirements = append(newRequirements, req)
				found = true
				break
			}
		}
		
		// Add new requirement
		if !found {
			newRequirements = append(newRequirements, Requirement{
				Path:    imp,
				Version: "latest",
			})
			fmt.Printf("Added missing dependency: %s\n", imp)
		}
	}
	
	// Check for removed dependencies
	for _, req := range mod.Require {
		found := false
		for _, newReq := range newRequirements {
			if req.Path == newReq.Path {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Removed unused dependency: %s\n", req.Path)
		}
	}
	
	// Update module
	mod.Require = newRequirements
	
	// Write updated module file
	if err := WriteModFile(modFile, mod); err != nil {
		return fmt.Errorf("failed to update sentra.mod: %w", err)
	}
	
	fmt.Println("Module dependencies tidied")
	return nil
}

// VendorDependencies copies all dependencies to vendor directory
func (pm *PackageManager) VendorDependencies() error {
	// Load current module
	modFile := filepath.Join(pm.workDir, "sentra.mod")
	mod, err := ParseModFile(modFile)
	if err != nil {
		return fmt.Errorf("failed to parse sentra.mod: %w", err)
	}
	
	// Create vendor directory
	vendorDir := filepath.Join(pm.workDir, "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		return fmt.Errorf("failed to create vendor directory: %w", err)
	}
	
	// Resolve and copy dependencies
	deps, err := pm.cache.ResolveDependencies(mod)
	if err != nil {
		return fmt.Errorf("failed to resolve dependencies: %w", err)
	}
	
	for _, dep := range deps {
		// Create destination directory
		destDir := filepath.Join(vendorDir, dep.Path)
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return fmt.Errorf("failed to create vendor subdirectory: %w", err)
		}
		
		// Copy module files
		if err := copyDir(dep.SourceDir, destDir); err != nil {
			return fmt.Errorf("failed to vendor %s: %w", dep.Path, err)
		}
		
		fmt.Printf("Vendored %s@%s\n", dep.Path, dep.Version)
	}
	
	fmt.Printf("Vendored %d dependencies\n", len(deps))
	return nil
}

// ListPackages lists all installed packages
func (pm *PackageManager) ListPackages() error {
	// Load current module
	modFile := filepath.Join(pm.workDir, "sentra.mod")
	mod, err := ParseModFile(modFile)
	if err != nil {
		return fmt.Errorf("failed to parse sentra.mod: %w", err)
	}
	
	fmt.Printf("Module: %s\n", mod.Module)
	fmt.Printf("Sentra: %s\n", mod.Sentra)
	fmt.Println("\nDependencies:")
	
	for _, req := range mod.Require {
		// Check if cached
		cachePath := pm.cache.GetModulePath(req.Path, req.Version)
		status := "not downloaded"
		if cachePath != "" {
			status = "cached"
		}
		
		fmt.Printf("  %s %s [%s]\n", req.Path, req.Version, status)
	}
	
	if len(mod.Replace) > 0 {
		fmt.Println("\nReplacements:")
		for old, repl := range mod.Replace {
			if repl.Version != "" {
				fmt.Printf("  %s => %s %s\n", old, repl.New, repl.Version)
			} else {
				fmt.Printf("  %s => %s\n", old, repl.New)
			}
		}
	}
	
	return nil
}

// scanImports scans source files for import statements
func (pm *PackageManager) scanImports(dir string) (map[string]bool, error) {
	imports := make(map[string]bool)
	
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Skip vendor and hidden directories
		if info.IsDir() && (info.Name() == "vendor" || strings.HasPrefix(info.Name(), ".")) {
			return filepath.SkipDir
		}
		
		// Process .sn files
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".sn") {
			fileImports, err := scanFileImports(path)
			if err != nil {
				return err
			}
			
			for imp := range fileImports {
				imports[imp] = true
			}
		}
		
		return nil
	})
	
	return imports, err
}

// scanFileImports scans a single file for imports
func scanFileImports(path string) (map[string]bool, error) {
	imports := make(map[string]bool)
	
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	// Simple import scanning - full implementation would use the parser
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Look for import statements
		if strings.HasPrefix(line, "import ") {
			line = strings.TrimPrefix(line, "import ")
			
			// Handle different import formats
			if strings.Contains(line, " from ") {
				// import { foo } from "path"
				parts := strings.Split(line, " from ")
				if len(parts) == 2 {
					path := strings.Trim(parts[1], "\"'")
					imports[path] = true
				}
			} else if strings.Contains(line, "\"") {
				// import "path" or import alias "path"
				start := strings.Index(line, "\"")
				end := strings.LastIndex(line, "\"")
				if start != -1 && end != -1 && start < end {
					path := line[start+1 : end]
					imports[path] = true
				}
			}
		}
	}
	
	return imports, nil
}

// copyDir copies a directory recursively
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Calculate destination path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)
		
		if info.IsDir() {
			// Create directory
			return os.MkdirAll(dstPath, info.Mode())
		}
		
		// Copy file
		return copyFile(path, dstPath)
	})
}

// copyFile copies a single file
func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	
	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	
	_, err = io.Copy(destination, source)
	return err
}

// Implement the actual extraction functions that were placeholders

// extractZip extracts a ZIP archive
func extractZip(src, dest string) error {
	reader, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer reader.Close()
	
	for _, file := range reader.File {
		path := filepath.Join(dest, file.Name)
		
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.Mode())
			continue
		}
		
		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()
		
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		
		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()
		
		_, err = io.Copy(targetFile, fileReader)
		if err != nil {
			return err
		}
	}
	
	return nil
}

// extractTarGz extracts a TAR.GZ archive
func extractTarGz(src, dest string) error {
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()
	
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzReader.Close()
	
	tarReader := tar.NewReader(gzReader)
	
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		
		path := filepath.Join(dest, header.Name)
		
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return err
			}
			
			outFile, err := os.Create(path)
			if err != nil {
				return err
			}
			
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}
	
	return nil
}