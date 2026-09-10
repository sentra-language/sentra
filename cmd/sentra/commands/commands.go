// cmd/sentra/commands/commands.go
package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"sentra/internal/buildutil"
	"sentra/internal/packages"
)

// InitCommand scaffolds a new Sentra project in the given (or current) directory.
func InitCommand(args []string) error {
	name := ""
	if len(args) > 0 {
		name = args[0]
	}

	projectDir := "."
	if name != "" {
		projectDir = name
		if err := os.MkdirAll(projectDir, 0o755); err != nil {
			return fmt.Errorf("failed to create project directory: %w", err)
		}
	} else {
		abs, err := filepath.Abs(projectDir)
		if err != nil {
			return err
		}
		name = filepath.Base(abs)
	}

	manifestPath := filepath.Join(projectDir, "sentra.json")
	if _, err := os.Stat(manifestPath); err == nil {
		return fmt.Errorf("sentra.json already exists in %s", projectDir)
	}

	manifest := map[string]interface{}{
		"name":         name,
		"version":      "0.1.0",
		"description":  "A Sentra project",
		"entry_point":  "main.sn",
		"dependencies": map[string]string{},
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(manifestPath, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("failed to write sentra.json: %w", err)
	}

	mainPath := filepath.Join(projectDir, "main.sn")
	if _, err := os.Stat(mainPath); os.IsNotExist(err) {
		mainSrc := fmt.Sprintf(`// %s - a Sentra project
// Run with: sentra run main.sn

log("Welcome to Sentra, the security-first programming language!")

let project = "%s"
log("Project " + project + " is ready.")
`, name, name)
		if err := os.WriteFile(mainPath, []byte(mainSrc), 0o644); err != nil {
			return fmt.Errorf("failed to write main.sn: %w", err)
		}
	}

	gitignorePath := filepath.Join(projectDir, ".gitignore")
	if _, err := os.Stat(gitignorePath); os.IsNotExist(err) {
		ignore := "dist/\nbuild/\n*.snb\n"
		if err := os.WriteFile(gitignorePath, []byte(ignore), 0o644); err != nil {
			return fmt.Errorf("failed to write .gitignore: %w", err)
		}
	}

	fmt.Printf("Initialized Sentra project %q\n", name)
	fmt.Println()
	fmt.Println("Next steps:")
	if projectDir != "." {
		fmt.Printf("  cd %s\n", projectDir)
	}
	fmt.Println("  sentra run main.sn")
	return nil
}

// BuildCommand compiles the project into a bytecode bundle.
func BuildCommand(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	output := fs.String("o", "", "output path for the compiled bundle")
	verbose := fs.Bool("v", false, "verbose output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	projectDir := "."
	if fs.NArg() > 0 {
		projectDir = fs.Arg(0)
	}

	out := *output
	if out == "" {
		abs, err := filepath.Abs(projectDir)
		if err != nil {
			return err
		}
		out = filepath.Join(projectDir, "dist", filepath.Base(abs)+".snb")
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if err := buildutil.BuildProject(projectDir, out, *verbose); err != nil {
		return err
	}
	fmt.Printf("Build complete: %s\n", out)
	return nil
}

// WatchCommand rebuilds the project whenever source files change.
func WatchCommand(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "verbose output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	projectDir := "."
	if fs.NArg() > 0 {
		projectDir = fs.Arg(0)
	}
	return buildutil.WatchProject(projectDir, *verbose)
}

// CleanCommand removes build artifacts.
func CleanCommand(args []string) error {
	projectDir := "."
	if len(args) > 0 {
		projectDir = args[0]
	}

	removed := false
	for _, dir := range []string{"dist", "build"} {
		target := filepath.Join(projectDir, dir)
		if _, err := os.Stat(target); err == nil {
			if err := os.RemoveAll(target); err != nil {
				return fmt.Errorf("failed to remove %s: %w", target, err)
			}
			fmt.Printf("Removed %s\n", target)
			removed = true
		}
	}
	if !removed {
		fmt.Println("Nothing to clean.")
	}
	return nil
}

// errRegistryUnavailable is returned by registry commands until the public
// package registry is live.
var errRegistryUnavailable = fmt.Errorf("the public Sentra package registry is not yet available; use 'sentra get <git-url>' to fetch packages directly")

// PackageSearchCommand searches the package registry.
func PackageSearchCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sentra pkg search <query>")
	}
	return errRegistryUnavailable
}

// PackageInfoCommand shows details for a registry package.
func PackageInfoCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sentra pkg info <package>")
	}
	return errRegistryUnavailable
}

// PackagePublishCommand publishes the current module to the registry.
func PackagePublishCommand(args []string) error {
	return errRegistryUnavailable
}

// PackageListCommand lists packages installed for the current module.
func PackageListCommand(args []string) error {
	pm := packages.NewPackageManager("")
	return pm.ListPackages()
}
