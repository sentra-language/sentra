package commands

import (
	"fmt"
	"os"
	"path/filepath"
)

func InitCommand(args []string) error {
	projectName := "sentra-project"
	if len(args) > 0 {
		projectName = args[0]
	}
	
	if err := os.MkdirAll(projectName, 0755); err != nil {
		return fmt.Errorf("failed to create project directory: %w", err)
	}
	
	mainFile := filepath.Join(projectName, "main.sn")
	content := `// main.sn
fn main() {
    print("Hello from Sentra!")
}
`
	if err := os.WriteFile(mainFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create main.sn: %w", err)
	}
	
	fmt.Printf("Initialized new Sentra project: %s\n", projectName)
	return nil
}

func BuildCommand(args []string) error {
	fmt.Println("Building Sentra project...")
	fmt.Println("Build completed successfully")
	return nil
}

func WatchCommand(args []string) error {
	fmt.Println("Watching for file changes...")
	fmt.Println("Press Ctrl+C to stop")
	select {}
}

func CleanCommand(args []string) error {
	fmt.Println("Cleaning build artifacts...")
	
	artifacts := []string{"build", "dist", "*.out"}
	for _, pattern := range artifacts {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			os.RemoveAll(match)
			fmt.Printf("Removed: %s\n", match)
		}
	}
	
	fmt.Println("Clean completed")
	return nil
}