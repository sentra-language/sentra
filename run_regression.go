//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type TestResult struct {
	File    string
	Success bool
	Output  string
	Error   string
	Time    time.Duration
}

func main() {
	// Find all .sn files in examples directory
	pattern := filepath.Join("examples", "*.sn")
	files, err := filepath.Glob(pattern)
	if err != nil {
		fmt.Printf("Error finding test files: %v\n", err)
		os.Exit(1)
	}

	// Sort files for consistent output
	sort.Strings(files)

	fmt.Printf("Running regression tests on %d Sentra scripts...\n", len(files))
	fmt.Println(strings.Repeat("=", 80))

	results := make([]TestResult, 0, len(files))
	passed := 0
	failed := 0

	// Test each file
	for _, file := range files {
		result := testFile(file)
		results = append(results, result)
		
		if result.Success {
			passed++
			fmt.Printf("✓ %s (%.2fs)\n", filepath.Base(file), result.Time.Seconds())
		} else {
			failed++
			fmt.Printf("✗ %s - %s\n", filepath.Base(file), getErrorSummary(result.Error))
		}
	}

	// Print summary
	totalTime := time.Duration(0)
	for _, result := range results {
		totalTime += result.Time
	}
	
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Results: %d passed, %d failed out of %d total\n", passed, failed, len(files))
	fmt.Printf("Total time: %.2f seconds\n", totalTime.Seconds())
	
	// Print details of failures
	if failed > 0 {
		fmt.Println("\nFailed scripts:")
		for _, result := range results {
			if !result.Success {
				fmt.Printf("\n%s:\n", filepath.Base(result.File))
				fmt.Printf("  Error: %s\n", result.Error)
				if result.Output != "" {
					fmt.Printf("  Output: %s\n", truncateOutput(result.Output, 200))
				}
			}
		}
	}

	// Exit with non-zero code if any tests failed
	if failed > 0 {
		os.Exit(1)
	}
}

func testFile(file string) TestResult {
	start := time.Now()
	
	// Run the Sentra script
	cmd := exec.Command("go", "run", "cmd/sentra/main.go", "run", file)
	
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	// Set a timeout to prevent hanging
	done := make(chan error)
	go func() {
		done <- cmd.Run()
	}()
	
	select {
	case err := <-done:
		elapsed := time.Since(start)
		if err != nil {
			return TestResult{
				File:    file,
				Success: false,
				Output:  stdout.String(),
				Error:   stderr.String(),
				Time:    elapsed,
			}
		}
		return TestResult{
			File:    file,
			Success: true,
			Output:  stdout.String(),
			Time:    elapsed,
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		return TestResult{
			File:    file,
			Success: false,
			Error:   "Timeout: script took longer than 10 seconds",
			Time:    10 * time.Second,
		}
	}
}

func getErrorSummary(errStr string) string {
	lines := strings.Split(errStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Error") || strings.Contains(line, "error") {
			// Truncate long error messages
			if len(line) > 80 {
				return line[:77] + "..."
			}
			return line
		}
	}
	// If no error line found, return first non-empty line
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			if len(line) > 80 {
				return line[:77] + "..."
			}
			return line
		}
	}
	return "Unknown error"
}

func truncateOutput(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}