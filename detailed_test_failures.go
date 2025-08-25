package main

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	pattern := filepath.Join("examples", "*.sn")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Fatal(err)
	}

	var failures []string
	var timeouts []string

	for _, file := range matches {
		cmd := exec.Command("C:\\Program Files\\Go\\bin\\go.exe", "run", "cmd/sentra/main.go", "run", file)
		cmd.Dir = "."
		
		done := make(chan error, 1)
		go func() {
			done <- cmd.Run()
		}()

		select {
		case err := <-done:
			if err != nil {
				failures = append(failures, file)
			}
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			timeouts = append(timeouts, file)
		}
	}

	fmt.Printf("=== FAILING TESTS (%d) ===\n", len(failures))
	for _, f := range failures {
		fmt.Printf("✗ %s\n", strings.TrimPrefix(f, "examples/"))
	}
	
	fmt.Printf("\n=== TIMEOUT TESTS (%d) ===\n", len(timeouts))
	for _, f := range timeouts {
		fmt.Printf("⏱ %s\n", strings.TrimPrefix(f, "examples/"))
	}
	
	total := len(failures) + len(timeouts)
	fmt.Printf("\n=== SUMMARY ===\n")
	fmt.Printf("Total issues: %d\n", total)
}