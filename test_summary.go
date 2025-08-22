//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

func main() {
	files, _ := filepath.Glob("examples/*.sn")
	
	passing := []string{}
	failing := []string{}
	timeout := []string{}
	
	for _, file := range files {
		cmd := exec.Command("go", "run", "cmd/sentra/main.go", "run", file)
		done := make(chan error, 1)
		go func() {
			done <- cmd.Run()
		}()
		
		select {
		case err := <-done:
			if err == nil {
				passing = append(passing, filepath.Base(file))
			} else {
				failing = append(failing, filepath.Base(file))
			}
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
			timeout = append(timeout, filepath.Base(file))
		}
	}
	
	fmt.Printf("\nPassing (%d):\n", len(passing))
	for _, f := range passing {
		fmt.Printf("  ✓ %s\n", f)
	}
	
	fmt.Printf("\nFailing (%d):\n", len(failing))
	for _, f := range failing {
		fmt.Printf("  ✗ %s\n", f)
	}
	
	fmt.Printf("\nTimeout (%d):\n", len(timeout))
	for _, f := range timeout {
		fmt.Printf("  ⏱ %s\n", f)
	}
	
	fmt.Printf("\nTotal: %d/%d passing\n", len(passing), len(files))
}