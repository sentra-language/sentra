package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	pattern := filepath.Join("examples", "*.sn")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		panic(err)
	}

	fmt.Println("=== DETAILED FAILURE ANALYSIS ===\n")
	
	for _, file := range matches {
		cmd := exec.Command("C:\\Program Files\\Go\\bin\\go.exe", "run", "cmd/sentra/main.go", "run", file)
		cmd.Dir = "."
		
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		
		done := make(chan error, 1)
		go func() {
			done <- cmd.Run()
		}()

		select {
		case err := <-done:
			if err != nil {
				errorOutput := stderr.String()
				if strings.Contains(errorOutput, "Runtime error") {
					// Extract the specific error
					lines := strings.Split(errorOutput, "\n")
					for _, line := range lines {
						if strings.Contains(line, "Runtime error") {
							fmt.Printf("%-35s: %s\n", filepath.Base(file), strings.TrimSpace(line))
							break
						}
					}
				} else if strings.Contains(errorOutput, "panic") {
					fmt.Printf("%-35s: PANIC (expected for test file)\n", filepath.Base(file))
				} else {
					fmt.Printf("%-35s: OTHER ERROR\n", filepath.Base(file))
				}
			}
		case <-time.After(2 * time.Second):
			cmd.Process.Kill()
			fmt.Printf("%-35s: TIMEOUT\n", filepath.Base(file))
		}
	}
}