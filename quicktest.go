package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	files, _ := filepath.Glob("examples/*.sn")
	
	passed := 0
	failed := 0
	var failedFiles []string
	
	for _, file := range files {
		if strings.Contains(file, "failing_test.sn") {
			continue
		}
		
		// Run with timeout
		cmd := exec.Command("go", "run", "cmd/sentra/main.go", "run", file)
		done := make(chan error, 1)
		
		go func() {
			done <- cmd.Run()
		}()
		
		select {
		case err := <-done:
			if err == nil {
				passed++
				fmt.Printf("✅ %s\n", filepath.Base(file))
			} else {
				failed++
				failedFiles = append(failedFiles, filepath.Base(file))
				fmt.Printf("❌ %s\n", filepath.Base(file))
			}
		case <-time.After(2 * time.Second):
			cmd.Process.Kill()
			failed++
			failedFiles = append(failedFiles, filepath.Base(file)+" (timeout)")
			fmt.Printf("⏱️ %s (timeout)\n", filepath.Base(file))
		}
	}
	
	fmt.Printf("\n📊 Results: %d/%d passing (%.1f%%)\n", passed, passed+failed, 
		float64(passed)/float64(passed+failed)*100)
	
	if len(failedFiles) > 0 {
		fmt.Println("\n❌ Failed files:")
		for _, f := range failedFiles {
			fmt.Printf("  - %s\n", f)
		}
	}
}