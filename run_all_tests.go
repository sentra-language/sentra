package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	files, err := filepath.Glob("examples/*.sn")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	passed := 0
	failed := 0
	
	for _, file := range files {
		// Skip the intentionally failing test
		if strings.Contains(file, "failing_test.sn") {
			continue
		}
		
		cmd := exec.Command("go", "run", "cmd/sentra/main.go", "run", file)
		err := cmd.Run()
		
		if err == nil {
			fmt.Printf("✅ PASS: %s\n", filepath.Base(file))
			passed++
		} else {
			fmt.Printf("❌ FAIL: %s\n", filepath.Base(file))
			failed++
		}
	}
	
	total := passed + failed
	percentage := float64(passed) / float64(total) * 100
	
	fmt.Printf("\n📊 Test Results: %d/%d passing (%.1f%%)\n", passed, total, percentage)
}