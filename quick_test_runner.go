package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

func main() {
	pattern := filepath.Join("examples", "*.sn")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		panic(err)
	}

	passing := 0
	failing := 0
	timeouts := 0

	fmt.Println("Testing all examples with 2-second timeout...")
	
	for _, file := range matches {
		fmt.Printf("%-35s ... ", filepath.Base(file))
		
		cmd := exec.Command("C:\\Program Files\\Go\\bin\\go.exe", "run", "cmd/sentra/main.go", "run", file)
		cmd.Dir = "."
		
		done := make(chan error, 1)
		go func() {
			done <- cmd.Run()
		}()

		select {
		case err := <-done:
			if err != nil {
				fmt.Printf("FAIL\n")
				failing++
			} else {
				fmt.Printf("PASS\n")
				passing++
			}
		case <-time.After(2 * time.Second):
			cmd.Process.Kill()
			fmt.Printf("TIMEOUT\n")
			timeouts++
		}
	}

	total := passing + failing + timeouts
	successRate := float64(passing) / float64(total) * 100
	
	fmt.Printf("\n==================================================\n")
	fmt.Printf("FINAL RESULTS:\n")
	fmt.Printf("PASSED:   %2d/%d (%.1f%%)\n", passing, total, successRate)
	fmt.Printf("FAILED:   %2d/%d\n", failing, total)
	fmt.Printf("TIMEOUT:  %2d/%d\n", timeouts, total)
	fmt.Printf("SUCCESS RATE: %.1f%%\n", successRate)
}