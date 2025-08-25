package main

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"time"
)

func main() {
	pattern := filepath.Join("examples", "*.sn")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Fatal(err)
	}

	passed := 0
	failed := 0
	timeout := 0

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
				failed++
			} else {
				passed++
			}
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
			timeout++
		}
	}

	total := passed + failed + timeout
	fmt.Printf("Final Results: %d/%d tests passing (%.1f%%)\n", passed, total, float64(passed)/float64(total)*100)
	fmt.Printf("Passed: %d, Failed: %d, Timeout: %d\n", passed, failed, timeout)
}