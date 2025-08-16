package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

func main() {
	files, err := filepath.Glob("examples/*.sn")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
	passing := 0
	failing := 0
	
	for _, file := range files {
		cmd := exec.Command("go", "run", "cmd/sentra/main.go", "run", file)
		done := make(chan error, 1)
		go func() {
			done <- cmd.Run()
		}()
		
		select {
		case err := <-done:
			if err == nil {
				passing++
				fmt.Printf("✓ %s\n", filepath.Base(file))
			} else {
				failing++
				fmt.Printf("✗ %s\n", filepath.Base(file))
			}
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
			failing++
			fmt.Printf("✗ %s (timeout)\n", filepath.Base(file))
		}
	}
	
	fmt.Printf("\n%d/%d tests passing\n", passing, len(files))
}