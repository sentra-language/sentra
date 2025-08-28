package main

import (
	"fmt"
	"os/exec"
	"time"
)

func main() {
	examples := []string{
		"hello.sn",
		"math.sn", 
		"arrays_and_maps.sn",
		"security_hash.sn",
		"threat_detection.sn",
		"os_simple.sn",
		"os_security.sn",
		"advanced_functions.sn",
		"algorithms.sn",
		"control_flow.sn",
		"error_handling.sn",
		"concurrency_showcase.sn",
	}
	
	passed := 0
	failed := 0
	timeouts := 0
	
	for _, example := range examples {
		fmt.Printf("Testing %s... ", example)
		
		// Run with timeout
		cmd := exec.Command("C:/Program Files/Go/bin/go.exe", "run", "cmd/sentra/main.go", "run", "examples/"+example)
		cmd.Dir = "C:/Users/pc/Projects/sentra"
		
		done := make(chan error, 1)
		go func() {
			done <- cmd.Run()
		}()
		
		select {
		case err := <-done:
			if err != nil {
				fmt.Printf("FAIL (%v)\n", err)
				failed++
			} else {
				fmt.Printf("PASS\n")
				passed++
			}
		case <-time.After(10 * time.Second):
			fmt.Printf("TIMEOUT\n")
			timeouts++
			cmd.Process.Kill()
		}
	}
	
	fmt.Printf("\n=== Results ===\n")
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", failed) 
	fmt.Printf("Timeouts: %d\n", timeouts)
	fmt.Printf("Total: %d\n", len(examples))
	fmt.Printf("Success Rate: %.1f%%\n", float64(passed)/float64(len(examples))*100)
}