package main

import (
	"fmt"
	"os/exec"
	"time"
)

func main() {
	fmt.Println("Starting process enumeration test...")
	start := time.Now()
	
	cmd := exec.Command("tasklist", "/fo", "csv")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
	fmt.Printf("Got %d bytes of output in %v\n", len(output), time.Since(start))
	fmt.Println("Test complete")
}