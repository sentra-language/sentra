package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func main() {
	examples := []string{
		"examples/arrays_and_maps.sn",
		"examples/algorithms.sn",
		"examples/advanced_functions.sn",
		"examples/memory_forensics.sn",
	}
	
	for _, example := range examples {
		fmt.Printf("Testing %s... ", example)
		
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		cmd := exec.CommandContext(ctx, "C:\\Program Files\\Go\\bin\\go.exe", "run", "cmd/sentra/main.go", "run", example)
		err := cmd.Run()
		
		if err != nil {
			fmt.Printf("❌ FAILED: %v\n", err)
		} else {
			fmt.Printf("✅ PASSED\n")
		}
	}
}