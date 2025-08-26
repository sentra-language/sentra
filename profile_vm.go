package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
	"sentra/internal/vm"
)

func main() {
	// CPU profiling
	cpuFile, err := os.Create("cpu_profile.prof")
	if err != nil {
		panic(err)
	}
	defer cpuFile.Close()
	
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		panic(err)
	}
	defer pprof.StopCPUProfile()

	// Simple benchmark program
	source := `
		// Arithmetic intensive
		let sum = 0
		for (let i = 0; i < 10000; i = i + 1) {
			sum = sum + i * 2 - 1
			sum = sum / 1.1
			sum = sum % 1000
		}
		
		// Array operations
		let arr = []
		for (let i = 0; i < 1000; i = i + 1) {
			push(arr, i)
			push(arr, i * 2)
		}
		
		log("Sum: " + sum + ", Array length: " + len(arr))
	`

	// Parse and compile
	scanner := lexer.NewScannerWithFile(source, "profile_test.sn")
	tokens := scanner.ScanTokens()
	
	p := parser.NewParserWithSource(tokens, source, "profile_test.sn")
	parsed := p.Parse()
	
	// Convert to interface{} slice
	var stmts []interface{}
	for _, stmt := range parsed {
		stmts = append(stmts, stmt)
	}
	
	compiler := compiler.NewStmtCompilerWithDebug("profile_test.sn")
	chunk := compiler.Compile(stmts)

	// Profile standard VM
	fmt.Println("Profiling Standard EnhancedVM...")
	start := time.Now()
	
	for i := 0; i < 10; i++ { // Run multiple times for better profiling
		enhancedVM := vm.NewEnhancedVM(chunk)
		_, err := enhancedVM.Run()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	}
	
	standardTime := time.Since(start)
	fmt.Printf("Standard VM (10 runs): %v\n", standardTime)

	// Profile FastVM
	fmt.Println("Profiling FastVM...")
	start = time.Now()
	
	for i := 0; i < 10; i++ {
		fastVM := vm.NewFastVM(chunk)
		_, err := fastVM.OptimizedRun()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	}
	
	fastTime := time.Since(start)
	fmt.Printf("Fast VM (10 runs): %v\n", fastTime)
	
	improvement := float64(standardTime-fastTime) / float64(standardTime) * 100
	fmt.Printf("Improvement: %.1f%%\n", improvement)

	// Memory profiling
	memFile, err := os.Create("mem_profile.prof")
	if err != nil {
		panic(err)
	}
	defer memFile.Close()
	
	runtime.GC() // Force GC before profiling
	if err := pprof.WriteHeapProfile(memFile); err != nil {
		panic(err)
	}
	
	fmt.Println("Profiling complete. Files: cpu_profile.prof, mem_profile.prof")
}