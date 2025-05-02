// cmd/sentra/main.go
package main

import (
	"fmt"
	"log"
	"os"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
	"sentra/internal/repl"
	"sentra/internal/vm"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "repl" {
		repl.Start()
		return
	}

	if args[0] == "run" && len(args) > 1 {
		source, err := os.ReadFile(args[1])
		if err != nil {
			log.Fatalf("Could not read file: %v", err)
		}

		// Optionally load prelude first
		var fullSource []byte
		// prelude, err := os.ReadFile("prelude.sn")
		// if err == nil {
		// 	fullSource = append(prelude, '\n')
		// }
		// fullSource = append(fullSource, source...)
		fullSource = source

		// --- Add these lines here ---
		// fmt.Println("===== FULL SOURCE CODE =====")
		// fmt.Println(string(fullSource))
		// fmt.Println("============================")

		tokens := lexer.NewScanner(string(fullSource)).ScanTokens()

		// --- And here ---
		// fmt.Println("===== TOKENS =====")
		// for _, t := range tokens {
		// 	fmt.Println(t)
		// }
		// fmt.Println("==================")
		// -----------------------------

		stmts := parser.NewParser(tokens).Parse()
		compiler := compiler.NewStmtCompiler()
		chunk := compiler.Compile(stmts)

		vm.NewVM(chunk).Run()		
		return
	}

	fmt.Println("Usage:")
	fmt.Println("  sentra repl")
	fmt.Println("  sentra run file.sn")
}
