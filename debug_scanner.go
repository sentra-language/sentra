package main

import (
	"fmt"
	"strings"
	"sentra/internal/lexer"
)

func main() {
	source := `// Simple test for error reporting
fn test() {
    log("missing paren"
}`
	fmt.Printf("Source:\n%s\n", source)
	fmt.Printf("Lines in source: %d\n", len(strings.Split(source, "\n")))
	
	scanner := lexer.NewScannerWithFile(source, "debug.sn")
	tokens := scanner.ScanTokens()
	
	for _, token := range tokens {
		fmt.Printf("Token: %s, Lexeme: '%s', Line: %d, Column: %d\n", 
			token.Type, token.Lexeme, token.Line, token.Column)
	}
}