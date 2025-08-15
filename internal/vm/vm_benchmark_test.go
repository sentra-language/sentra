package vm

import (
	"sentra/internal/bytecode"
	"sentra/internal/compiler"
	"sentra/internal/lexer"
	"sentra/internal/parser"
	"testing"
)

func compileSource(source string) *bytecode.Chunk {
	tokens := lexer.NewScanner(source).ScanTokens()
	stmts := parser.NewParser(tokens).Parse()
	comp := compiler.NewStmtCompiler()
	return comp.Compile(stmts)
}

func BenchmarkVMArithmetic(b *testing.B) {
	source := `
		let x = 10
		let y = 20
		let z = x + y * 2 - 5
	`
	chunk := compileSource(source)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm := NewEnhancedVM(chunk)
		vm.Run()
	}
}

func BenchmarkFunctionCall(b *testing.B) {
	source := `
		fn add(a, b) {
			return a + b
		}
		let result = add(10, 20)
	`
	chunk := compileSource(source)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm := NewEnhancedVM(chunk)
		vm.Run()
	}
}

func BenchmarkWhileLoop(b *testing.B) {
	source := `
		let i = 0
		let sum = 0
		while i < 100 {
			sum = sum + i
			i = i + 1
		}
	`
	chunk := compileSource(source)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm := NewEnhancedVM(chunk)
		vm.Run()
	}
}

func BenchmarkVMArrayCreation(b *testing.B) {
	source := `
		let arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
	`
	chunk := compileSource(source)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm := NewEnhancedVM(chunk)
		vm.Run()
	}
}

func BenchmarkMapCreation(b *testing.B) {
	source := `
		let person = {
			"name": "Alice",
			"age": 30,
			"city": "New York"
		}
	`
	chunk := compileSource(source)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm := NewEnhancedVM(chunk)
		vm.Run()
	}
}

func BenchmarkStringConcat(b *testing.B) {
	source := `
		let a = "Hello"
		let b = "World"
		let c = a + ", " + b + "!"
	`
	chunk := compileSource(source)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm := NewEnhancedVM(chunk)
		vm.Run()
	}
}

func BenchmarkIfStatement(b *testing.B) {
	source := `
		let x = 10
		if x > 5 {
			let y = x * 2
		} else {
			let y = x / 2
		}
	`
	chunk := compileSource(source)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm := NewEnhancedVM(chunk)
		vm.Run()
	}
}