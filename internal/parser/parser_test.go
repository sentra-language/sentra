package parser

import (
	"fmt"
	"sentra/internal/lexer"
	"testing"
)

// Test helper to parse a string and check for errors
func parseString(input string) (stmts []Stmt, errs []error) {
	defer func() {
		if r := recover(); r != nil {
			// Convert panic to error
			if err, ok := r.(error); ok {
				errs = append(errs, err)
			} else {
				errs = append(errs, fmt.Errorf("parser panic: %v", r))
			}
			stmts = nil
		}
	}()
	
	scanner := lexer.NewScanner(input)
	tokens := scanner.ScanTokens()
	parser := NewParser(tokens)
	stmts = parser.Parse()
	errs = parser.Errors
	return
}

// Test helper to check if parsing succeeds
func assertParseSuccess(t *testing.T, input string, description string) []Stmt {
	stmts, errs := parseString(input)
	if len(errs) > 0 {
		t.Errorf("%s: parsing failed with errors: %v", description, errs)
		return nil
	}
	if stmts == nil {
		t.Errorf("%s: parsing returned nil statements", description)
		return nil
	}
	return stmts
}

// Test helper to check if parsing fails
func assertParseError(t *testing.T, input string, description string) {
	_, errs := parseString(input)
	if len(errs) == 0 {
		t.Errorf("%s: expected parsing to fail but it succeeded", description)
	}
}

// ===== Variable Declaration Tests =====

func TestVariableDeclarations(t *testing.T) {
	tests := []struct {
		name  string
		input string
		shouldPass bool
	}{
		{"let declaration", "let x = 5", true},
		{"var declaration", "var x = 5", true},
		{"let without init", "let x", true}, // Parser allows it
		{"multiple declarations", "let x = 5\nlet y = 10", true},
		{"redeclaration same scope", "let x = 5\nlet x = 10", true}, // Currently allowed
		{"unicode variable name", "let 你好 = 5", true},
		{"emoji variable name", "let 🚀 = 5", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.shouldPass {
				assertParseSuccess(t, test.input, test.name)
			} else {
				assertParseError(t, test.input, test.name)
			}
		})
	}
}

// ===== String Literal Tests =====

func TestStringLiterals(t *testing.T) {
	tests := []struct {
		name  string
		input string
		shouldPass bool
	}{
		{"simple string", `let x = "hello"`, true},
		{"string with spaces", `let x = "hello world"`, true},
		{"empty string", `let x = ""`, true},
		{"string with escapes", `let x = "hello\nworld"`, true},
		{"string with quotes", `let x = "hello \"world\""`, true},
		{"template literal", "let x = `hello world`", true},
		{"template with newline", "let x = `hello\nworld`", true},
		{"unicode in string", `let x = "你好世界"`, true},
		{"emoji in string", `let x = "🚀 rocket"`, true},
		{"unterminated string", `let x = "hello`, false},
		{"mixed quotes", `let x = "hello'`, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.shouldPass {
				assertParseSuccess(t, test.input, test.name)
			} else {
				assertParseError(t, test.input, test.name)
			}
		})
	}
}

// ===== Map Literal Tests =====

func TestMapLiterals(t *testing.T) {
	tests := []struct {
		name  string
		input string
		shouldPass bool
	}{
		{"empty map", `let x = {}`, true},
		{"simple map", `let x = {"key": "value"}`, true},
		{"numeric keys", `let x = {1: "one", 2: "two"}`, true},
		{"identifier keys", `let x = {key: "value"}`, true},
		{"quoted keys", `let x = {"key": "value"}`, true},
		{"nested map", `let x = {"outer": {"inner": "value"}}`, true},
		{"map with array", `let x = {"items": [1, 2, 3]}`, true},
		{"trailing comma", `let x = {"key": "value",}`, true},
		{"unicode keys", `let x = {"你好": "world"}`, true},
		{"special char keys", `let x = {"access_key": "value"}`, true},
		{"computed keys", `let x = {[expr]: "value"}`, true},
		{"missing colon", `let x = {"key" "value"}`, false},
		{"missing comma", `let x = {"a": 1 "b": 2}`, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.shouldPass {
				assertParseSuccess(t, test.input, test.name)
			} else {
				assertParseError(t, test.input, test.name)
			}
		})
	}
}

// ===== Function Declaration Tests =====

func TestFunctionDeclarations(t *testing.T) {
	tests := []struct {
		name  string
		input string
		shouldPass bool
	}{
		{"simple function", `fn test() { return 1 }`, true},
		{"function with params", `fn test(a, b) { return a + b }`, true},
		{"function with body", `fn test() { let x = 1; return x }`, true},
		{"arrow function", `let f = fn(x) => x * 2`, true},
		{"nested function", `fn outer() { fn inner() { return 1 } return inner() }`, true},
		{"function hoisting test", `let x = test(); fn test() { return 1 }`, true},
		{"recursive function", `fn fact(n) { if n <= 1 { return 1 } return n * fact(n-1) }`, true},
		{"function without body", `fn test()`, false},
		{"function missing paren", `fn test { return 1 }`, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.shouldPass {
				assertParseSuccess(t, test.input, test.name)
			} else {
				assertParseError(t, test.input, test.name)
			}
		})
	}
}

// ===== For Loop Tests =====

func TestForLoops(t *testing.T) {
	tests := []struct {
		name  string
		input string
		shouldPass bool
	}{
		{"c-style for loop", `for (let i = 0; i < 10; i = i + 1) { log(i) }`, true},
		{"for-in loop", `for x in [1, 2, 3] { log(x) }`, true},
		{"for-in with let", `for let x in [1, 2, 3] { log(x) }`, true},
		{"nested for loops", `for (let i = 0; i < 5; i = i + 1) { for (let j = 0; j < 5; j = j + 1) { log(i + j) } }`, true},
		{"for with break", `for (let i = 0; i < 10; i = i + 1) { if i == 5 { break } }`, true},
		{"for with continue", `for (let i = 0; i < 10; i = i + 1) { if i == 5 { continue } }`, true},
		{"infinite for", `for { log("infinite") }`, true},
		{"for without body", `for (let i = 0; i < 10; i = i + 1)`, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.shouldPass {
				assertParseSuccess(t, test.input, test.name)
			} else {
				assertParseError(t, test.input, test.name)
			}
		})
	}
}

// ===== Variable Scoping Tests =====

func TestVariableScoping(t *testing.T) {
	tests := []struct {
		name  string
		input string
		shouldPass bool
	}{
		{
			"nested scope redeclaration",
			`let x = 1
			{
				let x = 2
				log(x)
			}
			log(x)`,
			true,
		},
		{
			"function scope",
			`let x = 1
			fn test() {
				let x = 2
				return x
			}`,
			true,
		},
		{
			"loop variable scope",
			`for (let i = 0; i < 5; i = i + 1) {
				log(i)
			}
			for (let i = 0; i < 5; i = i + 1) {
				log(i)
			}`,
			true,
		},
		{
			"multiple loop vars same name",
			`let i = 0
			while i < 5 {
				i = i + 1
			}
			let i = 10`,
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.shouldPass {
				assertParseSuccess(t, test.input, test.name)
			} else {
				assertParseError(t, test.input, test.name)
			}
		})
	}
}

// ===== Edge Cases Tests =====

func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		shouldPass bool
	}{
		{"empty program", "", true},
		{"only whitespace", "   \n\t  ", true},
		{"only comments", "// comment\n/* block */", true},
		{"statement without semicolon", "let x = 5\nlet y = 10", true},
		{"expression statement", "5 + 3", true},
		{"chained operations", "a.b.c.d()", true},
		{"complex expression", "(a + b) * (c - d) / e", true},
		{"ternary operator", "let x = a > b ? a : b", true},
		{"array indexing", "let x = arr[0][1][2]", true},
		{"map access", `let x = obj["key"]["nested"]`, true},
		{"function call chain", "fn1()()()", true},
		{"mixed brackets", "let x = arr[obj[key]]", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.shouldPass {
				assertParseSuccess(t, test.input, test.name)
			} else {
				assertParseError(t, test.input, test.name)
			}
		})
	}
}

// ===== Error Handling Tests =====

func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name  string
		input string
		shouldPass bool
	}{
		{"try-catch", `try { risky() } catch e { log(e) }`, true},
		{"try-catch-finally", `try { risky() } catch e { log(e) } finally { cleanup() }`, true},
		{"try-finally", `try { risky() } finally { cleanup() }`, true},
		{"throw statement", `throw "error"`, true},
		{"throw in function", `fn test() { throw "error" }`, true},
		{"nested try", `try { try { risky() } catch e { throw e } } catch e { log(e) }`, true},
		{"try without catch/finally", `try { risky() }`, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.shouldPass {
				assertParseSuccess(t, test.input, test.name)
			} else {
				assertParseError(t, test.input, test.name)
			}
		})
	}
}

// ===== Pattern Matching Tests =====

func TestPatternMatching(t *testing.T) {
	tests := []struct {
		name  string
		input string
		shouldPass bool
	}{
		{"simple match", `match x { 1 => log("one"), 2 => log("two"), _ => log("other") }`, true},
		{"match without default", `match x { 1 => log("one"), 2 => log("two") }`, true},
		{"match with blocks", `match x { 1 => { log("one") }, 2 => { log("two") } }`, true},
		{"nested match", `match x { 1 => match y { 1 => log("1,1") } }`, true},
		{"match without cases", `match x { }`, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.shouldPass {
				assertParseSuccess(t, test.input, test.name)
			} else {
				assertParseError(t, test.input, test.name)
			}
		})
	}
}

// ===== Import/Export Tests =====

func TestImportExport(t *testing.T) {
	tests := []struct {
		name  string
		input string
		shouldPass bool
	}{
		{"simple import", `import "module"`, true},
		{"import with alias", `import "module" as mod`, true},
		{"import builtin", `import math`, true},
		{"multiple imports", `import math\nimport string`, true},
		{"export function", `export fn test() { return 1 }`, true},
		{"export variable", `export let x = 5`, true},
		{"invalid import", `import`, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.shouldPass {
				assertParseSuccess(t, test.input, test.name)
			} else {
				assertParseError(t, test.input, test.name)
			}
		})
	}
}

// ===== Benchmark Tests =====

func BenchmarkParseSimpleProgram(b *testing.B) {
	input := `let x = 5; let y = 10; let z = x + y`
	for i := 0; i < b.N; i++ {
		parseString(input)
	}
}

func BenchmarkParseComplexProgram(b *testing.B) {
	input := `
	fn fibonacci(n) {
		if n <= 1 {
			return n
		}
		return fibonacci(n - 1) + fibonacci(n - 2)
	}
	
	for (let i = 0; i < 10; i = i + 1) {
		log(fibonacci(i))
	}
	`
	for i := 0; i < b.N; i++ {
		parseString(input)
	}
}

func BenchmarkParseLargeMap(b *testing.B) {
	input := `let data = {
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
		"key4": "value4",
		"key5": "value5",
		"nested": {
			"inner1": "value1",
			"inner2": "value2"
		}
	}`
	for i := 0; i < b.N; i++ {
		parseString(input)
	}
}