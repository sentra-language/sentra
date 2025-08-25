// internal/compiler/hoisting_compiler.go
package compiler

import (
	"sentra/internal/bytecode"
	"sentra/internal/parser"
)

// HoistingCompiler implements function hoisting by doing two-pass compilation
type HoistingCompiler struct {
	*StmtCompiler
	functions      map[string]*parser.FunctionStmt // Collected function declarations
	functionIndexes map[string]int                   // Function name to global index mapping
}

// NewHoistingCompiler creates a compiler with function hoisting support
func NewHoistingCompiler() *HoistingCompiler {
	return &HoistingCompiler{
		StmtCompiler:    NewStmtCompiler(),
		functions:       make(map[string]*parser.FunctionStmt),
		functionIndexes: make(map[string]int),
	}
}

// NewHoistingCompilerWithDebug creates a compiler with function hoisting and debug support
func NewHoistingCompilerWithDebug(fileName string) *HoistingCompiler {
	return &HoistingCompiler{
		StmtCompiler:    NewStmtCompilerWithDebug(fileName),
		functions:       make(map[string]*parser.FunctionStmt),
		functionIndexes: make(map[string]int),
	}
}

// CompileWithHoisting performs two-pass compilation for function hoisting
func (hc *HoistingCompiler) CompileWithHoisting(stmts []parser.Stmt) *bytecode.Chunk {
	// First pass: Collect all function declarations
	hc.collectFunctions(stmts)
	
	// Pre-compile all functions and register them as globals
	hc.precompileFunctions()
	
	// Second pass: Compile all statements with functions available
	for _, stmt := range stmts {
		stmt.Accept(hc)
	}
	
	hc.emitOp(bytecode.OpReturn)
	return hc.Chunk
}

// collectFunctions walks through statements and collects function declarations
func (hc *HoistingCompiler) collectFunctions(stmts []parser.Stmt) {
	for _, stmt := range stmts {
		hc.collectFunctionFromStmt(stmt)
	}
}

// collectFunctionFromStmt recursively collects functions from a statement
func (hc *HoistingCompiler) collectFunctionFromStmt(stmt parser.Stmt) {
	switch s := stmt.(type) {
	case *parser.FunctionStmt:
		// Store the function declaration
		hc.functions[s.Name] = s
		
	// Note: BlockStmt doesn't exist, statements are in arrays
		
	case *parser.IfStmt:
		// Check then branch
		for _, thenStmt := range s.Then {
			hc.collectFunctionFromStmt(thenStmt)
		}
		// Check else branch if it exists
		if s.Else != nil {
			for _, elseStmt := range s.Else {
				hc.collectFunctionFromStmt(elseStmt)
			}
		}
		
	case *parser.WhileStmt:
		// Check body
		for _, bodyStmt := range s.Body {
			hc.collectFunctionFromStmt(bodyStmt)
		}
		
	case *parser.ForStmt:
		// Check body
		for _, bodyStmt := range s.Body {
			hc.collectFunctionFromStmt(bodyStmt)
		}
		
	case *parser.TryStmt:
		// Check try block
		for _, tryStmt := range s.TryBlock {
			hc.collectFunctionFromStmt(tryStmt)
		}
		// Check catch block if it exists
		if s.CatchBlock != nil {
			for _, catchStmt := range s.CatchBlock {
				hc.collectFunctionFromStmt(catchStmt)
			}
		}
		// Check finally block if it exists
		if s.FinallyBlock != nil {
			for _, finallyStmt := range s.FinallyBlock {
				hc.collectFunctionFromStmt(finallyStmt)
			}
		}
	}
}

// precompileFunctions compiles all collected functions and registers them
func (hc *HoistingCompiler) precompileFunctions() {
	// Process all functions in a deterministic order
	functionNames := make([]string, 0, len(hc.functions))
	for name := range hc.functions {
		functionNames = append(functionNames, name)
	}
	
	// Process each function
	for _, name := range functionNames {
		fnStmt := hc.functions[name]
		// Create a new chunk for the function
		fnChunk := bytecode.NewChunk()
		
		// Create a new compiler for the function body
		fnCompiler := NewStmtCompilerWithDebug(hc.FileName)
		fnCompiler.Chunk = fnChunk
		fnCompiler.currentFunction = &Function{
			Name:   name,
			Arity:  len(fnStmt.Params),
			Params: fnStmt.Params,
			Chunk:  fnChunk,
		}
		fnCompiler.parent = hc.StmtCompiler
		
		// Add parameters as locals
		for _, param := range fnStmt.Params {
			fnCompiler.locals = append(fnCompiler.locals, param)
			fnCompiler.localCount++
		}
		
		// Compile the function body
		for _, stmt := range fnStmt.Body {
			stmt.Accept(fnCompiler)
		}
		
		// Add implicit return if not present
		if len(fnChunk.Code) == 0 || 
		   bytecode.OpCode(fnChunk.Code[len(fnChunk.Code)-1]) != bytecode.OpReturn {
			fnCompiler.emitOp(bytecode.OpReturn)
		}
		
		// Create function object
		fn := &Function{
			Name:   name,
			Arity:  len(fnStmt.Params),
			Params: fnStmt.Params,
			Chunk:  fnChunk,
		}
		
		// Add function object as a constant
		fnIndex := hc.Chunk.AddConstant(fn)
		
		// Add function name as a constant (do this AFTER the function object)
		nameIndex := hc.Chunk.AddConstant(name)
		hc.functionIndexes[name] = nameIndex
		
		// Load the function object and define it as a global
		hc.emitOp(bytecode.OpConstant)
		hc.emitByte(byte(fnIndex))
		hc.emitOp(bytecode.OpDefineGlobal)
		hc.emitByte(byte(nameIndex))
	}
}

// Override VisitFunctionStmt to skip function declarations (already processed)
func (hc *HoistingCompiler) VisitFunctionStmt(stmt *parser.FunctionStmt) interface{} {
	// Functions are already compiled in precompileFunctions
	// Skip them during the main compilation pass
	return nil
}

// Override VisitCallExpr to check for hoisted functions
func (hc *HoistingCompiler) VisitCallExpr(expr *parser.CallExpr) interface{} {
	// Check if this is a call to a hoisted function
	if varExpr, ok := expr.Callee.(*parser.Variable); ok {
		if globalIndex, exists := hc.functionIndexes[varExpr.Name]; exists {
			// Load the hoisted function
			hc.emitOp(bytecode.OpGetGlobal)
			hc.emitByte(byte(globalIndex))
			
			// Compile arguments
			for _, arg := range expr.Args {
				arg.Accept(hc)
			}
			
			// Emit call instruction
			hc.emitOp(bytecode.OpCall)
			hc.emitByte(byte(len(expr.Args)))
			return nil
		}
	}
	
	// Fall back to default behavior
	expr.Callee.Accept(hc)
	for _, arg := range expr.Args {
		arg.Accept(hc)
	}
	hc.emitOp(bytecode.OpCall)
	hc.emitByte(byte(len(expr.Args)))
	return nil
}