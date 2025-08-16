// internal/compiler/stmt_compiler.go
package compiler

import (
	"sentra/internal/bytecode"
	"sentra/internal/parser"
)

type StmtCompiler struct {
	Chunk           *bytecode.Chunk
	currentFunction *Function
	fileName        string
	currentLine     int
	currentColumn   int
	locals          []string  // Track local variables in current function
	localCount      int       // Number of locals
	parent          *StmtCompiler // Parent compiler for closures
}

type Function struct {
	Name   string
	Arity  int
	Params []string
	Chunk  *bytecode.Chunk
}

func NewStmtCompiler() *StmtCompiler {
	return &StmtCompiler{
		Chunk: bytecode.NewChunk(),
		currentFunction: &Function{
			Name:   "<script>",
			Arity:  0,
			Params: []string{},
			Chunk:  nil, // Will be set later
		},
	}
}

func NewStmtCompilerWithDebug(fileName string) *StmtCompiler {
	return &StmtCompiler{
		Chunk: bytecode.NewChunk(),
		currentFunction: &Function{
			Name:   "<script>",
			Arity:  0,
			Params: []string{},
			Chunk:  nil, // Will be set later
		},
		fileName: fileName,
	}
}

func (c *StmtCompiler) Compile(stmts []interface{}) *bytecode.Chunk {
	c.currentLine = 1 // Start from line 1
	for i, stmt := range stmts {
		if s, ok := stmt.(parser.Stmt); ok {
			c.currentLine = i + 1 // Simple line estimation
			s.Accept(c)
		}
	}
	c.emitOp(bytecode.OpReturn)
	return c.Chunk
}

// Helper methods for emitting bytecode with debug info
func (c *StmtCompiler) emitOp(op bytecode.OpCode) {
	debug := bytecode.DebugInfo{
		Line:     c.currentLine,
		Column:   c.currentColumn,
		File:     c.fileName,
		Function: c.currentFunction.Name,
	}
	c.Chunk.WriteOpWithDebug(op, debug)
}

func (c *StmtCompiler) emitByte(b byte) {
	debug := bytecode.DebugInfo{
		Line:     c.currentLine,
		Column:   c.currentColumn,
		File:     c.fileName,
		Function: c.currentFunction.Name,
	}
	c.Chunk.WriteByteWithDebug(b, debug)
}

func (c *StmtCompiler) VisitPrintStmt(stmt *parser.PrintStmt) interface{} {
	stmt.Expr.Accept(c)
	c.emitOp(bytecode.OpPrint)
	return nil
}

func (c *StmtCompiler) VisitLetStmt(stmt *parser.LetStmt) interface{} {
	stmt.Expr.Accept(c)
	
	// If we're inside a function, create a local
	if c.currentFunction != nil && c.currentFunction.Name != "<script>" {
		c.locals = append(c.locals, stmt.Name)
		localSlot := c.localCount
		c.localCount++
		// Emit OpSetLocal to store the value in the local slot
		c.emitOp(bytecode.OpSetLocal)
		c.emitByte(byte(localSlot))
	} else {
		// Global variable
		idx := c.Chunk.AddConstant(stmt.Name)
		c.emitOp(bytecode.OpDefineGlobal)
		c.emitByte(byte(idx))
	}
	return nil
}

func (c *StmtCompiler) VisitAssignmentStmt(stmt *parser.AssignmentStmt) interface{} {
	stmt.Value.Accept(c)
	
	// Check if this is a local variable
	if c.locals != nil {
		for i, local := range c.locals {
			if local == stmt.Name {
				c.Chunk.WriteOp(bytecode.OpSetLocal)
				c.Chunk.WriteByte(byte(i))
				return nil
			}
		}
	}
	
	// If not a local, treat it as a global
	idx := c.Chunk.AddConstant(stmt.Name)
	c.Chunk.WriteOp(bytecode.OpSetGlobal)
	c.Chunk.WriteByte(byte(idx))
	return nil
}

func (c *StmtCompiler) VisitIndexAssignmentStmt(stmt *parser.IndexAssignmentStmt) interface{} {
	// Push object
	stmt.Object.Accept(c)
	// Push index
	stmt.Index.Accept(c)
	// Push value
	stmt.Value.Accept(c)
	// Set index
	c.Chunk.WriteOp(bytecode.OpSetIndex)
	return nil
}

func (c *StmtCompiler) VisitExpressionStmt(stmt *parser.ExpressionStmt) interface{} {
	stmt.Expr.Accept(c)
	c.Chunk.WriteOp(bytecode.OpPop)
	return nil
}

func (c *StmtCompiler) VisitFunctionStmt(stmt *parser.FunctionStmt) interface{} {
	subCompiler := NewStmtCompiler()
	
	// Initialize locals tracking
	subCompiler.locals = make([]string, 0, 256)
	subCompiler.localCount = 0

	function := &Function{
		Name:   stmt.Name,
		Arity:  len(stmt.Params),
		Chunk:  subCompiler.Chunk,
		Params: stmt.Params,
	}

	// Set the current function for the subcompiler
	subCompiler.currentFunction = function
	
	// Add parameters as locals
	for _, param := range stmt.Params {
		subCompiler.locals = append(subCompiler.locals, param)
		subCompiler.localCount++
	}

	// Compile function body
	for _, s := range stmt.Body {
		s.Accept(subCompiler)
	}
	subCompiler.Chunk.WriteOp(bytecode.OpReturn)

	idx := c.Chunk.AddConstant(function)
	c.Chunk.WriteOp(bytecode.OpConstant)
	c.Chunk.WriteByte(byte(idx))

	nameIdx := c.Chunk.AddConstant(stmt.Name)
	c.Chunk.WriteOp(bytecode.OpDefineGlobal)
	c.Chunk.WriteByte(byte(nameIdx))

	return nil
}

func (c *StmtCompiler) VisitReturnStmt(stmt *parser.ReturnStmt) interface{} {
	if stmt.Value != nil {
		stmt.Value.Accept(c)
	} else {
		c.Chunk.WriteOp(bytecode.OpNil)
	}
	c.Chunk.WriteOp(bytecode.OpReturn)
	return nil
}

func (c *StmtCompiler) VisitIfStmt(stmt *parser.IfStmt) interface{} {
	// Compile condition
	stmt.Condition.Accept(c)
	
	// Jump if false (to else or end)
	c.Chunk.WriteOp(bytecode.OpJumpIfFalse)
	jumpIfFalsePos := len(c.Chunk.Code)
	c.Chunk.WriteByte(0) // Placeholder
	c.Chunk.WriteByte(0)
	
	// Compile then branch
	for _, s := range stmt.Then {
		s.Accept(c)
	}
	
	// Jump over else branch
	var jumpOverElsePos int
	if len(stmt.Else) > 0 {
		c.Chunk.WriteOp(bytecode.OpJump)
		jumpOverElsePos = len(c.Chunk.Code)
		c.Chunk.WriteByte(0) // Placeholder
		c.Chunk.WriteByte(0)
	}
	
	// Patch jump-if-false offset
	elseStart := len(c.Chunk.Code)
	jumpOffset := elseStart - jumpIfFalsePos - 2
	c.Chunk.Code[jumpIfFalsePos] = byte(jumpOffset >> 8)
	c.Chunk.Code[jumpIfFalsePos+1] = byte(jumpOffset & 0xff)
	
	// Compile else branch if present
	if len(stmt.Else) > 0 {
		for _, s := range stmt.Else {
			s.Accept(c)
		}
		
		// Patch jump-over-else offset
		endPos := len(c.Chunk.Code)
		jumpOffset = endPos - jumpOverElsePos - 2
		c.Chunk.Code[jumpOverElsePos] = byte(jumpOffset >> 8)
		c.Chunk.Code[jumpOverElsePos+1] = byte(jumpOffset & 0xff)
	}
	
	return nil
}

// New statement visitor methods

func (c *StmtCompiler) VisitWhileStmt(stmt *parser.WhileStmt) interface{} {
	loopStart := len(c.Chunk.Code)
	
	// Compile condition
	stmt.Condition.Accept(c)
	
	// Jump if false (exit loop)
	c.Chunk.WriteOp(bytecode.OpJumpIfFalse)
	jumpPos := len(c.Chunk.Code)
	c.Chunk.WriteByte(0) // Placeholder
	c.Chunk.WriteByte(0)
	
	// Compile body
	for _, s := range stmt.Body {
		s.Accept(c)
	}
	
	// Loop back
	c.Chunk.WriteOp(bytecode.OpLoop)
	loopOffset := len(c.Chunk.Code) - loopStart + 2 // +2 for the offset bytes
	c.Chunk.WriteByte(byte(loopOffset >> 8))
	c.Chunk.WriteByte(byte(loopOffset & 0xff))
	
	// Patch jump offset
	endPos := len(c.Chunk.Code)
	jumpOffset := endPos - jumpPos - 2
	c.Chunk.Code[jumpPos] = byte(jumpOffset >> 8)
	c.Chunk.Code[jumpPos+1] = byte(jumpOffset & 0xff)
	
	return nil
}

func (c *StmtCompiler) VisitForStmt(stmt *parser.ForStmt) interface{} {
	// Save the current local count to restore after the loop
	// This creates a new scope for the loop
	savedLocalCount := c.localCount
	savedLocals := c.locals
	if c.locals != nil {
		// Create a copy of locals for the new scope
		c.locals = make([]string, len(savedLocals))
		copy(c.locals, savedLocals)
	}
	
	// Compile initialization
	if stmt.Init != nil {
		stmt.Init.Accept(c)
	}
	
	loopStart := len(c.Chunk.Code)
	
	// Compile condition
	if stmt.Condition != nil {
		stmt.Condition.Accept(c)
	} else {
		// No condition means infinite loop (push true)
		idx := c.Chunk.AddConstant(true)
		c.Chunk.WriteOp(bytecode.OpConstant)
		c.Chunk.WriteByte(byte(idx))
	}
	
	// Jump if false (exit loop)
	c.Chunk.WriteOp(bytecode.OpJumpIfFalse)
	jumpPos := len(c.Chunk.Code)
	c.Chunk.WriteByte(0) // Placeholder
	c.Chunk.WriteByte(0)
	
	// Compile body
	for _, s := range stmt.Body {
		s.Accept(c)
	}
	
	// Compile update
	if stmt.Update != nil {
		stmt.Update.Accept(c)
		c.Chunk.WriteOp(bytecode.OpPop) // Pop update result
	}
	
	// Loop back
	c.Chunk.WriteOp(bytecode.OpLoop)
	loopOffset := len(c.Chunk.Code) - loopStart + 2 // +2 for the offset bytes
	c.Chunk.WriteByte(byte(loopOffset >> 8))
	c.Chunk.WriteByte(byte(loopOffset & 0xff))
	
	// Patch jump offset
	endPos := len(c.Chunk.Code)
	jumpOffset := endPos - jumpPos - 2
	c.Chunk.Code[jumpPos] = byte(jumpOffset >> 8)
	c.Chunk.Code[jumpPos+1] = byte(jumpOffset & 0xff)
	
	// Restore the local scope
	c.localCount = savedLocalCount
	c.locals = savedLocals
	
	return nil
}

func (c *StmtCompiler) VisitForInStmt(stmt *parser.ForInStmt) interface{} {
	// Compile collection
	stmt.Collection.Accept(c)
	
	// Start iteration
	c.Chunk.WriteOp(bytecode.OpIterStart)
	
	loopStart := len(c.Chunk.Code)
	
	// Check if iteration is done
	c.Chunk.WriteOp(bytecode.OpIterNext)
	c.Chunk.WriteOp(bytecode.OpJumpIfFalse)
	jumpPos := len(c.Chunk.Code)
	c.Chunk.WriteByte(0) // Placeholder
	c.Chunk.WriteByte(0)
	
	// Store iteration value in variable
	idx := c.Chunk.AddConstant(stmt.Variable)
	c.Chunk.WriteOp(bytecode.OpDefineGlobal)
	c.Chunk.WriteByte(byte(idx))
	
	// Compile body
	for _, s := range stmt.Body {
		s.Accept(c)
	}
	
	// Loop back
	c.Chunk.WriteOp(bytecode.OpLoop)
	loopOffset := len(c.Chunk.Code) - loopStart + 2 // +2 for the offset bytes
	c.Chunk.WriteByte(byte(loopOffset >> 8))
	c.Chunk.WriteByte(byte(loopOffset & 0xff))
	
	// Patch jump offset
	endPos := len(c.Chunk.Code)
	jumpOffset := endPos - jumpPos - 2
	c.Chunk.Code[jumpPos] = byte(jumpOffset >> 8)
	c.Chunk.Code[jumpPos+1] = byte(jumpOffset & 0xff)
	
	// End iteration
	c.Chunk.WriteOp(bytecode.OpIterEnd)
	
	return nil
}

func (c *StmtCompiler) VisitBreakStmt(stmt *parser.BreakStmt) interface{} {
	// For now, just emit a no-op with nil
	// Proper implementation requires loop context tracking
	idx := c.Chunk.AddConstant(nil)
	c.Chunk.WriteOp(bytecode.OpConstant)
	c.Chunk.WriteByte(byte(idx))
	c.Chunk.WriteOp(bytecode.OpPop)
	return nil
}

func (c *StmtCompiler) VisitContinueStmt(stmt *parser.ContinueStmt) interface{} {
	// For now, just emit a no-op with nil
	// Proper implementation requires loop context tracking
	idx := c.Chunk.AddConstant(nil)
	c.Chunk.WriteOp(bytecode.OpConstant)
	c.Chunk.WriteByte(byte(idx))
	c.Chunk.WriteOp(bytecode.OpPop)
	return nil
}

func (c *StmtCompiler) VisitImportStmt(stmt *parser.ImportStmt) interface{} {
	idx := c.Chunk.AddConstant(stmt.Path)
	c.Chunk.WriteOp(bytecode.OpImport)
	c.Chunk.WriteByte(byte(idx))
	
	// Store the module in a global variable
	// Use alias if provided, otherwise use the module path as the name
	varName := stmt.Alias
	if varName == "" {
		varName = stmt.Path
	}
	
	nameIdx := c.Chunk.AddConstant(varName)
	c.Chunk.WriteOp(bytecode.OpDefineGlobal)
	c.Chunk.WriteByte(byte(nameIdx))
	
	return nil
}

func (c *StmtCompiler) VisitClassStmt(stmt *parser.ClassStmt) interface{} {
	// TODO: Implement class compilation
	return nil
}

func (c *StmtCompiler) VisitTryStmt(stmt *parser.TryStmt) interface{} {
	// Set up try block
	c.Chunk.WriteOp(bytecode.OpTry)
	catchPos := len(c.Chunk.Code)
	c.Chunk.WriteByte(0) // Placeholder for catch offset
	c.Chunk.WriteByte(0)
	
	// Compile try block
	for _, s := range stmt.TryBlock {
		s.Accept(c)
	}
	
	// Jump over catch block if no error
	c.Chunk.WriteOp(bytecode.OpJump)
	jumpPos := len(c.Chunk.Code)
	c.Chunk.WriteByte(0)
	c.Chunk.WriteByte(0)
	
	// Patch catch offset
	catchStart := len(c.Chunk.Code)
	catchOffset := catchStart - catchPos - 2
	c.Chunk.Code[catchPos] = byte(catchOffset >> 8)
	c.Chunk.Code[catchPos+1] = byte(catchOffset & 0xff)
	
	// Compile catch block
	if stmt.CatchVar != "" {
		// Store caught error in variable
		idx := c.Chunk.AddConstant(stmt.CatchVar)
		c.Chunk.WriteOp(bytecode.OpDefineGlobal)
		c.Chunk.WriteByte(byte(idx))
	}
	
	for _, s := range stmt.CatchBlock {
		s.Accept(c)
	}
	
	// Patch jump offset
	endPos := len(c.Chunk.Code)
	jumpOffset := endPos - jumpPos - 2
	c.Chunk.Code[jumpPos] = byte(jumpOffset >> 8)
	c.Chunk.Code[jumpPos+1] = byte(jumpOffset & 0xff)
	
	// Compile finally block if present
	if len(stmt.FinallyBlock) > 0 {
		for _, s := range stmt.FinallyBlock {
			s.Accept(c)
		}
	}
	
	return nil
}

func (c *StmtCompiler) VisitThrowStmt(stmt *parser.ThrowStmt) interface{} {
	stmt.Value.Accept(c)
	c.Chunk.WriteOp(bytecode.OpThrow)
	return nil
}

func (c *StmtCompiler) VisitMatchStmt(stmt *parser.MatchStmt) interface{} {
	// Evaluate the value to match
	stmt.Value.Accept(c)
	
	// Keep track of jump addresses
	var endJumps []int
	
	for i, matchCase := range stmt.Cases {
		// Check if this is the default case (_)
		isDefault := false
		if lit, ok := matchCase.Pattern.(*parser.Literal); ok {
			if str, ok := lit.Value.(string); ok && str == "_" {
				isDefault = true
			}
		}
		
		var jumpToNext int
		if !isDefault {
			// Duplicate the value for comparison
			c.Chunk.WriteOp(bytecode.OpDup)
			
			// Compile the pattern
			matchCase.Pattern.Accept(c)
			
			// Compare with the value
			c.Chunk.WriteOp(bytecode.OpEqual)
			
			// Jump to next case if not equal
			c.Chunk.WriteOp(bytecode.OpJumpIfFalse)
			jumpToNext = len(c.Chunk.Code)
			c.Chunk.WriteByte(0) // Placeholder
			c.Chunk.WriteByte(0)
			
			// Pop the comparison result
			c.Chunk.WriteOp(bytecode.OpPop)
		}
		
		// Compile the case body
		for _, s := range matchCase.Body {
			s.Accept(c)
		}
		
		// Jump to end after executing the case
		if i < len(stmt.Cases)-1 {
			c.Chunk.WriteOp(bytecode.OpJump)
			endJumpAddr := len(c.Chunk.Code)
			c.Chunk.WriteByte(0) // Placeholder
			c.Chunk.WriteByte(0)
			endJumps = append(endJumps, endJumpAddr)
		}
		
		// Patch the jump to next case
		if !isDefault && jumpToNext > 0 {
			jumpOffset := len(c.Chunk.Code) - jumpToNext - 2
			c.Chunk.Code[jumpToNext] = byte(jumpOffset >> 8)
			c.Chunk.Code[jumpToNext+1] = byte(jumpOffset)
		}
	}
	
	// Pop the original value at the end
	c.Chunk.WriteOp(bytecode.OpPop)
	
	// Patch all end jumps
	endAddr := len(c.Chunk.Code)
	for _, endJump := range endJumps {
		jumpOffset := endAddr - endJump - 2
		c.Chunk.Code[endJump] = byte(jumpOffset >> 8)
		c.Chunk.Code[endJump+1] = byte(jumpOffset)
	}
	
	return nil
}

// Expression visitors
func (c *StmtCompiler) VisitLiteralExpr(expr *parser.Literal) interface{} {
	idx := c.Chunk.AddConstant(expr.Value)
	c.Chunk.WriteOp(bytecode.OpConstant)
	c.Chunk.WriteByte(byte(idx))
	return nil
}

func (c *StmtCompiler) VisitBinaryExpr(expr *parser.Binary) interface{} {
	expr.Left.Accept(c)
	expr.Right.Accept(c)

	switch expr.Operator {
	case "+":
		c.emitOp(bytecode.OpAdd)
	case "-":
		c.emitOp(bytecode.OpSub)
	case "*":
		c.emitOp(bytecode.OpMul)
	case "/":
		c.emitOp(bytecode.OpDiv)
	case "%":
		c.emitOp(bytecode.OpMod)
	case "==":
		c.Chunk.WriteOp(bytecode.OpEqual)
	case "!=":
		c.Chunk.WriteOp(bytecode.OpNotEqual)
	case ">":
		c.Chunk.WriteOp(bytecode.OpGreater)
	case "<":
		c.Chunk.WriteOp(bytecode.OpLess)
	case ">=":
		c.Chunk.WriteOp(bytecode.OpGreaterEqual)
	case "<=":
		c.Chunk.WriteOp(bytecode.OpLessEqual)
	case "&&":
		c.Chunk.WriteOp(bytecode.OpAnd)
	case "||":
		c.Chunk.WriteOp(bytecode.OpOr)
	}
	return nil
}

func (c *StmtCompiler) VisitVariableExpr(expr *parser.Variable) interface{} {
	// Check if this is a local variable
	if c.locals != nil {
		for i, local := range c.locals {
			if local == expr.Name {
				c.Chunk.WriteOp(bytecode.OpGetLocal)
				c.Chunk.WriteByte(byte(i))
				return nil
			}
		}
	}

	// If not a local, treat it as a global
	idx := c.Chunk.AddConstant(expr.Name)
	c.Chunk.WriteOp(bytecode.OpGetGlobal)
	c.Chunk.WriteByte(byte(idx))
	return nil
}

func (c *StmtCompiler) VisitAssignExpr(expr *parser.Assign) interface{} {
	expr.Value.Accept(c)
	idx := c.Chunk.AddConstant(expr.Name)
	c.Chunk.WriteOp(bytecode.OpDefineGlobal)
	c.Chunk.WriteByte(byte(idx))
	return nil
}

func (c *StmtCompiler) VisitCallExpr(expr *parser.CallExpr) interface{} {
	// Compile arguments (left-to-right)
	for _, arg := range expr.Args {
		arg.Accept(c)
	}
	// Compile callee (leaves function on stack)
	expr.Callee.Accept(c)
	// Emit OpCall with arg count
	c.Chunk.WriteOp(bytecode.OpCall)
	c.Chunk.WriteByte(byte(len(expr.Args)))
	return nil
}

func (c *StmtCompiler) VisitIfExpr(expr *parser.IfExpr) interface{} {
	// Compile the condition
	expr.Cond.Accept(c)

	// Emit jump if false (placeholder offset)
	c.Chunk.WriteOp(bytecode.OpJumpIfFalse)
	jumpIfFalsePos := len(c.Chunk.Code)
	c.Chunk.WriteByte(0) // high byte
	c.Chunk.WriteByte(0) // low byte

	// Compile then branch
	expr.ThenBranch.Accept(c)

	// Emit jump over else branch (if present)
	c.Chunk.WriteOp(bytecode.OpJump)
	jumpOverElsePos := len(c.Chunk.Code)
	c.Chunk.WriteByte(0)
	c.Chunk.WriteByte(0)

	// Patch jumpIfFalse to point here (start of else)
	elseStart := len(c.Chunk.Code)
	c.Chunk.Code[jumpIfFalsePos] = byte((elseStart >> 8) & 0xff)
	c.Chunk.Code[jumpIfFalsePos+1] = byte(elseStart & 0xff)

	// Compile else branch if present
	if expr.ElseBranch != nil {
		expr.ElseBranch.Accept(c)
	} else {
		// If no else, push nil for expression result
		c.Chunk.WriteOp(bytecode.OpNil)
	}

	// Patch jumpOverElse to point here (after else)
	afterElse := len(c.Chunk.Code)
	c.Chunk.Code[jumpOverElsePos] = byte((afterElse >> 8) & 0xff)
	c.Chunk.Code[jumpOverElsePos+1] = byte(afterElse & 0xff)

	return nil
}

func (c *StmtCompiler) VisitBlockExpr(expr *parser.BlockExpr) interface{} {
	var result interface{}
	for _, stmt := range expr.Stmts {
		result = stmt.Accept(c)
	}
	return result
}

// New expression visitor methods

func (c *StmtCompiler) VisitArrayExpr(expr *parser.ArrayExpr) interface{} {
	for _, elem := range expr.Elements {
		elem.Accept(c)
	}
	c.Chunk.WriteOp(bytecode.OpArray)
	c.Chunk.WriteByte(byte(len(expr.Elements) >> 8))
	c.Chunk.WriteByte(byte(len(expr.Elements) & 0xff))
	return nil
}

func (c *StmtCompiler) VisitMapExpr(expr *parser.MapExpr) interface{} {
	for i := range expr.Keys {
		expr.Keys[i].Accept(c)
		expr.Values[i].Accept(c)
	}
	c.Chunk.WriteOp(bytecode.OpMap)
	c.Chunk.WriteByte(byte(len(expr.Keys) >> 8))
	c.Chunk.WriteByte(byte(len(expr.Keys) & 0xff))
	return nil
}

func (c *StmtCompiler) VisitIndexExpr(expr *parser.IndexExpr) interface{} {
	expr.Object.Accept(c)
	expr.Index.Accept(c)
	c.Chunk.WriteOp(bytecode.OpIndex)
	return nil
}

func (c *StmtCompiler) VisitSetIndexExpr(expr *parser.SetIndexExpr) interface{} {
	expr.Object.Accept(c)
	expr.Index.Accept(c)
	expr.Value.Accept(c)
	c.Chunk.WriteOp(bytecode.OpSetIndex)
	return nil
}

func (c *StmtCompiler) VisitUnaryExpr(expr *parser.UnaryExpr) interface{} {
	expr.Operand.Accept(c)
	switch expr.Operator {
	case "!":
		c.Chunk.WriteOp(bytecode.OpNot)
	case "-":
		c.Chunk.WriteOp(bytecode.OpNegate)
	}
	return nil
}

func (c *StmtCompiler) VisitLogicalExpr(expr *parser.LogicalExpr) interface{} {
	expr.Left.Accept(c)
	expr.Right.Accept(c)
	switch expr.Operator {
	case "&&":
		c.Chunk.WriteOp(bytecode.OpAnd)
	case "||":
		c.Chunk.WriteOp(bytecode.OpOr)
	}
	return nil
}

func (c *StmtCompiler) VisitInterpolationExpr(expr *parser.InterpolationExpr) interface{} {
	for i, part := range expr.Parts {
		part.Accept(c)
		if i > 0 {
			c.Chunk.WriteOp(bytecode.OpConcat)
		}
	}
	return nil
}

func (c *StmtCompiler) VisitLambdaExpr(expr *parser.LambdaExpr) interface{} {
	// Create a new chunk for the lambda
	subCompiler := NewStmtCompiler()
	subCompiler.parent = c // Set parent for closure support
	
	// Initialize locals tracking
	subCompiler.locals = make([]string, 0, 256)
	subCompiler.localCount = 0
	
	function := &Function{
		Name:   "<lambda>",
		Arity:  len(expr.Params),
		Chunk:  subCompiler.Chunk,
		Params: expr.Params,
	}
	
	// Set the current function for the subcompiler
	subCompiler.currentFunction = function
	
	// Add parameters as locals
	for _, param := range expr.Params {
		subCompiler.locals = append(subCompiler.locals, param)
		subCompiler.localCount++
	}
	
	// Compile the body
	if blockExpr, ok := expr.Body.(*parser.BlockExpr); ok {
		// Block body - compile statements
		for _, stmt := range blockExpr.Stmts {
			stmt.Accept(subCompiler)
		}
		subCompiler.Chunk.WriteOp(bytecode.OpReturn)
	} else {
		// Expression body - compile and return
		expr.Body.Accept(subCompiler)
		subCompiler.Chunk.WriteOp(bytecode.OpReturn)
	}
	
	// Push the function as a constant
	idx := c.Chunk.AddConstant(function)
	c.Chunk.WriteOp(bytecode.OpConstant)
	c.Chunk.WriteByte(byte(idx))
	
	return nil
}

func (c *StmtCompiler) VisitPropertyExpr(expr *parser.PropertyExpr) interface{} {
	expr.Object.Accept(c)
	idx := c.Chunk.AddConstant(expr.Property)
	c.Chunk.WriteOp(bytecode.OpConstant)
	c.Chunk.WriteByte(byte(idx))
	c.Chunk.WriteOp(bytecode.OpIndex)
	return nil
}

func (c *StmtCompiler) VisitAssignmentExpr(expr *parser.AssignmentExpr) interface{} {
	// Compile the value
	expr.Value.Accept(c)
	
	// Store in variable
	c.Chunk.WriteOp(bytecode.OpSetGlobal)
	idx := c.Chunk.AddConstant(expr.Name)
	c.Chunk.WriteByte(byte(idx))
	
	// Assignment expressions should leave the value on the stack
	// (for use in for loop update, etc.)
	c.Chunk.WriteOp(bytecode.OpGetGlobal)
	c.Chunk.WriteByte(byte(idx))
	
	return nil
}
