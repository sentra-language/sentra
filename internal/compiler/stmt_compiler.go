// internal/compiler/stmt_compiler.go
package compiler

import (
	"sentra/internal/bytecode"
	"sentra/internal/parser"
)

type StmtCompiler struct {
	Chunk           *bytecode.Chunk
	currentFunction *Function
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

func (c *StmtCompiler) Compile(stmts []parser.Stmt) *bytecode.Chunk {
	for _, stmt := range stmts {
		stmt.Accept(c)
	}
	c.Chunk.WriteOp(bytecode.OpReturn)
	return c.Chunk
}

func (c *StmtCompiler) VisitPrintStmt(stmt *parser.PrintStmt) interface{} {
	stmt.Expr.Accept(c)
	c.Chunk.WriteOp(bytecode.OpPrint)
	return nil
}

func (c *StmtCompiler) VisitLetStmt(stmt *parser.LetStmt) interface{} {
	stmt.Expr.Accept(c)
	idx := c.Chunk.AddConstant(stmt.Name)
	c.Chunk.WriteOp(bytecode.OpDefineGlobal)
	c.Chunk.WriteByte(byte(idx))
	return nil
}

func (c *StmtCompiler) VisitExpressionStmt(stmt *parser.ExpressionStmt) interface{} {
	stmt.Expr.Accept(c)
	c.Chunk.WriteOp(bytecode.OpPop)
	return nil
}

func (c *StmtCompiler) VisitFunctionStmt(stmt *parser.FunctionStmt) interface{} {
	subCompiler := NewStmtCompiler()

	function := &Function{
		Name:   stmt.Name,
		Arity:  len(stmt.Params),
		Chunk:  subCompiler.Chunk,
		Params: stmt.Params,
	}

	// Set the current function for the subcompiler
	subCompiler.currentFunction = function

	// Emit OpSetLocal for each parameter (in order)
	for i := range stmt.Params {
		subCompiler.Chunk.WriteOp(bytecode.OpSetLocal)
		subCompiler.Chunk.WriteByte(byte(i))
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
		c.Chunk.WriteOp(bytecode.OpAdd)
	case "-":
		c.Chunk.WriteOp(bytecode.OpSub)
	case "*":
		c.Chunk.WriteOp(bytecode.OpMul)
	case "/":
		c.Chunk.WriteOp(bytecode.OpDiv)
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
	}
	return nil
}

func (c *StmtCompiler) VisitVariableExpr(expr *parser.Variable) interface{} {
	// Check if this is a local variable (parameter)
	if c.currentFunction != nil && c.currentFunction.Params != nil {
		for i, param := range c.currentFunction.Params {
			if param == expr.Name {
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
