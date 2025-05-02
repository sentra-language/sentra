// internal/compiler/compiler.go
package compiler

import (
	"sentra/internal/bytecode"
	"sentra/internal/parser"
)

type Compiler struct {
	chunk *bytecode.Chunk
}

func NewCompiler() *Compiler {
	return &Compiler{
		chunk: bytecode.NewChunk(),
	}
}

func (c *Compiler) Compile(expr parser.Expr) *bytecode.Chunk {
	expr.Accept(c)
	c.chunk.WriteOp(bytecode.OpReturn)
	return c.chunk
}

func (c *Compiler) VisitLiteralExpr(expr *parser.Literal) interface{} {
	idx := c.chunk.AddConstant(expr.Value)
	c.chunk.WriteOp(bytecode.OpConstant)
	c.chunk.WriteByte(byte(idx))
	return nil
}

func (c *Compiler) VisitBinaryExpr(expr *parser.Binary) interface{} {
	expr.Left.Accept(c)
	expr.Right.Accept(c)

	switch expr.Operator {
	case "+":
		c.chunk.WriteOp(bytecode.OpAdd)
	case "-":
		c.chunk.WriteOp(bytecode.OpSub)
	case "*":
		c.chunk.WriteOp(bytecode.OpMul)
	case "/":
		c.chunk.WriteOp(bytecode.OpDiv)
	case "==":
		c.chunk.WriteOp(bytecode.OpEqual)
	case "!=":
		c.chunk.WriteOp(bytecode.OpNotEqual)
	case ">":
		c.chunk.WriteOp(bytecode.OpGreater)
	case "<":
		c.chunk.WriteOp(bytecode.OpLess)
	case ">=":
		c.chunk.WriteOp(bytecode.OpGreaterEqual)
	case "<=":
		c.chunk.WriteOp(bytecode.OpLessEqual)
	}
	return nil
}

func (c *Compiler) VisitVariableExpr(expr *parser.Variable) interface{} {
	name := expr.Name
	idx := c.chunk.AddConstant(name)
	c.chunk.WriteOp(bytecode.OpGetGlobal)
	c.chunk.WriteByte(byte(idx))
	return nil
}

func (c *Compiler) VisitAssignExpr(expr *parser.Assign) interface{} {
	expr.Value.Accept(c)
	idx := c.chunk.AddConstant(expr.Name)
	c.chunk.WriteOp(bytecode.OpDefineGlobal)
	c.chunk.WriteByte(byte(idx))
	return nil
}

// NEW: Compile CallExpr
func (c *Compiler) VisitCallExpr(expr *parser.CallExpr) interface{} {
	// Compile each argument (in order)
	for _, arg := range expr.Args {
		arg.Accept(c)
	}
	// Compile the callee (should leave function value on stack)
	expr.Callee.Accept(c)
	// Emit OpCall with arg count
	c.chunk.WriteOp(bytecode.OpCall)
	c.chunk.WriteByte(byte(len(expr.Args)))
	return nil
}

func (c *Compiler) VisitIfExpr(expr *parser.IfExpr) interface{} {
	// Compile the condition
	expr.Cond.Accept(c)

	// Emit jump if false (placeholder offset)
	c.chunk.WriteOp(bytecode.OpJumpIfFalse)
	jumpIfFalsePos := len(c.chunk.Code)
	c.chunk.WriteByte(0) // high byte
	c.chunk.WriteByte(0) // low byte

	// Compile then branch
	expr.ThenBranch.Accept(c)

	// Emit jump over else branch (if present)
	c.chunk.WriteOp(bytecode.OpJump)
	jumpOverElsePos := len(c.chunk.Code)
	c.chunk.WriteByte(0)
	c.chunk.WriteByte(0)

	// Patch jumpIfFalse to point here (start of else)
	elseStart := len(c.chunk.Code)
	c.chunk.Code[jumpIfFalsePos] = byte((elseStart >> 8) & 0xff)
	c.chunk.Code[jumpIfFalsePos+1] = byte(elseStart & 0xff)

	// Compile else branch if present
	if expr.ElseBranch != nil {
		expr.ElseBranch.Accept(c)
	} else {
		// If no else, push nil for expression result
		c.chunk.WriteOp(bytecode.OpNil)
	}

	// Patch jumpOverElse to point here (after else)
	afterElse := len(c.chunk.Code)
	c.chunk.Code[jumpOverElsePos] = byte((afterElse >> 8) & 0xff)
	c.chunk.Code[jumpOverElsePos+1] = byte(afterElse & 0xff)

	return nil
}

func (c *Compiler) VisitBlockExpr(expr *parser.BlockExpr) interface{} {
	var result interface{}
	for _, stmt := range expr.Stmts {
		result = stmt.Accept(c)
	}
	return result
}

func (c *Compiler) VisitExpressionStmt(stmt *parser.ExpressionStmt) interface{} {
	return stmt.Expr.Accept(c)
}

func (c *Compiler) VisitPrintStmt(stmt *parser.PrintStmt) interface{} {
	return stmt.Expr.Accept(c)
}

func (c *Compiler) VisitLetStmt(stmt *parser.LetStmt) interface{} {
	stmt.Expr.Accept(c)
	return nil
}

func (c *Compiler) VisitFunctionStmt(stmt *parser.FunctionStmt) interface{} {
	// Not implemented for expression-level compiler
	return nil
}

func (c *Compiler) VisitReturnStmt(stmt *parser.ReturnStmt) interface{} {
	if stmt.Value != nil {
		stmt.Value.Accept(c)
	}
	return nil
}
