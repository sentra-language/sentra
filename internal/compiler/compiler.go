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

// New visitor methods for extended AST

func (c *Compiler) VisitArrayExpr(expr *parser.ArrayExpr) interface{} {
	// Compile each element
	for _, elem := range expr.Elements {
		elem.Accept(c)
	}
	// Emit array creation opcode
	c.chunk.WriteOp(bytecode.OpArray)
	c.chunk.WriteByte(byte(len(expr.Elements) >> 8))
	c.chunk.WriteByte(byte(len(expr.Elements) & 0xff))
	return nil
}

func (c *Compiler) VisitMapExpr(expr *parser.MapExpr) interface{} {
	// Compile key-value pairs
	for i := range expr.Keys {
		expr.Keys[i].Accept(c)
		expr.Values[i].Accept(c)
	}
	// Emit map creation opcode
	c.chunk.WriteOp(bytecode.OpMap)
	c.chunk.WriteByte(byte(len(expr.Keys) >> 8))
	c.chunk.WriteByte(byte(len(expr.Keys) & 0xff))
	return nil
}

func (c *Compiler) VisitIndexExpr(expr *parser.IndexExpr) interface{} {
	expr.Object.Accept(c)
	expr.Index.Accept(c)
	c.chunk.WriteOp(bytecode.OpIndex)
	return nil
}

func (c *Compiler) VisitSetIndexExpr(expr *parser.SetIndexExpr) interface{} {
	expr.Object.Accept(c)
	expr.Index.Accept(c)
	expr.Value.Accept(c)
	c.chunk.WriteOp(bytecode.OpSetIndex)
	return nil
}

func (c *Compiler) VisitUnaryExpr(expr *parser.UnaryExpr) interface{} {
	expr.Operand.Accept(c)
	switch expr.Operator {
	case "!":
		c.chunk.WriteOp(bytecode.OpNot)
	case "-":
		c.chunk.WriteOp(bytecode.OpNegate)
	}
	return nil
}

func (c *Compiler) VisitLogicalExpr(expr *parser.LogicalExpr) interface{} {
	expr.Left.Accept(c)
	expr.Right.Accept(c)
	switch expr.Operator {
	case "&&":
		c.chunk.WriteOp(bytecode.OpAnd)
	case "||":
		c.chunk.WriteOp(bytecode.OpOr)
	}
	return nil
}

func (c *Compiler) VisitInterpolationExpr(expr *parser.InterpolationExpr) interface{} {
	// Compile all parts and concatenate
	for i, part := range expr.Parts {
		part.Accept(c)
		if i > 0 {
			c.chunk.WriteOp(bytecode.OpConcat)
		}
	}
	return nil
}

func (c *Compiler) VisitLambdaExpr(expr *parser.LambdaExpr) interface{} {
	// TODO: Implement lambda compilation
	// This requires creating a new function chunk
	return nil
}

func (c *Compiler) VisitPropertyExpr(expr *parser.PropertyExpr) interface{} {
	expr.Object.Accept(c)
	idx := c.chunk.AddConstant(expr.Property)
	c.chunk.WriteOp(bytecode.OpConstant)
	c.chunk.WriteByte(byte(idx))
	c.chunk.WriteOp(bytecode.OpIndex)
	return nil
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

func (c *Compiler) VisitAssignmentStmt(stmt *parser.AssignmentStmt) interface{} {
	// Not implemented for expression-level compiler
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

func (c *Compiler) VisitIfStmt(stmt *parser.IfStmt) interface{} {
	// Delegate to StmtCompiler for actual implementation
	return nil
}

// Additional statement visitor methods

func (c *Compiler) VisitWhileStmt(stmt *parser.WhileStmt) interface{} {
	return nil
}

func (c *Compiler) VisitForStmt(stmt *parser.ForStmt) interface{} {
	return nil
}

func (c *Compiler) VisitForInStmt(stmt *parser.ForInStmt) interface{} {
	return nil
}

func (c *Compiler) VisitBreakStmt(stmt *parser.BreakStmt) interface{} {
	return nil
}

func (c *Compiler) VisitContinueStmt(stmt *parser.ContinueStmt) interface{} {
	return nil
}

func (c *Compiler) VisitImportStmt(stmt *parser.ImportStmt) interface{} {
	return nil
}

func (c *Compiler) VisitClassStmt(stmt *parser.ClassStmt) interface{} {
	return nil
}

func (c *Compiler) VisitTryStmt(stmt *parser.TryStmt) interface{} {
	return nil
}

func (c *Compiler) VisitThrowStmt(stmt *parser.ThrowStmt) interface{} {
	return nil
}

func (c *Compiler) VisitMatchStmt(stmt *parser.MatchStmt) interface{} {
	return nil
}
