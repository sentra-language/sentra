package parser

type Expr interface {
	Accept(visitor ExprVisitor) interface{}
}

// Binary expression: a + b
type Binary struct {
	Left     Expr
	Operator string
	Right    Expr
}

func (b *Binary) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitBinaryExpr(b)
}

// Literal expression: string or number
type Literal struct {
	Value interface{}
}

func (l *Literal) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitLiteralExpr(l)
}

// Variable expression: x
type Variable struct {
	Name string
}

func (v *Variable) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitVariableExpr(v)
}

// Assignment expression: x = 42
type Assign struct {
	Name  string
	Value Expr
}

func (a *Assign) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitAssignExpr(a)
}

// Call expression: callee(args...)
type CallExpr struct {
	Callee Expr
	Args   []Expr
}

func (c *CallExpr) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitCallExpr(c)
}

// If expression: if cond { thenBranch } else { elseBranch }
type IfExpr struct {
	Cond       Expr
	ThenBranch Expr
	ElseBranch Expr
}

func (i *IfExpr) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitIfExpr(i)
}

// Block expression: { stmts... }
type BlockExpr struct {
	Stmts []Stmt
}

func (b *BlockExpr) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitBlockExpr(b)
}

// Array expression: [1, 2, 3]
type ArrayExpr struct {
	Elements []Expr
}

func (a *ArrayExpr) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitArrayExpr(a)
}

// Map expression: {key: value, ...}
type MapExpr struct {
	Keys   []Expr
	Values []Expr
}

func (m *MapExpr) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitMapExpr(m)
}

// Index expression: array[index] or map[key]
type IndexExpr struct {
	Object Expr
	Index  Expr
}

func (i *IndexExpr) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitIndexExpr(i)
}

// Set index expression: array[index] = value
type SetIndexExpr struct {
	Object Expr
	Index  Expr
	Value  Expr
}

func (s *SetIndexExpr) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitSetIndexExpr(s)
}

// Unary expression: !x, -x
type UnaryExpr struct {
	Operator string
	Operand  Expr
}

func (u *UnaryExpr) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitUnaryExpr(u)
}

// Logical expression: a && b, a || b
type LogicalExpr struct {
	Left     Expr
	Operator string
	Right    Expr
}

func (l *LogicalExpr) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitLogicalExpr(l)
}

// String interpolation: `Hello ${name}`
type InterpolationExpr struct {
	Parts []Expr // Mix of string literals and expressions
}

func (i *InterpolationExpr) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitInterpolationExpr(i)
}

// Lambda expression: fn(x) => x * 2
type LambdaExpr struct {
	Params []string
	Body   Expr
}

func (l *LambdaExpr) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitLambdaExpr(l)
}

// Property access: object.property
type PropertyExpr struct {
	Object   Expr
	Property string
}

func (p *PropertyExpr) Accept(visitor ExprVisitor) interface{} {
	return visitor.VisitPropertyExpr(p)
}

type ExprVisitor interface {
	VisitBinaryExpr(expr *Binary) interface{}
	VisitLiteralExpr(expr *Literal) interface{}
	VisitVariableExpr(expr *Variable) interface{}
	VisitAssignExpr(expr *Assign) interface{}
	VisitCallExpr(expr *CallExpr) interface{}
	VisitIfExpr(expr *IfExpr) interface{}
	VisitBlockExpr(expr *BlockExpr) interface{}
	VisitArrayExpr(expr *ArrayExpr) interface{}
	VisitMapExpr(expr *MapExpr) interface{}
	VisitIndexExpr(expr *IndexExpr) interface{}
	VisitSetIndexExpr(expr *SetIndexExpr) interface{}
	VisitUnaryExpr(expr *UnaryExpr) interface{}
	VisitLogicalExpr(expr *LogicalExpr) interface{}
	VisitInterpolationExpr(expr *InterpolationExpr) interface{}
	VisitLambdaExpr(expr *LambdaExpr) interface{}
	VisitPropertyExpr(expr *PropertyExpr) interface{}
}
