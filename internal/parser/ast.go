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

type ExprVisitor interface {
	VisitBinaryExpr(expr *Binary) interface{}
	VisitLiteralExpr(expr *Literal) interface{}
	VisitVariableExpr(expr *Variable) interface{}
	VisitAssignExpr(expr *Assign) interface{}
	VisitCallExpr(expr *CallExpr) interface{}
	VisitIfExpr(expr *IfExpr) interface{}
	VisitBlockExpr(expr *BlockExpr) interface{}
}
