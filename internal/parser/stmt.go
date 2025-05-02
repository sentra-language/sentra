// internal/parser/stmt.go
package parser

// Stmt represents a top-level statement.
type Stmt interface {
	Accept(visitor StmtVisitor) interface{}
}

// PrintStmt wraps an expression to print.
type PrintStmt struct {
	Expr Expr
}

func (p *PrintStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitPrintStmt(p)
}

// LetStmt represents a variable declaration: let x = expr
type LetStmt struct {
	Name string
	Expr Expr
}

func (l *LetStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitLetStmt(l)
}

// ExpressionStmt wraps a raw expression as a statement.
type ExpressionStmt struct {
	Expr Expr
}

func (e *ExpressionStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitExpressionStmt(e)
}

// FunctionStmt represents a function declaration.
type FunctionStmt struct {
	Name       string
	Params     []string
	ReturnType string
	Body       []Stmt
}

func (f *FunctionStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitFunctionStmt(f)
}

// ReturnStmt represents a return statement.
type ReturnStmt struct {
	Value Expr
}

func (r *ReturnStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitReturnStmt(r)
}

// StmtVisitor handles all statement types.
type StmtVisitor interface {
	VisitPrintStmt(stmt *PrintStmt) interface{}
	VisitLetStmt(stmt *LetStmt) interface{}
	VisitExpressionStmt(stmt *ExpressionStmt) interface{}
	VisitFunctionStmt(stmt *FunctionStmt) interface{}
	VisitReturnStmt(stmt *ReturnStmt) interface{}
}
