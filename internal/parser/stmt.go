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

// AssignmentStmt represents a variable assignment: x = expr
type AssignmentStmt struct {
	Name  string
	Value Expr
}

func (a *AssignmentStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitAssignmentStmt(a)
}

// IndexAssignmentStmt represents an index assignment: array[index] = expr
type IndexAssignmentStmt struct {
	Object Expr
	Index  Expr
	Value  Expr
}

func (i *IndexAssignmentStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitIndexAssignmentStmt(i)
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

// IfStmt represents an if statement.
type IfStmt struct {
	Condition Expr
	Then      []Stmt
	Else      []Stmt
}

func (i *IfStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitIfStmt(i)
}

// WhileStmt represents a while loop.
type WhileStmt struct {
	Condition Expr
	Body      []Stmt
}

func (w *WhileStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitWhileStmt(w)
}

// ForStmt represents a for loop.
type ForStmt struct {
	Init      Stmt  // Optional initialization
	Condition Expr  // Loop condition
	Update    Expr  // Optional update expression
	Body      []Stmt
}

func (f *ForStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitForStmt(f)
}

// ForInStmt represents a for-in loop for iterating collections.
type ForInStmt struct {
	Variable   string
	Collection Expr
	Body       []Stmt
}

func (f *ForInStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitForInStmt(f)
}

// BreakStmt represents a break statement.
type BreakStmt struct{}

func (b *BreakStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitBreakStmt(b)
}

// ContinueStmt represents a continue statement.
type ContinueStmt struct{}

func (c *ContinueStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitContinueStmt(c)
}

// ImportStmt represents an import statement.
type ImportStmt struct {
	Path  string
	Alias string // Optional alias for the import
}

func (i *ImportStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitImportStmt(i)
}

// ExportStmt represents an export statement.
type ExportStmt struct {
	Name string // The name being exported
	Stmt Stmt   // The statement being exported (function, let, etc.)
}

func (e *ExportStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitExportStmt(e)
}

// ClassStmt represents a class declaration.
type ClassStmt struct {
	Name       string
	Superclass string // Optional parent class
	Methods    []*FunctionStmt
	Fields     []string
}

func (c *ClassStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitClassStmt(c)
}

// TryStmt represents a try-catch block.
type TryStmt struct {
	TryBlock   []Stmt
	CatchVar   string // Variable to bind the caught error
	CatchBlock []Stmt
	FinallyBlock []Stmt // Optional finally block
}

func (t *TryStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitTryStmt(t)
}

// ThrowStmt represents a throw statement.
type ThrowStmt struct {
	Value Expr
}

func (t *ThrowStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitThrowStmt(t)
}

// MatchStmt represents a pattern matching statement.
type MatchStmt struct {
	Value Expr
	Cases []MatchCase
}

type MatchCase struct {
	Pattern Expr
	Body    []Stmt
}

func (m *MatchStmt) Accept(visitor StmtVisitor) interface{} {
	return visitor.VisitMatchStmt(m)
}

// StmtVisitor handles all statement types.
type StmtVisitor interface {
	VisitPrintStmt(stmt *PrintStmt) interface{}
	VisitLetStmt(stmt *LetStmt) interface{}
	VisitAssignmentStmt(stmt *AssignmentStmt) interface{}
	VisitIndexAssignmentStmt(stmt *IndexAssignmentStmt) interface{}
	VisitExpressionStmt(stmt *ExpressionStmt) interface{}
	VisitFunctionStmt(stmt *FunctionStmt) interface{}
	VisitReturnStmt(stmt *ReturnStmt) interface{}
	VisitIfStmt(stmt *IfStmt) interface{}
	VisitWhileStmt(stmt *WhileStmt) interface{}
	VisitForStmt(stmt *ForStmt) interface{}
	VisitForInStmt(stmt *ForInStmt) interface{}
	VisitBreakStmt(stmt *BreakStmt) interface{}
	VisitContinueStmt(stmt *ContinueStmt) interface{}
	VisitImportStmt(stmt *ImportStmt) interface{}
	VisitExportStmt(stmt *ExportStmt) interface{}
	VisitClassStmt(stmt *ClassStmt) interface{}
	VisitTryStmt(stmt *TryStmt) interface{}
	VisitThrowStmt(stmt *ThrowStmt) interface{}
	VisitMatchStmt(stmt *MatchStmt) interface{}
}
