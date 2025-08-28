package formatter

import (
	"fmt"
	"strings"
	"sentra/internal/parser"
)

type Formatter struct {
	indent      int
	indentStr   string
	output      strings.Builder
	lineBreak   string
}

func NewFormatter() *Formatter {
	return &Formatter{
		indent:    0,
		indentStr: "    ", // 4 spaces
		lineBreak: "\n",
	}
}

func (f *Formatter) Format(stmts []parser.Stmt) string {
	f.output.Reset()
	f.indent = 0
	
	for i, stmt := range stmts {
		f.formatStmt(stmt)
		if i < len(stmts)-1 {
			// Add blank line between top-level statements if needed
			if f.needsBlankLine(stmt, stmts[i+1]) {
				f.output.WriteString(f.lineBreak)
			}
		}
	}
	
	return f.output.String()
}

func (f *Formatter) needsBlankLine(curr, next parser.Stmt) bool {
	// Add blank line between function definitions
	_, currIsFunc := curr.(*parser.FunctionStmt)
	_, nextIsFunc := next.(*parser.FunctionStmt)
	if currIsFunc || nextIsFunc {
		return true
	}
	
	// Add blank line between imports and other code
	_, currIsImport := curr.(*parser.ImportStmt)
	_, nextIsImport := next.(*parser.ImportStmt)
	if currIsImport && !nextIsImport {
		return true
	}
	
	return false
}

func (f *Formatter) writeIndent() {
	for i := 0; i < f.indent; i++ {
		f.output.WriteString(f.indentStr)
	}
}

func (f *Formatter) formatStmt(stmt parser.Stmt) {
	if stmt == nil {
		return
	}
	
	switch s := stmt.(type) {
	case *parser.LetStmt:
		f.writeIndent()
		f.output.WriteString("let ")
		f.output.WriteString(s.Name)
		f.output.WriteString(" = ")
		f.formatExpr(s.Expr)
		f.output.WriteString(f.lineBreak)
		
	case *parser.FunctionStmt:
		f.writeIndent()
		f.output.WriteString("fn ")
		f.output.WriteString(s.Name)
		f.output.WriteString("(")
		for i, param := range s.Params {
			if i > 0 {
				f.output.WriteString(", ")
			}
			f.output.WriteString(param)
		}
		f.output.WriteString(") ")
		if s.ReturnType != "" {
			f.output.WriteString("-> ")
			f.output.WriteString(s.ReturnType)
			f.output.WriteString(" ")
		}
		f.output.WriteString("{")
		f.output.WriteString(f.lineBreak)
		
		f.indent++
		for _, bodyStmt := range s.Body {
			f.formatStmt(bodyStmt)
		}
		f.indent--
		
		f.writeIndent()
		f.output.WriteString("}")
		f.output.WriteString(f.lineBreak)
		
	case *parser.ReturnStmt:
		f.writeIndent()
		f.output.WriteString("return")
		if s.Value != nil {
			f.output.WriteString(" ")
			f.formatExpr(s.Value)
		}
		f.output.WriteString(f.lineBreak)
		
	case *parser.IfStmt:
		f.writeIndent()
		f.output.WriteString("if ")
		f.formatExpr(s.Condition)
		f.output.WriteString(" {")
		f.output.WriteString(f.lineBreak)
		
		f.indent++
		for _, thenStmt := range s.Then {
			f.formatStmt(thenStmt)
		}
		f.indent--
		
		f.writeIndent()
		f.output.WriteString("}")
		
		if len(s.Else) > 0 {
			f.output.WriteString(" else {")
			f.output.WriteString(f.lineBreak)
			
			f.indent++
			for _, elseStmt := range s.Else {
				f.formatStmt(elseStmt)
			}
			f.indent--
			
			f.writeIndent()
			f.output.WriteString("}")
		}
		f.output.WriteString(f.lineBreak)
		
	case *parser.WhileStmt:
		f.writeIndent()
		f.output.WriteString("while ")
		f.formatExpr(s.Condition)
		f.output.WriteString(" {")
		f.output.WriteString(f.lineBreak)
		
		f.indent++
		for _, bodyStmt := range s.Body {
			f.formatStmt(bodyStmt)
		}
		f.indent--
		
		f.writeIndent()
		f.output.WriteString("}")
		f.output.WriteString(f.lineBreak)
		
	case *parser.ForStmt:
		f.writeIndent()
		f.output.WriteString("for ")
		if s.Init != nil {
			f.formatStmt(s.Init)
			// Remove trailing newline by truncating
			str := f.output.String()
			f.output.Reset()
			f.output.WriteString(str[:len(str)-1])
			f.output.WriteString("; ")
		} else {
			f.output.WriteString("; ")
		}
		
		if s.Condition != nil {
			f.formatExpr(s.Condition)
		}
		f.output.WriteString("; ")
		
		if s.Update != nil {
			f.formatExpr(s.Update)
		}
		f.output.WriteString(" {")
		f.output.WriteString(f.lineBreak)
		
		f.indent++
		for _, bodyStmt := range s.Body {
			f.formatStmt(bodyStmt)
		}
		f.indent--
		
		f.writeIndent()
		f.output.WriteString("}")
		f.output.WriteString(f.lineBreak)
		
	case *parser.ForInStmt:
		f.writeIndent()
		f.output.WriteString("for ")
		f.output.WriteString(s.Variable)
		f.output.WriteString(" in ")
		f.formatExpr(s.Collection)
		f.output.WriteString(" {")
		f.output.WriteString(f.lineBreak)
		
		f.indent++
		for _, bodyStmt := range s.Body {
			f.formatStmt(bodyStmt)
		}
		f.indent--
		
		f.writeIndent()
		f.output.WriteString("}")
		f.output.WriteString(f.lineBreak)
		
	case *parser.ExpressionStmt:
		f.writeIndent()
		f.formatExpr(s.Expr)
		f.output.WriteString(f.lineBreak)
		
	case *parser.PrintStmt:
		f.writeIndent()
		f.output.WriteString("print(")
		f.formatExpr(s.Expr)
		f.output.WriteString(")")
		f.output.WriteString(f.lineBreak)
		
	case *parser.AssignmentStmt:
		f.writeIndent()
		f.output.WriteString(s.Name)
		f.output.WriteString(" = ")
		f.formatExpr(s.Value)
		f.output.WriteString(f.lineBreak)
		
	case *parser.ImportStmt:
		f.writeIndent()
		f.output.WriteString("import ")
		if s.Alias != "" {
			f.output.WriteString(s.Alias)
			f.output.WriteString(" from ")
		}
		f.output.WriteString("\"")
		f.output.WriteString(s.Path)
		f.output.WriteString("\"")
		f.output.WriteString(f.lineBreak)
		
	case *parser.TryStmt:
		f.writeIndent()
		f.output.WriteString("try {")
		f.output.WriteString(f.lineBreak)
		
		f.indent++
		for _, tryStmt := range s.TryBlock {
			f.formatStmt(tryStmt)
		}
		f.indent--
		
		f.writeIndent()
		f.output.WriteString("} catch ")
		if s.CatchVar != "" {
			f.output.WriteString(s.CatchVar)
			f.output.WriteString(" ")
		}
		f.output.WriteString("{")
		f.output.WriteString(f.lineBreak)
		
		f.indent++
		for _, catchStmt := range s.CatchBlock {
			f.formatStmt(catchStmt)
		}
		f.indent--
		
		f.writeIndent()
		f.output.WriteString("}")
		
		if len(s.FinallyBlock) > 0 {
			f.output.WriteString(" finally {")
			f.output.WriteString(f.lineBreak)
			
			f.indent++
			for _, finallyStmt := range s.FinallyBlock {
				f.formatStmt(finallyStmt)
			}
			f.indent--
			
			f.writeIndent()
			f.output.WriteString("}")
		}
		f.output.WriteString(f.lineBreak)
		
	case *parser.ThrowStmt:
		f.writeIndent()
		f.output.WriteString("throw ")
		f.formatExpr(s.Value)
		f.output.WriteString(f.lineBreak)
		
	case *parser.BreakStmt:
		f.writeIndent()
		f.output.WriteString("break")
		f.output.WriteString(f.lineBreak)
		
	case *parser.ContinueStmt:
		f.writeIndent()
		f.output.WriteString("continue")
		f.output.WriteString(f.lineBreak)
	}
}

func (f *Formatter) formatExpr(expr parser.Expr) {
	if expr == nil {
		return
	}
	
	switch e := expr.(type) {
	case *parser.Binary:
		f.formatExpr(e.Left)
		f.output.WriteString(" ")
		f.output.WriteString(e.Operator)
		f.output.WriteString(" ")
		f.formatExpr(e.Right)
		
	case *parser.Literal:
		switch v := e.Value.(type) {
		case string:
			f.output.WriteString("\"")
			f.output.WriteString(v)
			f.output.WriteString("\"")
		case float64:
			f.output.WriteString(fmt.Sprintf("%g", v))
		case bool:
			f.output.WriteString(fmt.Sprintf("%v", v))
		case nil:
			f.output.WriteString("null")
		default:
			f.output.WriteString(fmt.Sprintf("%v", v))
		}
		
	case *parser.Variable:
		f.output.WriteString(e.Name)
		
	case *parser.Assign:
		f.output.WriteString(e.Name)
		f.output.WriteString(" = ")
		f.formatExpr(e.Value)
		
	case *parser.CallExpr:
		f.formatExpr(e.Callee)
		f.output.WriteString("(")
		for i, arg := range e.Args {
			if i > 0 {
				f.output.WriteString(", ")
			}
			f.formatExpr(arg)
		}
		f.output.WriteString(")")
		
	case *parser.ArrayExpr:
		f.output.WriteString("[")
		for i, elem := range e.Elements {
			if i > 0 {
				f.output.WriteString(", ")
			}
			f.formatExpr(elem)
		}
		f.output.WriteString("]")
		
	case *parser.MapExpr:
		f.output.WriteString("{")
		for i := range e.Keys {
			if i > 0 {
				f.output.WriteString(", ")
			}
			f.formatExpr(e.Keys[i])
			f.output.WriteString(": ")
			f.formatExpr(e.Values[i])
		}
		f.output.WriteString("}")
		
	case *parser.IndexExpr:
		f.formatExpr(e.Object)
		f.output.WriteString("[")
		f.formatExpr(e.Index)
		f.output.WriteString("]")
		
	case *parser.UnaryExpr:
		f.output.WriteString(e.Operator)
		f.formatExpr(e.Operand)
		
	case *parser.LogicalExpr:
		f.formatExpr(e.Left)
		f.output.WriteString(" ")
		f.output.WriteString(e.Operator)
		f.output.WriteString(" ")
		f.formatExpr(e.Right)
		
	case *parser.PropertyExpr:
		f.formatExpr(e.Object)
		f.output.WriteString(".")
		f.output.WriteString(e.Property)
		
	case *parser.LambdaExpr:
		f.output.WriteString("fn(")
		for i, param := range e.Params {
			if i > 0 {
				f.output.WriteString(", ")
			}
			f.output.WriteString(param)
		}
		f.output.WriteString(") => ")
		f.formatExpr(e.Body)
	}
}