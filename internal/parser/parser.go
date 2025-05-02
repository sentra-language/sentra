// internal/parser/parser.go
package parser

import (
	"fmt"
	"sentra/internal/lexer"
)

// Add operator precedence (optional for debug)
var precedence = map[lexer.TokenType]int{
	lexer.TokenPlus:        1,
	lexer.TokenMinus:       1,
	lexer.TokenStar:        2,
	lexer.TokenSlash:       2,
	lexer.TokenDoubleEqual: 0, // Add this line - equality has lower precedence
	lexer.TokenNotEqual:    0, // Add this line
	lexer.TokenLT:          0, // Add this line
	lexer.TokenGT:          0, // Add this line
	lexer.TokenLE:          0, // Add this line
	lexer.TokenGE:          0, // Add this line
}

type Parser struct {
	tokens  []lexer.Token
	current int
}

func NewParser(tokens []lexer.Token) *Parser {
	return &Parser{tokens: tokens, current: 0}
}

func (p *Parser) Parse() []Stmt {
	var stmts []Stmt
	for !p.isAtEnd() {
		fmt.Printf("AT TOP, token: [%s] '%s'\n", p.peek().Type, p.peek().Lexeme)
		if p.match(lexer.TokenFn) {
			fmt.Println("Matched 'fn', parsing function...")
			stmts = append(stmts, p.function())
		} else {
			stmt := p.statement()
			stmts = append(stmts, stmt)
		}
	}
	return stmts
}

func (p *Parser) statement() Stmt {
	if p.match(lexer.TokenLog) {
		p.consume(lexer.TokenLParen, "Expect '(' after log")
		expr := p.expression()
		p.consume(lexer.TokenRParen, "Expect ')' after log argument")
		return &PrintStmt{Expr: expr}
	}
	if p.match(lexer.TokenLet) {
		nameTok := p.consume(lexer.TokenIdent, "Expect variable name")
		p.consume(lexer.TokenEqual, "Expect '=' after variable name")
		expr := p.expression()
		return &LetStmt{Name: nameTok.Lexeme, Expr: expr}
	}
	if p.match(lexer.TokenReturn) {
		var value Expr = nil
		if !p.check(lexer.TokenRBrace) {
			value = p.expression()
		}
		return &ReturnStmt{Value: value}
	}
	expr := p.expression()
	return &ExpressionStmt{Expr: expr}
}

func (p *Parser) function() Stmt {
	fmt.Printf("function() at: [%s] '%s'\n", p.peek().Type, p.peek().Lexeme)
	nameTok := p.consume(lexer.TokenIdent, "Expect function name")
	p.consume(lexer.TokenLParen, "Expect '(' after function name")

	params := []string{}
	if !p.check(lexer.TokenRParen) {
		params = append(params, p.consume(lexer.TokenIdent, "Expect parameter name").Lexeme)
		for p.match(lexer.TokenComma) {
			params = append(params, p.consume(lexer.TokenIdent, "Expect parameter name").Lexeme)
		}
	}
	p.consume(lexer.TokenRParen, "Expect ')' after parameters")

	var returnType string
	if p.match(lexer.TokenColon) {
		returnType = p.consume(lexer.TokenIdent, "Expect return type after ':'").Lexeme
	}

	if p.match(lexer.TokenArrow) {
		expr := p.expression()
		body := []Stmt{&ReturnStmt{Value: expr}}
		return &FunctionStmt{
			Name:       nameTok.Lexeme,
			Params:     params,
			ReturnType: returnType,
			Body:       body,
		}
	}

	p.consume(lexer.TokenLBrace, "Expect '{' before function body")
	var body []Stmt
	for !p.check(lexer.TokenRBrace) && !p.isAtEnd() {
		body = append(body, p.statement())
	}
	p.consume(lexer.TokenRBrace, "Expect '}' after function body")

	return &FunctionStmt{
		Name:       nameTok.Lexeme,
		Params:     params,
		ReturnType: returnType,
		Body:       body,
	}
}

// --- Expression Parsing with Precedence ---
func (p *Parser) expression() Expr {
	return p.parseBinary(0)
}

func (p *Parser) parseBinary(minPrec int) Expr {
	left := p.parseUnary()
	for {
		tok := p.peek()
		prec, ok := precedence[tok.Type]
		if !ok || prec < minPrec {
			break
		}
		p.advance()
		right := p.parseBinary(prec + 1)
		left = &Binary{
			Left:     left,
			Operator: tok.Lexeme,
			Right:    right,
		}
	}
	return left
}

func (p *Parser) parseUnary() Expr {
	// For now, just parse function calls and primaries (add unary ops later)
	return p.parseCall()
}

func (p *Parser) parseCall() Expr {
	expr := p.primary()
	for {
		if p.match(lexer.TokenLParen) {
			expr = p.finishCall(expr)
		} else {
			break
		}
	}
	return expr
}

func (p *Parser) finishCall(callee Expr) Expr {
	args := []Expr{}
	if !p.check(lexer.TokenRParen) {
		for {
			args = append(args, p.expression())
			if !p.match(lexer.TokenComma) {
				break
			}
		}
	}
	p.consume(lexer.TokenRParen, "Expect ')' after arguments")
	return &CallExpr{Callee: callee, Args: args}
}

func (p *Parser) primary() Expr {
	tok := p.advance()
	switch tok.Type {
	case lexer.TokenString:
		return &Literal{Value: tok.Lexeme}
	case lexer.TokenNumber:
		var val float64
		fmt.Sscanf(tok.Lexeme, "%f", &val)
		return &Literal{Value: val}
	case lexer.TokenIdent:
		return &Variable{Name: tok.Lexeme}
	case lexer.TokenNull:
		// Add this case to handle 'null'
		return &Literal{Value: nil}
	case lexer.TokenTrue:
		return &Literal{Value: true}
	case lexer.TokenFalse:
		return &Literal{Value: false}
	case lexer.TokenIf:
		// Parse: if cond { then } else { else }
		cond := p.parseCondition()
		thenBranch := p.parseBlockExpr()
		var elseBranch Expr = nil
		if p.match(lexer.TokenElse) {
			elseBranch = p.parseBlockExpr()
		}
		return &IfExpr{
			Cond:       cond,
			ThenBranch: thenBranch,
			ElseBranch: elseBranch,
		}
	default:
		panic("Unexpected token in expression: " + tok.Lexeme)
	}
}

func (p *Parser) parseCondition() Expr {
	// Parse an expression, but stop if we see '{', '}', or EOF
	start := p.current
	for !p.check(lexer.TokenLBrace) && !p.check(lexer.TokenRBrace) && !p.check(lexer.TokenEOF) {
		p.advance()
	}
	// Rewind to start, parse as expression
	oldCurrent := p.current
	p.current = start
	expr := p.parseBinary(0)
	p.current = oldCurrent
	return expr
}

func (p *Parser) parseBlockExpr() Expr {
	p.consume(lexer.TokenLBrace, "Expect '{' to start block")
	var stmts []Stmt
	for !p.check(lexer.TokenRBrace) && !p.isAtEnd() {
		stmts = append(stmts, p.statement())
	}
	p.consume(lexer.TokenRBrace, "Expect '}' after block")
	return &BlockExpr{Stmts: stmts}
}

// --- Utility methods ---

func (p *Parser) match(t lexer.TokenType) bool {
	if p.check(t) {
		p.advance()
		return true
	}
	return false
}

func (p *Parser) consume(t lexer.TokenType, msg string) lexer.Token {
	if p.check(t) {
		return p.advance()
	}
	panic(msg)
}

func (p *Parser) check(t lexer.TokenType) bool {
	if p.isAtEnd() {
		return false
	}
	return p.peek().Type == t
}

func (p *Parser) checkNext(t lexer.TokenType) bool {
	if p.current+1 >= len(p.tokens) {
		return false
	}
	return p.tokens[p.current+1].Type == t
}

func (p *Parser) advance() lexer.Token {
	if !p.isAtEnd() {
		p.current++
	}
	return p.previous()
}

func (p *Parser) peek() lexer.Token {
	return p.tokens[p.current]
}

func (p *Parser) previous() lexer.Token {
	return p.tokens[p.current-1]
}

func (p *Parser) isAtEnd() bool {
	return p.peek().Type == lexer.TokenEOF
}
