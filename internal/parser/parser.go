// internal/parser/parser.go
package parser

import (
	"fmt"
	"sentra/internal/errors"
	"sentra/internal/lexer"
	"strings"
)

// Add operator precedence (optional for debug)
var precedence = map[lexer.TokenType]int{
	// Logical operators (lowest precedence)
	lexer.TokenOr:          1,  // ||
	lexer.TokenAnd:         2,  // &&
	// Comparison operators
	lexer.TokenDoubleEqual: 3,  // ==
	lexer.TokenNotEqual:    3,  // !=
	lexer.TokenLT:          3,  // <
	lexer.TokenGT:          3,  // >
	lexer.TokenLE:          3,  // <=
	lexer.TokenGE:          3,  // >=
	// Arithmetic operators
	lexer.TokenPlus:        4,  // +
	lexer.TokenMinus:       4,  // -
	lexer.TokenStar:        5,  // *
	lexer.TokenSlash:       5,  // /
	lexer.TokenPercent:     5,  // %
}

type Parser struct {
	tokens     []lexer.Token
	current    int
	Errors     []error
	file       string
	sourceLines []string // Source lines for error reporting
}

func NewParser(tokens []lexer.Token) *Parser {
	return &Parser{
		tokens:  tokens,
		current: 0,
		Errors:  []error{},
	}
}

func NewParserWithSource(tokens []lexer.Token, source string, file string) *Parser {
	return &Parser{
		tokens:      tokens,
		current:     0,
		Errors:      []error{},
		file:        file,
		sourceLines: strings.Split(source, "\n"),
	}
}

func (p *Parser) Parse() []Stmt {
	var stmts []Stmt
	for !p.isAtEnd() {
		if p.match(lexer.TokenFn) {
			stmts = append(stmts, p.function())
		} else {
			stmt := p.statement()
			stmts = append(stmts, stmt)
		}
	}
	return stmts
}

func (p *Parser) statement() Stmt {
	// Import statement
	if p.match(lexer.TokenImport) {
		return p.importStatement()
	}
	
	// If statement
	if p.match(lexer.TokenIf) {
		return p.ifStatement()
	}
	
	// While loop
	if p.match(lexer.TokenWhile) {
		return p.whileStatement()
	}
	
	// For loop
	if p.match(lexer.TokenFor) {
		return p.forStatement()
	}
	
	// Log/print statement
	if p.match(lexer.TokenLog) {
		p.consume(lexer.TokenLParen, "Expect '(' after log")
		expr := p.expression()
		p.consume(lexer.TokenRParen, "Expect ')' after log argument")
		return &PrintStmt{Expr: expr}
	}
	
	// Variable declaration
	if p.match(lexer.TokenLet) {
		nameTok := p.consume(lexer.TokenIdent, "Expect variable name")
		p.consume(lexer.TokenEqual, "Expect '=' after variable name")
		expr := p.expression()
		return &LetStmt{Name: nameTok.Lexeme, Expr: expr}
	}
	
	// Return statement
	if p.match(lexer.TokenReturn) {
		var value Expr = nil
		if !p.check(lexer.TokenRBrace) && !p.isAtEnd() {
			value = p.expression()
		}
		return &ReturnStmt{Value: value}
	}
	
	// Check for assignment statement (variable = expr)
	if p.check(lexer.TokenIdent) {
		// Look ahead to see if this is an assignment
		saved := p.current
		name := p.advance().Lexeme
		if p.match(lexer.TokenEqual) {
			// This is an assignment
			value := p.expression()
			return &AssignmentStmt{Name: name, Value: value}
		}
		// Not an assignment, rewind and parse as expression
		p.current = saved
	}
	
	// Expression statement
	expr := p.expression()
	return &ExpressionStmt{Expr: expr}
}

func (p *Parser) ifStatement() Stmt {
	condition := p.expression()
	p.consume(lexer.TokenLBrace, "Expect '{' before if body")
	thenBranch := p.blockStatements()
	p.consume(lexer.TokenRBrace, "Expect '}' after if body")
	
	var elseBranch []Stmt
	if p.match(lexer.TokenElse) {
		if p.match(lexer.TokenIf) {
			// else if - parse as nested if statement
			elseBranch = []Stmt{p.ifStatement()}
		} else {
			// else block
			p.consume(lexer.TokenLBrace, "Expect '{' before else body")
			elseBranch = p.blockStatements()
			p.consume(lexer.TokenRBrace, "Expect '}' after else body")
		}
	}
	
	return &IfStmt{Condition: condition, Then: thenBranch, Else: elseBranch}
}

func (p *Parser) importStatement() Stmt {
	var path string
	var alias string
	
	if p.check(lexer.TokenString) {
		// import "path/to/module"
		pathTok := p.advance()
		path = pathTok.Lexeme
		// Scanner already removes quotes, so we use it as-is
	} else {
		// import module_name
		nameTok := p.consume(lexer.TokenIdent, "Expect module name")
		path = nameTok.Lexeme
	}
	
	// Check for alias
	if p.match(lexer.TokenAs) {
		aliasTok := p.consume(lexer.TokenIdent, "Expect alias name")
		alias = aliasTok.Lexeme
	}
	
	return &ImportStmt{Path: path, Alias: alias}
}

func (p *Parser) whileStatement() Stmt {
	condition := p.expression()
	p.consume(lexer.TokenLBrace, "Expect '{' before while body")
	body := p.blockStatements()
	p.consume(lexer.TokenRBrace, "Expect '}' after while body")
	return &WhileStmt{Condition: condition, Body: body}
}

func (p *Parser) forStatement() Stmt {
	// Check for for-in loop: for i in collection
	if p.checkNext(lexer.TokenIn) {
		variable := p.consume(lexer.TokenIdent, "Expect variable name").Lexeme
		p.consume(lexer.TokenIn, "Expect 'in'")
		collection := p.expression()
		p.consume(lexer.TokenLBrace, "Expect '{' before for body")
		body := p.blockStatements()
		p.consume(lexer.TokenRBrace, "Expect '}' after for body")
		return &ForInStmt{Variable: variable, Collection: collection, Body: body}
	}
	
	// Traditional for loop
	var init Stmt
	var condition Expr
	var update Expr
	
	p.consume(lexer.TokenLParen, "Expect '(' after 'for'")
	
	// Initialization
	if !p.check(lexer.TokenSemicolon) {
		if p.match(lexer.TokenLet) {
			nameTok := p.consume(lexer.TokenIdent, "Expect variable name")
			p.consume(lexer.TokenEqual, "Expect '='")
			expr := p.expression()
			init = &LetStmt{Name: nameTok.Lexeme, Expr: expr}
		} else {
			init = &ExpressionStmt{Expr: p.expression()}
		}
	}
	p.consume(lexer.TokenSemicolon, "Expect ';' after for loop initializer")
	
	// Condition
	if !p.check(lexer.TokenSemicolon) {
		condition = p.expression()
	}
	p.consume(lexer.TokenSemicolon, "Expect ';' after for loop condition")
	
	// Update
	if !p.check(lexer.TokenRParen) {
		update = p.expression()
	}
	p.consume(lexer.TokenRParen, "Expect ')' after for clauses")
	
	p.consume(lexer.TokenLBrace, "Expect '{' before for body")
	body := p.blockStatements()
	p.consume(lexer.TokenRBrace, "Expect '}' after for body")
	
	return &ForStmt{Init: init, Condition: condition, Update: update, Body: body}
}

func (p *Parser) blockStatements() []Stmt {
	var stmts []Stmt
	for !p.check(lexer.TokenRBrace) && !p.isAtEnd() {
		if p.match(lexer.TokenFn) {
			stmts = append(stmts, p.function())
		} else {
			stmts = append(stmts, p.statement())
		}
	}
	return stmts
}

func (p *Parser) function() Stmt {
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
		} else if p.match(lexer.TokenLBracket) {
			// Array/map indexing
			index := p.expression()
			p.consume(lexer.TokenRBracket, "Expect ']' after index")
			expr = &IndexExpr{Object: expr, Index: index}
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
	// Debug: print the token
	// fmt.Printf("DEBUG primary: token=%s lexeme=%s\n", tok.Type, tok.Lexeme)
	switch tok.Type {
	case lexer.TokenString:
		// Scanner already removes quotes and processes escape sequences
		return &Literal{Value: tok.Lexeme}
	case lexer.TokenNumber:
		var val float64
		fmt.Sscanf(tok.Lexeme, "%f", &val)
		return &Literal{Value: val}
	case lexer.TokenIdent:
		return &Variable{Name: tok.Lexeme}
	case lexer.TokenNull:
		return &Literal{Value: nil}
	case lexer.TokenTrue:
		return &Literal{Value: true}
	case lexer.TokenFalse:
		return &Literal{Value: false}
	case lexer.TokenLBracket:
		// Array literal: [1, 2, 3]
		return p.parseArrayLiteral()
	case lexer.TokenLBrace:
		// Could be map literal or block expression
		// Peek ahead to determine
		if p.isMapLiteral() {
			return p.parseMapLiteral()
		}
		// Otherwise it's a block expression
		p.current-- // Back up
		return p.parseBlockExpr()
	case lexer.TokenLParen:
		// Parenthesized expression
		expr := p.expression()
		p.consume(lexer.TokenRParen, "Expect ')' after expression")
		return expr
	case lexer.TokenNot:
		// Unary not: !expr
		operand := p.unary()
		return &UnaryExpr{Operator: "!", Operand: operand}
	case lexer.TokenMinus:
		// Unary minus: -expr
		operand := p.unary()
		return &UnaryExpr{Operator: "-", Operand: operand}
	case lexer.TokenIf:
		// Parse: if cond { then } else { else }
		cond := p.parseCondition()
		thenBranch := p.parseBlockExpr()
		var elseBranch Expr = nil
		if p.match(lexer.TokenElse) {
			if p.check(lexer.TokenIf) {
				// else if - parse as nested if expression
				elseBranch = p.primary()
			} else {
				// else block
				elseBranch = p.parseBlockExpr()
			}
		}
		return &IfExpr{
			Cond:       cond,
			ThenBranch: thenBranch,
			ElseBranch: elseBranch,
		}
	default:
		err := errors.NewSyntaxError(
			fmt.Sprintf("Unexpected token in expression: '%s'", tok.Lexeme),
			tok.File,
			tok.Line,
			tok.Column,
		)
		if p.sourceLines != nil && tok.Line > 0 && tok.Line <= len(p.sourceLines) {
			err = err.WithSource(p.sourceLines[tok.Line-1])
		}
		panic(err)
	}
}

func (p *Parser) parseArrayLiteral() Expr {
	elements := []Expr{}
	for !p.check(lexer.TokenRBracket) && !p.isAtEnd() {
		elements = append(elements, p.expression())
		if !p.match(lexer.TokenComma) {
			break
		}
	}
	p.consume(lexer.TokenRBracket, "Expect ']' after array elements")
	return &ArrayExpr{Elements: elements}
}

func (p *Parser) parseMapLiteral() Expr {
	keys := []Expr{}
	values := []Expr{}
	
	for !p.check(lexer.TokenRBrace) && !p.isAtEnd() {
		// Parse key
		key := p.expression()
		keys = append(keys, key)
		
		// Expect colon
		p.consume(lexer.TokenColon, "Expect ':' after map key")
		
		// Parse value
		value := p.expression()
		values = append(values, value)
		
		// Check for comma
		if !p.match(lexer.TokenComma) {
			break
		}
	}
	
	p.consume(lexer.TokenRBrace, "Expect '}' after map elements")
	return &MapExpr{Keys: keys, Values: values}
}

func (p *Parser) isMapLiteral() bool {
	// Look ahead to see if this is a map literal
	// Map literals have the pattern: { key: value, ... }
	saved := p.current
	defer func() { p.current = saved }()
	
	// Skip whitespace and check for key:value pattern
	if p.check(lexer.TokenRBrace) {
		return true // Empty map
	}
	
	// Try to parse a key
	if !p.match(lexer.TokenString) && !p.match(lexer.TokenIdent) && !p.match(lexer.TokenNumber) {
		return false
	}
	
	// Check for colon
	return p.check(lexer.TokenColon)
}

func (p *Parser) unary() Expr {
	if p.match(lexer.TokenNot) {
		operator := p.previous().Lexeme
		operand := p.unary()
		return &UnaryExpr{Operator: operator, Operand: operand}
	}
	if p.match(lexer.TokenMinus) {
		operator := p.previous().Lexeme
		operand := p.unary()
		return &UnaryExpr{Operator: operator, Operand: operand}
	}
	return p.primary()
}

func (p *Parser) previous() lexer.Token {
	return p.tokens[p.current-1]
}

func (p *Parser) parseCondition() Expr {
	// Simply parse an expression - the expression parser will handle everything
	return p.expression()
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
	// Create error with location information
	currentToken := p.peek()
	err := errors.NewSyntaxError(
		fmt.Sprintf("%s (got '%s')", msg, currentToken.Lexeme),
		currentToken.File,
		currentToken.Line,
		currentToken.Column,
	)
	
	// Add source line if available
	if p.sourceLines != nil && currentToken.Line > 0 && currentToken.Line <= len(p.sourceLines) {
		err = err.WithSource(p.sourceLines[currentToken.Line-1])
	}
	
	panic(err)
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
	return p.tokens[p.current-1]
}

func (p *Parser) peek() lexer.Token {
	return p.tokens[p.current]
}

func (p *Parser) isAtEnd() bool {
	return p.peek().Type == lexer.TokenEOF
}
