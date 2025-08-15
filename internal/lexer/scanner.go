package lexer

import (
	"fmt"
	"unicode"
)

type TokenType string

const (
	// Keywords
	TokenFn      TokenType = "FN"
	TokenLet     TokenType = "LET"
	TokenVar     TokenType = "VAR"
	TokenConst   TokenType = "CONST"
	TokenIf      TokenType = "IF"
	TokenElse    TokenType = "ELSE"
	TokenReturn  TokenType = "RETURN"
	TokenWhile   TokenType = "WHILE"
	TokenFor     TokenType = "FOR"
	TokenMatch   TokenType = "MATCH"
	TokenSpawn   TokenType = "SPAWN"
	TokenImport  TokenType = "IMPORT"
	TokenChannel TokenType = "CHANNEL"
	TokenLog     TokenType = "LOG"

	// Literals & Types
	TokenTrue     TokenType = "TRUE"
	TokenFalse    TokenType = "FALSE"
	TokenNull     TokenType = "NULL"
	TokenIdent    TokenType = "IDENT"
	TokenString   TokenType = "STRING"
	TokenNumber   TokenType = "NUMBER"
	TokenInt      TokenType = "INT"
	TokenFloat    TokenType = "FLOAT"
	TokenBool     TokenType = "BOOL"
	TokenStringT  TokenType = "STRING_T"

	// Symbols
	TokenLParen      TokenType = "("
	TokenRParen      TokenType = ")"
	TokenLBrace      TokenType = "{"
	TokenRBrace      TokenType = "}"
	TokenLBracket    TokenType = "["
	TokenRBracket    TokenType = "]"
	TokenPlus        TokenType = "+"
	TokenMinus       TokenType = "-"
	TokenStar        TokenType = "*"
	TokenSlash       TokenType = "/"
	TokenPercent     TokenType = "%"
	TokenEqual       TokenType = "="
	TokenArrow       TokenType = "=>"
	TokenColon       TokenType = ":"
	TokenDoubleColon TokenType = "::"
	TokenLeftArrow   TokenType = "<-"
	TokenDoubleEqual TokenType = "=="
	TokenNotEqual    TokenType = "!="
	TokenLT          TokenType = "<"
	TokenGT          TokenType = ">"
	TokenLE          TokenType = "<="
	TokenGE          TokenType = ">="
	TokenAnd         TokenType = "&&"
	TokenOr          TokenType = "||"
	TokenNot         TokenType = "!"
	TokenComma       TokenType = ","
	TokenDot         TokenType = "."
	TokenSemicolon   TokenType = ";"
	TokenAs          TokenType = "AS"
	TokenIn          TokenType = "IN"
	TokenEOF         TokenType = "EOF"
)

type Token struct {
	Type   TokenType
	Lexeme string
	Line   int
}

func (t Token) String() string {
	return fmt.Sprintf("[%s] '%s'", t.Type, t.Lexeme)
}

type Scanner struct {
	source  string
	tokens  []Token
	start   int
	current int
	line    int
}

func NewScanner(source string) *Scanner {
	return &Scanner{
		source: source,
		line:   1,
	}
}

func (s *Scanner) ScanTokens() []Token {
	// Handle shebang at the beginning of the file
	if s.current == 0 && len(s.source) >= 2 && s.source[0] == '#' && s.source[1] == '!' {
		s.skipShebang()
	}
	
	for !s.isAtEnd() {
		s.sanitize()
		s.start = s.current
		if s.isAtEnd() { // Prevent scanToken from running at EOF
			break
		}
		s.scanToken()
	}
	s.tokens = append(s.tokens, Token{Type: TokenEOF, Lexeme: "", Line: s.line})
	return s.tokens
}

func (s *Scanner) scanToken() {
	c := s.advance()
	switch c {
	case '(':
		s.addToken(TokenLParen)
	case ')':
		s.addToken(TokenRParen)
	case '{':
		s.addToken(TokenLBrace)
	case '}':
		s.addToken(TokenRBrace)
	case '[':
		s.addToken(TokenLBracket)
	case ']':
		s.addToken(TokenRBracket)
	case '+':
		s.addToken(TokenPlus)
	case '-':
		if s.match('>') {
			s.addToken(TokenLeftArrow)
		} else {
			s.addToken(TokenMinus)
		}
	case '*':
		s.addToken(TokenStar)
	case '/':
		if s.match('/') {
			// Skip to end of line (ignore comments)
			for s.peek() != '\n' && !s.isAtEnd() {
				s.advance()
			}
		} else {
			s.addToken(TokenSlash)
		}
	case '%':
		s.addToken(TokenPercent)
	case '=':
		if s.match('=') {
			s.addToken(TokenDoubleEqual)
		} else {
			s.addToken(TokenEqual)
		}
	case '!':
		if s.match('=') {
			s.addToken(TokenNotEqual)
		} else {
			s.addToken(TokenNot)
		}
	case '<':
		if s.match('=') {
			s.addToken(TokenLE)
		} else {
			s.addToken(TokenLT)
		}
	case '>':
		if s.match('=') {
			s.addToken(TokenGE)
		} else {
			s.addToken(TokenGT)
		}
	case ':':
		if s.match(':') {
			s.addToken(TokenDoubleColon)
		} else {
			s.addToken(TokenColon)
		}
	case '"':
		s.string()
	case ',':
		s.addToken(TokenComma)
	case '.':
		s.addToken(TokenDot)
	case ';':
		s.addToken(TokenSemicolon)
	case '&':
		if s.match('&') {
			s.addToken(TokenAnd)
		}
	case '|':
		if s.match('|') {
			s.addToken(TokenOr)
		}
	case '\n':
		s.line++
	case ' ', '\r', '\t':
		// Ignore whitespace
	default:
		if isDigit(c) {
			s.number()
		} else if isAlpha(c) {
			s.identifier()
		}
	}
}

func (s *Scanner) match(expected byte) bool {
	if s.isAtEnd() || s.source[s.current] != expected {
		return false
	}
	s.current++
	return true
}

func (s *Scanner) identifier() {
	for isAlphaNumeric(s.peek()) {
		s.advance()
	}
	text := s.source[s.start:s.current]
	switch text {
	case "fn":
		s.addToken(TokenFn)
	case "let":
		s.addToken(TokenLet)
	case "var":
		s.addToken(TokenVar)
	case "const":
		s.addToken(TokenConst)
	case "if":
		s.addToken(TokenIf)
	case "else":
		s.addToken(TokenElse)
	case "return":
		s.addToken(TokenReturn)
	case "while":
		s.addToken(TokenWhile)
	case "for":
		s.addToken(TokenFor)
	case "spawn":
		s.addToken(TokenSpawn)
	case "import":
		s.addToken(TokenImport)
	case "channel":
		s.addToken(TokenChannel)
	case "log":
		s.addToken(TokenLog)
	case "true":
		s.addToken(TokenTrue)
	case "false":
		s.addToken(TokenFalse)
	case "null":
		s.addToken(TokenNull)
	case "int":
		s.addToken(TokenInt)
	case "float":
		s.addToken(TokenFloat)
	case "bool":
		s.addToken(TokenBool)
	case "string":
		s.addToken(TokenStringT)
	case "as":
		s.addToken(TokenAs)
	case "in":
		s.addToken(TokenIn)
	default:
		s.addToken(TokenIdent)
	}
}

func (s *Scanner) number() {
	for isDigit(s.peek()) {
		s.advance()
	}
	s.tokens = append(s.tokens, Token{Type: TokenNumber, Lexeme: s.source[s.start:s.current], Line: s.line})
}

func (s *Scanner) string() {
	for s.peek() != '"' && !s.isAtEnd() {
		if s.peek() == '\n' {
			s.line++
		}
		s.advance()
	}
	if s.isAtEnd() {
		return // Unterminated string; ignore for now
	}
	s.advance()
	value := s.source[s.start+1 : s.current-1]
	s.tokens = append(s.tokens, Token{Type: TokenString, Lexeme: value, Line: s.line})
}

func (s *Scanner) addToken(t TokenType) {
	text := s.source[s.start:s.current]
	s.tokens = append(s.tokens, Token{Type: t, Lexeme: text, Line: s.line})
}

func (s *Scanner) advance() byte {
	s.current++
	return s.source[s.current-1]
}

func (s *Scanner) peek() byte {
	if s.isAtEnd() {
		return '\000'
	}
	return s.source[s.current]
}

func (s *Scanner) isAtEnd() bool {
	return s.current >= len(s.source)
}

func (s *Scanner) sanitize() {
	for !s.isAtEnd() && unicode.IsSpace(rune(s.peek())) {
		if s.peek() == '\n' {
			s.line++
		}
		s.advance()
	}
}

func isAlpha(c byte) bool {
	return unicode.IsLetter(rune(c)) || c == '_'
}

func isAlphaNumeric(c byte) bool {
	return isAlpha(c) || unicode.IsDigit(rune(c))
}

func isDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

// skipShebang skips over shebang line at the beginning of the file
func (s *Scanner) skipShebang() {
	// Skip until end of line
	for !s.isAtEnd() && s.peek() != '\n' {
		s.advance()
	}
	// Skip the newline
	if !s.isAtEnd() && s.peek() == '\n' {
		s.line++
		s.advance()
	}
}
