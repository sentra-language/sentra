package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"sentra/internal/lexer"
	"sentra/internal/parser"
)

// LSP Protocol constants
const (
	LSPVersion = "2.0"
)

// Server is the LSP server implementation for Sentra
type Server struct {
	in      *bufio.Reader
	out     io.Writer
	mu      sync.Mutex
	docs    map[string]*Document
	running bool
}

// Document represents an open text document
type Document struct {
	URI     string
	Content string
	Version int
}

// NewServer creates a new LSP server
func NewServer(in io.Reader, out io.Writer) *Server {
	return &Server{
		in:   bufio.NewReader(in),
		out:  out,
		docs: make(map[string]*Document),
	}
}

// Start starts the LSP server main loop
func (s *Server) Start(ctx context.Context) error {
	s.running = true

	for s.running {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := s.handleMessage(); err != nil {
				if err == io.EOF {
					return nil
				}
				// Log error but continue
				fmt.Fprintf(os.Stderr, "LSP error: %v\n", err)
			}
		}
	}
	return nil
}

// handleMessage reads and processes a single LSP message
func (s *Server) handleMessage() error {
	// Read headers
	contentLength := 0
	for {
		line, err := s.in.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)

		if line == "" {
			break // End of headers
		}

		if strings.HasPrefix(line, "Content-Length:") {
			lengthStr := strings.TrimSpace(strings.TrimPrefix(line, "Content-Length:"))
			contentLength, err = strconv.Atoi(lengthStr)
			if err != nil {
				return fmt.Errorf("invalid Content-Length: %v", err)
			}
		}
	}

	if contentLength == 0 {
		return nil
	}

	// Read content
	content := make([]byte, contentLength)
	_, err := io.ReadFull(s.in, content)
	if err != nil {
		return err
	}

	// Parse JSON-RPC message
	var msg Message
	if err := json.Unmarshal(content, &msg); err != nil {
		return fmt.Errorf("failed to parse message: %v", err)
	}

	// Handle the message
	return s.dispatch(&msg)
}

// Message represents a JSON-RPC message
type Message struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *ResponseError   `json:"error,omitempty"`
}

// ResponseError represents a JSON-RPC error
type ResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// dispatch routes messages to appropriate handlers
func (s *Server) dispatch(msg *Message) error {
	switch msg.Method {
	case "initialize":
		return s.handleInitialize(msg)
	case "initialized":
		return nil // Notification, no response needed
	case "shutdown":
		return s.handleShutdown(msg)
	case "exit":
		s.running = false
		return nil
	case "textDocument/didOpen":
		return s.handleDidOpen(msg)
	case "textDocument/didChange":
		return s.handleDidChange(msg)
	case "textDocument/didClose":
		return s.handleDidClose(msg)
	case "textDocument/completion":
		return s.handleCompletion(msg)
	case "textDocument/hover":
		return s.handleHover(msg)
	case "textDocument/definition":
		return s.handleDefinition(msg)
	case "textDocument/documentSymbol":
		return s.handleDocumentSymbol(msg)
	default:
		// Unknown method - ignore notifications, error for requests
		if msg.ID != nil {
			return s.sendError(msg.ID, -32601, "Method not found: "+msg.Method)
		}
		return nil
	}
}

// sendResponse sends a JSON-RPC response
func (s *Server) sendResponse(id *json.RawMessage, result interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	response := map[string]interface{}{
		"jsonrpc": LSPVersion,
		"id":      id,
		"result":  result,
	}

	return s.writeMessage(response)
}

// sendError sends a JSON-RPC error response
func (s *Server) sendError(id *json.RawMessage, code int, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	response := map[string]interface{}{
		"jsonrpc": LSPVersion,
		"id":      id,
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}

	return s.writeMessage(response)
}

// sendNotification sends a JSON-RPC notification
func (s *Server) sendNotification(method string, params interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	notification := map[string]interface{}{
		"jsonrpc": LSPVersion,
		"method":  method,
		"params":  params,
	}

	return s.writeMessage(notification)
}

// writeMessage writes a message with LSP headers
func (s *Server) writeMessage(msg interface{}) error {
	content, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(content))
	if _, err := s.out.Write([]byte(header)); err != nil {
		return err
	}
	if _, err := s.out.Write(content); err != nil {
		return err
	}
	return nil
}

// Initialize request/response types
type InitializeParams struct {
	ProcessID    int                `json:"processId"`
	RootURI      string             `json:"rootUri"`
	Capabilities ClientCapabilities `json:"capabilities"`
}

type ClientCapabilities struct {
	TextDocument TextDocumentClientCapabilities `json:"textDocument"`
}

type TextDocumentClientCapabilities struct {
	Completion CompletionClientCapabilities `json:"completion"`
}

type CompletionClientCapabilities struct {
	CompletionItem CompletionItemCapabilities `json:"completionItem"`
}

type CompletionItemCapabilities struct {
	SnippetSupport bool `json:"snippetSupport"`
}

type InitializeResult struct {
	Capabilities ServerCapabilities `json:"capabilities"`
}

type ServerCapabilities struct {
	TextDocumentSync   int                     `json:"textDocumentSync"`
	CompletionProvider *CompletionOptions      `json:"completionProvider,omitempty"`
	HoverProvider      bool                    `json:"hoverProvider"`
	DefinitionProvider bool                    `json:"definitionProvider"`
	DocumentSymbolProvider bool                `json:"documentSymbolProvider"`
}

type CompletionOptions struct {
	TriggerCharacters []string `json:"triggerCharacters"`
	ResolveProvider   bool     `json:"resolveProvider"`
}

func (s *Server) handleInitialize(msg *Message) error {
	result := InitializeResult{
		Capabilities: ServerCapabilities{
			TextDocumentSync: 1, // Full sync
			CompletionProvider: &CompletionOptions{
				TriggerCharacters: []string{".", "("},
				ResolveProvider:   false,
			},
			HoverProvider:      true,
			DefinitionProvider: true,
			DocumentSymbolProvider: true,
		},
	}
	return s.sendResponse(msg.ID, result)
}

func (s *Server) handleShutdown(msg *Message) error {
	return s.sendResponse(msg.ID, nil)
}

// Document sync types
type DidOpenParams struct {
	TextDocument TextDocumentItem `json:"textDocument"`
}

type TextDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

type DidChangeParams struct {
	TextDocument   VersionedTextDocumentIdentifier  `json:"textDocument"`
	ContentChanges []TextDocumentContentChangeEvent `json:"contentChanges"`
}

type VersionedTextDocumentIdentifier struct {
	URI     string `json:"uri"`
	Version int    `json:"version"`
}

type TextDocumentContentChangeEvent struct {
	Text string `json:"text"`
}

type DidCloseParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

type TextDocumentIdentifier struct {
	URI string `json:"uri"`
}

func (s *Server) handleDidOpen(msg *Message) error {
	var params DidOpenParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	s.mu.Lock()
	s.docs[params.TextDocument.URI] = &Document{
		URI:     params.TextDocument.URI,
		Content: params.TextDocument.Text,
		Version: params.TextDocument.Version,
	}
	s.mu.Unlock()

	// Publish diagnostics
	return s.publishDiagnostics(params.TextDocument.URI)
}

func (s *Server) handleDidChange(msg *Message) error {
	var params DidChangeParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	s.mu.Lock()
	if doc, ok := s.docs[params.TextDocument.URI]; ok {
		if len(params.ContentChanges) > 0 {
			doc.Content = params.ContentChanges[len(params.ContentChanges)-1].Text
			doc.Version = params.TextDocument.Version
		}
	}
	s.mu.Unlock()

	return s.publishDiagnostics(params.TextDocument.URI)
}

func (s *Server) handleDidClose(msg *Message) error {
	var params DidCloseParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return err
	}

	s.mu.Lock()
	delete(s.docs, params.TextDocument.URI)
	s.mu.Unlock()

	// Clear diagnostics
	return s.sendNotification("textDocument/publishDiagnostics", map[string]interface{}{
		"uri":         params.TextDocument.URI,
		"diagnostics": []interface{}{},
	})
}

// Diagnostic types
type Diagnostic struct {
	Range    Range  `json:"range"`
	Severity int    `json:"severity"`
	Message  string `json:"message"`
	Source   string `json:"source"`
}

type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

func (s *Server) publishDiagnostics(uri string) error {
	s.mu.Lock()
	doc, ok := s.docs[uri]
	s.mu.Unlock()

	if !ok {
		return nil
	}

	diagnostics := s.getDiagnostics(doc.Content)

	return s.sendNotification("textDocument/publishDiagnostics", map[string]interface{}{
		"uri":         uri,
		"diagnostics": diagnostics,
	})
}

func (s *Server) getDiagnostics(content string) []Diagnostic {
	diagnostics := []Diagnostic{}

	// Try to parse the content
	scanner := lexer.NewScanner(content)
	tokens := scanner.ScanTokens()

	// Check for scanner errors
	if scanner.HadError() {
		diagnostics = append(diagnostics, Diagnostic{
			Range: Range{
				Start: Position{Line: 0, Character: 0},
				End:   Position{Line: 0, Character: 10},
			},
			Severity: 1, // Error
			Message:  "Lexical error in source",
			Source:   "sentra",
		})
		return diagnostics
	}

	p := parser.NewParser(tokens)
	_ = p.Parse()

	// Check for parser errors
	if len(p.Errors) > 0 {
		for _, err := range p.Errors {
			diagnostics = append(diagnostics, Diagnostic{
				Range: Range{
					Start: Position{Line: 0, Character: 0},
					End:   Position{Line: 0, Character: 10},
				},
				Severity: 1, // Error
				Message:  err.Error(),
				Source:   "sentra",
			})
		}
	}

	return diagnostics
}

// Completion types
type CompletionParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Position     Position               `json:"position"`
}

type CompletionItem struct {
	Label         string `json:"label"`
	Kind          int    `json:"kind"`
	Detail        string `json:"detail,omitempty"`
	Documentation string `json:"documentation,omitempty"`
	InsertText    string `json:"insertText,omitempty"`
}

// CompletionItemKind constants
const (
	CompletionItemKindText          = 1
	CompletionItemKindMethod        = 2
	CompletionItemKindFunction      = 3
	CompletionItemKindConstructor   = 4
	CompletionItemKindField         = 5
	CompletionItemKindVariable      = 6
	CompletionItemKindClass         = 7
	CompletionItemKindInterface     = 8
	CompletionItemKindModule        = 9
	CompletionItemKindProperty      = 10
	CompletionItemKindKeyword       = 14
	CompletionItemKindSnippet       = 15
	CompletionItemKindConstant      = 21
)

var sentraKeywords = []CompletionItem{
	{Label: "fn", Kind: CompletionItemKindKeyword, Detail: "Function declaration", InsertText: "fn ${1:name}(${2:params}) {\n\t$0\n}"},
	{Label: "let", Kind: CompletionItemKindKeyword, Detail: "Variable declaration"},
	{Label: "var", Kind: CompletionItemKindKeyword, Detail: "Mutable variable declaration"},
	{Label: "const", Kind: CompletionItemKindKeyword, Detail: "Constant declaration"},
	{Label: "if", Kind: CompletionItemKindKeyword, Detail: "Conditional statement", InsertText: "if ${1:condition} {\n\t$0\n}"},
	{Label: "else", Kind: CompletionItemKindKeyword, Detail: "Else clause"},
	{Label: "for", Kind: CompletionItemKindKeyword, Detail: "For loop", InsertText: "for ${1:i} = ${2:0}; ${1:i} < ${3:n}; ${1:i} = ${1:i} + 1 {\n\t$0\n}"},
	{Label: "while", Kind: CompletionItemKindKeyword, Detail: "While loop", InsertText: "while ${1:condition} {\n\t$0\n}"},
	{Label: "return", Kind: CompletionItemKindKeyword, Detail: "Return statement"},
	{Label: "true", Kind: CompletionItemKindConstant, Detail: "Boolean true"},
	{Label: "false", Kind: CompletionItemKindConstant, Detail: "Boolean false"},
	{Label: "nil", Kind: CompletionItemKindConstant, Detail: "Nil value"},
	{Label: "import", Kind: CompletionItemKindKeyword, Detail: "Import module"},
	{Label: "export", Kind: CompletionItemKindKeyword, Detail: "Export value"},
	{Label: "match", Kind: CompletionItemKindKeyword, Detail: "Pattern matching"},
	{Label: "try", Kind: CompletionItemKindKeyword, Detail: "Try block"},
	{Label: "catch", Kind: CompletionItemKindKeyword, Detail: "Catch block"},
	{Label: "throw", Kind: CompletionItemKindKeyword, Detail: "Throw exception"},
	{Label: "class", Kind: CompletionItemKindKeyword, Detail: "Class declaration"},
}

var sentraBuiltins = []CompletionItem{
	{Label: "print", Kind: CompletionItemKindFunction, Detail: "fn print(value)", Documentation: "Prints a value to stdout"},
	{Label: "len", Kind: CompletionItemKindFunction, Detail: "fn len(value) -> int", Documentation: "Returns length of string, array, or map"},
	{Label: "push", Kind: CompletionItemKindFunction, Detail: "fn push(array, value)", Documentation: "Appends value to array"},
	{Label: "pop", Kind: CompletionItemKindFunction, Detail: "fn pop(array) -> value", Documentation: "Removes and returns last element"},
	{Label: "keys", Kind: CompletionItemKindFunction, Detail: "fn keys(map) -> array", Documentation: "Returns array of map keys"},
	{Label: "values", Kind: CompletionItemKindFunction, Detail: "fn values(map) -> array", Documentation: "Returns array of map values"},
	{Label: "typeof", Kind: CompletionItemKindFunction, Detail: "fn typeof(value) -> string", Documentation: "Returns type name of value"},
	{Label: "str", Kind: CompletionItemKindFunction, Detail: "fn str(value) -> string", Documentation: "Converts value to string"},
	{Label: "int", Kind: CompletionItemKindFunction, Detail: "fn int(value) -> int", Documentation: "Converts value to integer"},
	{Label: "float", Kind: CompletionItemKindFunction, Detail: "fn float(value) -> float", Documentation: "Converts value to float"},
	{Label: "abs", Kind: CompletionItemKindFunction, Detail: "fn abs(n) -> number", Documentation: "Returns absolute value"},
	{Label: "sqrt", Kind: CompletionItemKindFunction, Detail: "fn sqrt(n) -> float", Documentation: "Returns square root"},
	{Label: "floor", Kind: CompletionItemKindFunction, Detail: "fn floor(n) -> int", Documentation: "Rounds down to nearest integer"},
	{Label: "ceil", Kind: CompletionItemKindFunction, Detail: "fn ceil(n) -> int", Documentation: "Rounds up to nearest integer"},
	{Label: "round", Kind: CompletionItemKindFunction, Detail: "fn round(n) -> int", Documentation: "Rounds to nearest integer"},
	{Label: "split", Kind: CompletionItemKindFunction, Detail: "fn split(str, sep) -> array", Documentation: "Splits string by separator"},
	{Label: "join", Kind: CompletionItemKindFunction, Detail: "fn join(array, sep) -> string", Documentation: "Joins array elements with separator"},
	{Label: "trim", Kind: CompletionItemKindFunction, Detail: "fn trim(str) -> string", Documentation: "Removes leading/trailing whitespace"},
	{Label: "upper", Kind: CompletionItemKindFunction, Detail: "fn upper(str) -> string", Documentation: "Converts to uppercase"},
	{Label: "lower", Kind: CompletionItemKindFunction, Detail: "fn lower(str) -> string", Documentation: "Converts to lowercase"},
}

func (s *Server) handleCompletion(msg *Message) error {
	var params CompletionParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return s.sendError(msg.ID, -32602, "Invalid params")
	}

	// Get document content
	s.mu.Lock()
	doc, ok := s.docs[params.TextDocument.URI]
	s.mu.Unlock()

	items := []CompletionItem{}

	if ok {
		// Get the word being typed
		prefix := s.getWordAtPosition(doc.Content, params.Position)

		// Add matching keywords
		for _, kw := range sentraKeywords {
			if strings.HasPrefix(kw.Label, prefix) {
				items = append(items, kw)
			}
		}

		// Add matching builtins
		for _, fn := range sentraBuiltins {
			if strings.HasPrefix(fn.Label, prefix) {
				items = append(items, fn)
			}
		}
	}

	return s.sendResponse(msg.ID, items)
}

func (s *Server) getWordAtPosition(content string, pos Position) string {
	lines := strings.Split(content, "\n")
	if pos.Line >= len(lines) {
		return ""
	}

	line := lines[pos.Line]
	if pos.Character > len(line) {
		return ""
	}

	// Find word start
	start := pos.Character
	for start > 0 && isIdentChar(line[start-1]) {
		start--
	}

	if start >= pos.Character {
		return ""
	}

	return line[start:pos.Character]
}

func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

// Hover types
type HoverParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Position     Position               `json:"position"`
}

type Hover struct {
	Contents MarkupContent `json:"contents"`
	Range    *Range        `json:"range,omitempty"`
}

type MarkupContent struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func (s *Server) handleHover(msg *Message) error {
	var params HoverParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return s.sendError(msg.ID, -32602, "Invalid params")
	}

	s.mu.Lock()
	doc, ok := s.docs[params.TextDocument.URI]
	s.mu.Unlock()

	if !ok {
		return s.sendResponse(msg.ID, nil)
	}

	word := s.getWordAtPosition(doc.Content, params.Position)
	if word == "" {
		return s.sendResponse(msg.ID, nil)
	}

	// Check keywords
	for _, kw := range sentraKeywords {
		if kw.Label == word {
			return s.sendResponse(msg.ID, Hover{
				Contents: MarkupContent{
					Kind:  "markdown",
					Value: fmt.Sprintf("**%s** (keyword)\n\n%s", kw.Label, kw.Detail),
				},
			})
		}
	}

	// Check builtins
	for _, fn := range sentraBuiltins {
		if fn.Label == word {
			return s.sendResponse(msg.ID, Hover{
				Contents: MarkupContent{
					Kind:  "markdown",
					Value: fmt.Sprintf("```sentra\n%s\n```\n\n%s", fn.Detail, fn.Documentation),
				},
			})
		}
	}

	return s.sendResponse(msg.ID, nil)
}

// Definition types
type DefinitionParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Position     Position               `json:"position"`
}

type Location struct {
	URI   string `json:"uri"`
	Range Range  `json:"range"`
}

func (s *Server) handleDefinition(msg *Message) error {
	// TODO: Implement proper definition lookup
	// For now, return null (no definition found)
	return s.sendResponse(msg.ID, nil)
}

// Document Symbol types
type DocumentSymbolParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

type DocumentSymbol struct {
	Name           string           `json:"name"`
	Kind           int              `json:"kind"`
	Range          Range            `json:"range"`
	SelectionRange Range            `json:"selectionRange"`
	Children       []DocumentSymbol `json:"children,omitempty"`
}

// SymbolKind constants
const (
	SymbolKindFile        = 1
	SymbolKindModule      = 2
	SymbolKindNamespace   = 3
	SymbolKindPackage     = 4
	SymbolKindClass       = 5
	SymbolKindMethod      = 6
	SymbolKindProperty    = 7
	SymbolKindField       = 8
	SymbolKindConstructor = 9
	SymbolKindEnum        = 10
	SymbolKindInterface   = 11
	SymbolKindFunction    = 12
	SymbolKindVariable    = 13
	SymbolKindConstant    = 14
)

func (s *Server) handleDocumentSymbol(msg *Message) error {
	var params DocumentSymbolParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return s.sendError(msg.ID, -32602, "Invalid params")
	}

	s.mu.Lock()
	doc, ok := s.docs[params.TextDocument.URI]
	s.mu.Unlock()

	if !ok {
		return s.sendResponse(msg.ID, []DocumentSymbol{})
	}

	symbols := s.extractSymbols(doc.Content)
	return s.sendResponse(msg.ID, symbols)
}

func (s *Server) extractSymbols(content string) []DocumentSymbol {
	symbols := []DocumentSymbol{}

	// Parse the content to extract symbols
	scanner := lexer.NewScanner(content)
	tokens := scanner.ScanTokens()
	if scanner.HadError() {
		return symbols
	}

	p := parser.NewParser(tokens)
	stmts := p.Parse()
	if len(p.Errors) > 0 {
		return symbols
	}

	// Extract function and variable declarations
	for _, stmt := range stmts {
		switch st := stmt.(type) {
		case *parser.FunctionStmt:
			symbols = append(symbols, DocumentSymbol{
				Name: st.Name,
				Kind: SymbolKindFunction,
				Range: Range{
					Start: Position{Line: 0, Character: 0},
					End:   Position{Line: 0, Character: len(st.Name)},
				},
				SelectionRange: Range{
					Start: Position{Line: 0, Character: 0},
					End:   Position{Line: 0, Character: len(st.Name)},
				},
			})
		case *parser.LetStmt:
			symbols = append(symbols, DocumentSymbol{
				Name: st.Name,
				Kind: SymbolKindVariable,
				Range: Range{
					Start: Position{Line: 0, Character: 0},
					End:   Position{Line: 0, Character: len(st.Name)},
				},
				SelectionRange: Range{
					Start: Position{Line: 0, Character: 0},
					End:   Position{Line: 0, Character: len(st.Name)},
				},
			})
		}
	}

	return symbols
}
