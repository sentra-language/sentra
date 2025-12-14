package lsp

import (
	"context"
	"fmt"
	"io"
)

// Server is the LSP server
type Server struct{}

// NewServer creates a new LSP server
func NewServer(in io.Reader, out io.Writer) *Server {
	return &Server{}
}

// Start starts the LSP server
// STUB: LSP server not available
func (s *Server) Start(ctx context.Context) error {
	return fmt.Errorf("LSP server not available: restore internal/lsp")
}
