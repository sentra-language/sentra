package buildutil

import (
	"fmt"
	"io"
	"sentra/internal/bytecode"
)

// Chunk represents compiled bytecode
type Chunk struct {
	Code      []uint32
	Constants []interface{}
	Lines     []int
}

// BytecodeFile represents a compiled bytecode file
type BytecodeFile struct {
	Version   uint32
	Chunks    []Chunk
	MainChunk int
}

// ToChunk converts the bytecode file to a VM chunk
// STUB: Returns nil until buildutil is restored
func (bf *BytecodeFile) ToChunk() *bytecode.Chunk {
	return nil
}

// NewBytecodeFile creates a new bytecode file
func NewBytecodeFile() *BytecodeFile {
	return &BytecodeFile{
		Version: 1,
		Chunks:  make([]Chunk, 0),
	}
}

// FromBytecodeChunk converts a VM chunk to a buildutil chunk
func FromBytecodeChunk(code []uint32, constants []interface{}, lines []int) Chunk {
	return Chunk{
		Code:      code,
		Constants: constants,
		Lines:     lines,
	}
}

// Deserialize loads a bytecode file from a reader
// STUB: Returns error until buildutil is restored
func Deserialize(r io.Reader) (*BytecodeFile, error) {
	return nil, fmt.Errorf("bytecode deserialization not available: restore internal/buildutil")
}

// BuildProject builds a Sentra project
// STUB: Build system not available
func BuildProject(projectDir string, outputPath string, verbose bool) error {
	return fmt.Errorf("build system not available: restore internal/buildutil")
}

// WatchProject watches a project for changes
// STUB: Watch system not available
func WatchProject(projectDir string, verbose bool) error {
	return fmt.Errorf("watch system not available: restore internal/buildutil")
}
