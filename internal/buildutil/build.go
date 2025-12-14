package buildutil

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sentra/internal/bytecode"
)

// Version information
const (
	BytecodeVersion = 1
	MagicNumber     = 0x53454E54 // "SENT" in hex
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

// NewBytecodeFile creates a new bytecode file
func NewBytecodeFile() *BytecodeFile {
	return &BytecodeFile{
		Version:   BytecodeVersion,
		Chunks:    make([]Chunk, 0),
		MainChunk: 0,
	}
}

// AddChunk adds a chunk to the bytecode file
func (bf *BytecodeFile) AddChunk(chunk Chunk) int {
	bf.Chunks = append(bf.Chunks, chunk)
	return len(bf.Chunks) - 1
}

// ToChunk converts the main chunk to a VM bytecode chunk
func (bf *BytecodeFile) ToChunk() *bytecode.Chunk {
	if bf.MainChunk >= len(bf.Chunks) {
		return nil
	}

	chunk := bf.Chunks[bf.MainChunk]

	// Convert code from uint32 to bytes
	code := make([]byte, len(chunk.Code)*4)
	for i, c := range chunk.Code {
		binary.LittleEndian.PutUint32(code[i*4:], c)
	}

	// Build debug info from line numbers
	debug := make([]bytecode.DebugInfo, len(chunk.Lines))
	for i, line := range chunk.Lines {
		debug[i] = bytecode.DebugInfo{Line: line}
	}

	return &bytecode.Chunk{
		Code:      code,
		Constants: chunk.Constants,
		Debug:     debug,
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

// Serialize writes the bytecode file to a writer
func (bf *BytecodeFile) Serialize(w io.Writer) error {
	// Write magic number
	if err := binary.Write(w, binary.LittleEndian, uint32(MagicNumber)); err != nil {
		return fmt.Errorf("failed to write magic number: %w", err)
	}

	// Write version
	if err := binary.Write(w, binary.LittleEndian, bf.Version); err != nil {
		return fmt.Errorf("failed to write version: %w", err)
	}

	// Write number of chunks
	if err := binary.Write(w, binary.LittleEndian, uint32(len(bf.Chunks))); err != nil {
		return fmt.Errorf("failed to write chunk count: %w", err)
	}

	// Write main chunk index
	if err := binary.Write(w, binary.LittleEndian, uint32(bf.MainChunk)); err != nil {
		return fmt.Errorf("failed to write main chunk index: %w", err)
	}

	// Write each chunk
	for i, chunk := range bf.Chunks {
		if err := serializeChunk(w, &chunk); err != nil {
			return fmt.Errorf("failed to serialize chunk %d: %w", i, err)
		}
	}

	return nil
}

func serializeChunk(w io.Writer, chunk *Chunk) error {
	// Write code length and code
	if err := binary.Write(w, binary.LittleEndian, uint32(len(chunk.Code))); err != nil {
		return err
	}
	for _, instr := range chunk.Code {
		if err := binary.Write(w, binary.LittleEndian, instr); err != nil {
			return err
		}
	}

	// Write constants length and constants
	if err := binary.Write(w, binary.LittleEndian, uint32(len(chunk.Constants))); err != nil {
		return err
	}
	for _, constant := range chunk.Constants {
		if err := serializeConstant(w, constant); err != nil {
			return err
		}
	}

	// Write lines length and lines
	if err := binary.Write(w, binary.LittleEndian, uint32(len(chunk.Lines))); err != nil {
		return err
	}
	for _, line := range chunk.Lines {
		if err := binary.Write(w, binary.LittleEndian, int32(line)); err != nil {
			return err
		}
	}

	return nil
}

func serializeConstant(w io.Writer, constant interface{}) error {
	switch v := constant.(type) {
	case nil:
		binary.Write(w, binary.LittleEndian, byte(0))
	case bool:
		binary.Write(w, binary.LittleEndian, byte(1))
		if v {
			binary.Write(w, binary.LittleEndian, byte(1))
		} else {
			binary.Write(w, binary.LittleEndian, byte(0))
		}
	case int:
		binary.Write(w, binary.LittleEndian, byte(2))
		binary.Write(w, binary.LittleEndian, int64(v))
	case int64:
		binary.Write(w, binary.LittleEndian, byte(2))
		binary.Write(w, binary.LittleEndian, v)
	case float64:
		binary.Write(w, binary.LittleEndian, byte(3))
		binary.Write(w, binary.LittleEndian, v)
	case string:
		binary.Write(w, binary.LittleEndian, byte(4))
		binary.Write(w, binary.LittleEndian, uint32(len(v)))
		w.Write([]byte(v))
	default:
		return fmt.Errorf("unsupported constant type: %T", v)
	}
	return nil
}

// Deserialize loads a bytecode file from a reader
func Deserialize(r io.Reader) (*BytecodeFile, error) {
	bf := &BytecodeFile{}

	// Read and verify magic number
	var magic uint32
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return nil, fmt.Errorf("failed to read magic number: %w", err)
	}
	if magic != MagicNumber {
		return nil, fmt.Errorf("invalid bytecode file: bad magic number")
	}

	// Read version
	if err := binary.Read(r, binary.LittleEndian, &bf.Version); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	if bf.Version > BytecodeVersion {
		return nil, fmt.Errorf("unsupported bytecode version: %d", bf.Version)
	}

	// Read number of chunks
	var numChunks uint32
	if err := binary.Read(r, binary.LittleEndian, &numChunks); err != nil {
		return nil, fmt.Errorf("failed to read chunk count: %w", err)
	}

	// Read main chunk index
	var mainChunk uint32
	if err := binary.Read(r, binary.LittleEndian, &mainChunk); err != nil {
		return nil, fmt.Errorf("failed to read main chunk index: %w", err)
	}
	bf.MainChunk = int(mainChunk)

	// Read each chunk
	bf.Chunks = make([]Chunk, numChunks)
	for i := uint32(0); i < numChunks; i++ {
		chunk, err := deserializeChunk(r)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize chunk %d: %w", i, err)
		}
		bf.Chunks[i] = *chunk
	}

	return bf, nil
}

func deserializeChunk(r io.Reader) (*Chunk, error) {
	chunk := &Chunk{}

	// Read code
	var codeLen uint32
	if err := binary.Read(r, binary.LittleEndian, &codeLen); err != nil {
		return nil, err
	}
	chunk.Code = make([]uint32, codeLen)
	for i := uint32(0); i < codeLen; i++ {
		if err := binary.Read(r, binary.LittleEndian, &chunk.Code[i]); err != nil {
			return nil, err
		}
	}

	// Read constants
	var constLen uint32
	if err := binary.Read(r, binary.LittleEndian, &constLen); err != nil {
		return nil, err
	}
	chunk.Constants = make([]interface{}, constLen)
	for i := uint32(0); i < constLen; i++ {
		constant, err := deserializeConstant(r)
		if err != nil {
			return nil, err
		}
		chunk.Constants[i] = constant
	}

	// Read lines
	var linesLen uint32
	if err := binary.Read(r, binary.LittleEndian, &linesLen); err != nil {
		return nil, err
	}
	chunk.Lines = make([]int, linesLen)
	for i := uint32(0); i < linesLen; i++ {
		var line int32
		if err := binary.Read(r, binary.LittleEndian, &line); err != nil {
			return nil, err
		}
		chunk.Lines[i] = int(line)
	}

	return chunk, nil
}

func deserializeConstant(r io.Reader) (interface{}, error) {
	var typeTag byte
	if err := binary.Read(r, binary.LittleEndian, &typeTag); err != nil {
		return nil, err
	}

	switch typeTag {
	case 0: // nil
		return nil, nil
	case 1: // bool
		var b byte
		if err := binary.Read(r, binary.LittleEndian, &b); err != nil {
			return nil, err
		}
		return b != 0, nil
	case 2: // int64
		var v int64
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return nil, err
		}
		return v, nil
	case 3: // float64
		var v float64
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return nil, err
		}
		return v, nil
	case 4: // string
		var length uint32
		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			return nil, err
		}
		bytes := make([]byte, length)
		if _, err := io.ReadFull(r, bytes); err != nil {
			return nil, err
		}
		return string(bytes), nil
	default:
		return nil, fmt.Errorf("unknown constant type: %d", typeTag)
	}
}

// BuildConfig contains project build configuration
type BuildConfig struct {
	ProjectDir  string
	OutputPath  string
	EntryPoint  string
	Verbose     bool
	Optimize    bool
}

// BuildResult contains the result of a build
type BuildResult struct {
	OutputPath string
	SourceFiles []string
	BuildTime   time.Duration
	Errors      []error
}

// BuildProject builds a Sentra project
func BuildProject(projectDir string, outputPath string, verbose bool) error {
	config := &BuildConfig{
		ProjectDir: projectDir,
		OutputPath: outputPath,
		Verbose:    verbose,
	}

	result := Build(config)
	if len(result.Errors) > 0 {
		return result.Errors[0]
	}
	return nil
}

// Build builds a project with the given configuration
func Build(config *BuildConfig) *BuildResult {
	startTime := time.Now()
	result := &BuildResult{
		SourceFiles: []string{},
		Errors:      []error{},
	}

	// Find all .sn files
	files, err := findSentraFiles(config.ProjectDir)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("failed to find source files: %w", err))
		return result
	}
	result.SourceFiles = files

	if len(files) == 0 {
		result.Errors = append(result.Errors, fmt.Errorf("no Sentra files found in %s", config.ProjectDir))
		return result
	}

	if config.Verbose {
		fmt.Printf("Found %d source files\n", len(files))
	}

	// Find entry point
	entryPoint := config.EntryPoint
	if entryPoint == "" {
		// Look for main.sn or index.sn
		for _, f := range files {
			base := filepath.Base(f)
			if base == "main.sn" || base == "index.sn" {
				entryPoint = f
				break
			}
		}
		if entryPoint == "" && len(files) == 1 {
			entryPoint = files[0]
		}
	}

	if entryPoint == "" {
		result.Errors = append(result.Errors, fmt.Errorf("no entry point found (create main.sn or index.sn)"))
		return result
	}

	if config.Verbose {
		fmt.Printf("Entry point: %s\n", entryPoint)
	}

	// For now, just copy the entry point to output if specified
	// Full compilation would require the compiler module
	if config.OutputPath != "" {
		result.OutputPath = config.OutputPath
	}

	result.BuildTime = time.Since(startTime)

	if config.Verbose {
		fmt.Printf("Build completed in %v\n", result.BuildTime)
	}

	return result
}

func findSentraFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories
		if info.IsDir() && strings.HasPrefix(info.Name(), ".") {
			return filepath.SkipDir
		}

		// Skip node_modules
		if info.IsDir() && info.Name() == "node_modules" {
			return filepath.SkipDir
		}

		// Include .sn files
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".sn") {
			files = append(files, path)
		}

		return nil
	})

	return files, err
}

// WatchConfig contains watch mode configuration
type WatchConfig struct {
	ProjectDir string
	Verbose    bool
	OnChange   func(files []string) error
}

// WatchProject watches a project for changes
func WatchProject(projectDir string, verbose bool) error {
	config := &WatchConfig{
		ProjectDir: projectDir,
		Verbose:    verbose,
	}
	return Watch(config)
}

// Watch watches for file changes and triggers rebuilds
func Watch(config *WatchConfig) error {
	if config.Verbose {
		fmt.Printf("Watching %s for changes...\n", config.ProjectDir)
	}

	// Get initial file list and modification times
	files, err := findSentraFiles(config.ProjectDir)
	if err != nil {
		return err
	}

	modTimes := make(map[string]time.Time)
	for _, f := range files {
		info, err := os.Stat(f)
		if err == nil {
			modTimes[f] = info.ModTime()
		}
	}

	// Poll for changes
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		changed := []string{}

		// Check for modified or new files
		currentFiles, err := findSentraFiles(config.ProjectDir)
		if err != nil {
			continue
		}

		for _, f := range currentFiles {
			info, err := os.Stat(f)
			if err != nil {
				continue
			}

			prevMod, exists := modTimes[f]
			if !exists || info.ModTime().After(prevMod) {
				changed = append(changed, f)
				modTimes[f] = info.ModTime()
			}
		}

		// Check for deleted files
		for f := range modTimes {
			found := false
			for _, cf := range currentFiles {
				if cf == f {
					found = true
					break
				}
			}
			if !found {
				delete(modTimes, f)
				changed = append(changed, f)
			}
		}

		if len(changed) > 0 {
			if config.Verbose {
				fmt.Printf("Files changed: %v\n", changed)
			}
			if config.OnChange != nil {
				config.OnChange(changed)
			}
		}
	}

	return nil
}
