# Sentra Module System Implementation Plan

## Current State Analysis

### What's Working:
1. **Parser Support**: ImportStmt already exists in AST
2. **Bytecode Support**: OpImport opcode exists
3. **Compiler Support**: VisitImportStmt generates OpImport
4. **VM Module Loading**: loadModule() for built-in modules (math, string, etc.)
5. **Module Structure**: Module type with Name, Exports, Loaded fields

### What's Missing:
1. **File Loading**: No support for loading .sn files as modules
2. **Export Statements**: No way to mark exports in source files
3. **Path Resolution**: No file path resolution logic
4. **Module Compilation**: No compilation of imported .sn files
5. **Circular Dependency Detection**: No protection against circular imports
6. **Module Caching**: Basic caching exists but not for file modules

## Implementation Plan

### Phase 1: Add Export Support (Non-Breaking)
1. Add `export` keyword to lexer
2. Add ExportStmt to AST
3. Track exports during compilation
4. Store export information in compiled chunk

### Phase 2: Module Loader Infrastructure
1. Create ModuleLoader type to handle file loading
2. Add module search paths (relative, project root, stdlib)
3. Implement module cache with compiled bytecode
4. Add circular dependency detection

### Phase 3: File Import Implementation
1. Enhance loadModule to detect file paths (.sn extension)
2. Read and compile imported .sn files
3. Execute module in isolated environment
4. Collect exports into Module.Exports map
5. Return module to importing code

### Phase 4: Module Resolution
1. Implement path resolution algorithm:
   - Check if path starts with ./ or ../ (relative)
   - Check project root
   - Check standard library location
   - Check sentra.mod dependencies
2. Handle different import syntaxes:
   - `import "./file.sn" as alias`
   - `import "module"` (built-in)

### Phase 5: Testing & Documentation
1. Test with example-project
2. Test circular dependency detection
3. Update documentation
4. Add integration tests

## Technical Design

### Module Loading Flow:
```
1. Parse: import "./utils/logger.sn" as logger
2. Compile: OpImport with path constant
3. VM Execute OpImport:
   a. Check module cache
   b. If not cached:
      - Resolve file path
      - Read .sn file
      - Compile to bytecode
      - Create isolated VM context
      - Execute module
      - Collect exports
      - Cache result
   c. Push module (Map) to stack
4. Store in variable (logger)
```

### Export Collection:
```sentra
// In module.sn
export fn hello() { return "Hello" }
export let version = "1.0"
let internal = "private"  // Not exported

// Compiles to:
// OpExport "hello" <function>
// OpExport "version" "1.0"
```

### Module Structure:
```go
type FileModule struct {
    Path     string
    Chunk    *Chunk
    Exports  map[string]Value
    VM       *EnhancedVM  // Isolated context
}
```

## Implementation Steps

### Step 1: Add Export Keyword
```go
// lexer/scanner.go
case 'e':
    if s.checkKeyword("export") {
        s.addToken(EXPORT)
    }
```

### Step 2: Add Export Statement
```go
// parser/stmt.go
type ExportStmt struct {
    Name  string
    Value Expr
}
```

### Step 3: Module Loader
```go
// vm/module_loader.go
type ModuleLoader struct {
    cache     map[string]*Module
    searchPaths []string
    vm        *EnhancedVM
}

func (ml *ModuleLoader) LoadModule(path string) (*Module, error) {
    // Implementation
}
```

### Step 4: Enhanced loadModule
```go
func (vm *EnhancedVM) loadModule(name string) Value {
    // Check if it's a file path
    if strings.HasSuffix(name, ".sn") {
        return vm.loadFileModule(name)
    }
    // Existing built-in module logic...
}
```

## Testing Strategy

### Test Cases:
1. Simple module import/export
2. Nested imports (A imports B imports C)
3. Circular dependency detection
4. Module with multiple exports
5. Re-export from imported modules
6. Error handling for missing files
7. Path resolution tests

### Example Test:
```sentra
// math_utils.sn
export fn add(a, b) {
    return a + b
}

export fn multiply(a, b) {
    return a * b
}

// main.sn
import "./math_utils.sn" as math
log(math.add(2, 3))  // 5
log(math.multiply(3, 4))  // 12
```

## Backwards Compatibility

### Ensuring No Breaks:
1. Built-in modules continue to work unchanged
2. Existing import syntax remains valid
3. New export keyword doesn't conflict
4. Module objects pattern still works
5. All existing examples continue to run

### Migration Path:
- Phase 1: Both patterns work (module objects + file imports)
- Phase 2: Gradual migration to file imports
- Phase 3: Module objects remain for backwards compatibility

## Risk Mitigation

### Potential Issues:
1. **Performance**: Cache compiled modules
2. **Memory**: Limit module cache size
3. **Security**: Validate file paths, prevent directory traversal
4. **Complexity**: Keep implementation simple initially
5. **Debugging**: Add clear error messages

## Success Criteria

1. ✅ example-project works with file imports
2. ✅ No existing functionality broken
3. ✅ Clear error messages for import failures
4. ✅ Documentation updated
5. ✅ Tests pass
6. ✅ Performance acceptable (< 100ms per import)