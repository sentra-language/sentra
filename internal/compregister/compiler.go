package compregister

import (
	"fmt"
	"sentra/internal/parser"
	"sentra/internal/vmregister"
)

// Compiler compiles AST to register-based bytecode
type Compiler struct {
	// Code generation
	code      []vmregister.Instruction
	constants []vmregister.Value

	// Register allocation
	allocator *RegisterAllocator

	// Scope management
	scope      *Scope
	scopeDepth int

	// Global variables
	globalNames  map[string]uint16
	nextGlobalID uint16

	// Function compilation
	functions []*vmregister.FunctionObj

	// Loop management (for break/continue)
	loopStack []LoopInfo

	// Error tracking
	errors []error
}

// LoopInfo tracks loop state for break/continue
type LoopInfo struct {
	startPC    int
	breakJumps []int // PCs of break jumps to patch
}

// Scope tracks local variables
type Scope struct {
	parent *Scope
	locals map[string]int // name -> register
	depth  int
}

// RegisterAllocator manages register allocation
type RegisterAllocator struct {
	nextReg  int
	maxReg   int
	freeRegs []int
	locked   map[int]bool
}

// NewCompilerWithGlobals creates a compiler with pre-defined global names
func NewCompilerWithGlobals(globalNames map[string]uint16, nextID uint16) *Compiler {
	c := &Compiler{
		code:         make([]vmregister.Instruction, 0),
		constants:    make([]vmregister.Value, 0),
		allocator:    NewRegisterAllocator(),
		globalNames:  globalNames,
		nextGlobalID: nextID,
		functions:    make([]*vmregister.FunctionObj, 0),
		loopStack:    make([]LoopInfo, 0),
		errors:       make([]error, 0),
	}
	c.scope = &Scope{
		locals: make(map[string]int),
		depth:  0,
	}
	return c
}

// NewRegisterAllocator creates a new register allocator
func NewRegisterAllocator() *RegisterAllocator {
	return &RegisterAllocator{
		nextReg:  0,
		maxReg:   0,
		freeRegs: make([]int, 0),
		locked:   make(map[int]bool),
	}
}

// Alloc allocates a register
func (ra *RegisterAllocator) Alloc() int {
	if len(ra.freeRegs) > 0 {
		reg := ra.freeRegs[len(ra.freeRegs)-1]
		ra.freeRegs = ra.freeRegs[:len(ra.freeRegs)-1]
		return reg
	}
	reg := ra.nextReg
	ra.nextReg++
	if ra.nextReg > ra.maxReg {
		ra.maxReg = ra.nextReg
	}
	return reg
}

// Free frees a register
func (ra *RegisterAllocator) Free(reg int) {
	if !ra.locked[reg] {
		ra.freeRegs = append(ra.freeRegs, reg)
	}
}

// Lock prevents a register from being freed
func (ra *RegisterAllocator) Lock(reg int) {
	ra.locked[reg] = true
}

// Unlock allows a register to be freed
func (ra *RegisterAllocator) Unlock(reg int) {
	delete(ra.locked, reg)
}

// findConsecutiveRegisters finds n consecutive registers that are not locked
func (c *Compiler) findConsecutiveRegisters(n int) int {
	// Start from the next available register and find n consecutive unlocked ones
	start := c.allocator.nextReg
	for {
		allFree := true
		for i := 0; i < n; i++ {
			if c.allocator.locked[start+i] {
				allFree = false
				start = start + i + 1 // Skip past the locked register
				break
			}
		}
		if allFree {
			// Update nextReg to be after these registers
			if start+n > c.allocator.nextReg {
				c.allocator.nextReg = start + n
				if c.allocator.nextReg > c.allocator.maxReg {
					c.allocator.maxReg = c.allocator.nextReg
				}
			}
			return start
		}
	}
}

// Compile compiles statements to a FunctionObj
func (c *Compiler) Compile(stmts []parser.Stmt) (*vmregister.FunctionObj, error) {
	// Compile all statements
	for _, stmt := range stmts {
		c.compileStmt(stmt)
	}

	// Add implicit return nil
	c.emit(vmregister.CreateABC(vmregister.OP_RETURN, 0, 1, 0))

	// Check for errors
	if len(c.errors) > 0 {
		return nil, c.errors[0]
	}

	// Create function object
	fn := &vmregister.FunctionObj{
		Object:    vmregister.Object{Type: vmregister.OBJ_FUNCTION},
		Name:      "<main>",
		Arity:     0,
		Code:      c.code,
		Constants: c.constants,
	}

	return fn, nil
}

// emit adds an instruction and returns its position
func (c *Compiler) emit(instr vmregister.Instruction) int {
	pos := len(c.code)
	c.code = append(c.code, instr)
	return pos
}

// addConstant adds a constant and returns its index
func (c *Compiler) addConstant(val vmregister.Value) uint16 {
	for i, v := range c.constants {
		if v == val {
			return uint16(i)
		}
	}
	idx := len(c.constants)
	c.constants = append(c.constants, val)
	return uint16(idx)
}

// addStringConstant adds a string constant
func (c *Compiler) addStringConstant(s string) uint16 {
	return c.addConstant(vmregister.BoxString(s))
}

// addNumberConstant adds a number constant
func (c *Compiler) addNumberConstant(n float64) uint16 {
	// Check if it's an integer
	if n == float64(int64(n)) && n >= -32768 && n <= 32767 {
		return c.addConstant(vmregister.BoxInt(int64(n)))
	}
	return c.addConstant(vmregister.BoxNumber(n))
}

// getOrAssignGlobalID gets or creates a global ID for a name
func (c *Compiler) getOrAssignGlobalID(name string) uint16 {
	if id, ok := c.globalNames[name]; ok {
		return id
	}
	id := c.nextGlobalID
	c.globalNames[name] = id
	c.nextGlobalID++
	return id
}

// Define a local variable in current scope
func (c *Compiler) defineLocal(name string) int {
	reg := c.allocator.Alloc()
	c.scope.locals[name] = reg
	c.allocator.Lock(reg)
	return reg
}

// Resolve a variable (returns register if local, -1 if global)
func (c *Compiler) resolveLocal(name string) int {
	scope := c.scope
	for scope != nil {
		if reg, ok := scope.locals[name]; ok {
			return reg
		}
		scope = scope.parent
	}
	return -1 // Global
}

// pushScope creates a new scope
func (c *Compiler) pushScope() {
	c.scope = &Scope{
		parent: c.scope,
		locals: make(map[string]int),
		depth:  c.scopeDepth + 1,
	}
	c.scopeDepth++
}

// popScope removes current scope and frees its registers
func (c *Compiler) popScope() {
	for _, reg := range c.scope.locals {
		c.allocator.Unlock(reg)
		c.allocator.Free(reg)
	}
	c.scope = c.scope.parent
	c.scopeDepth--
}

// error adds a compilation error
func (c *Compiler) error(msg string) {
	c.errors = append(c.errors, fmt.Errorf("compile error: %s", msg))
}

// compileStmt compiles a statement
func (c *Compiler) compileStmt(stmt parser.Stmt) {
	switch s := stmt.(type) {
	case *parser.PrintStmt:
		c.compilePrintStmt(s)
	case *parser.LetStmt:
		c.compileLetStmt(s)
	case *parser.AssignmentStmt:
		c.compileAssignmentStmt(s)
	case *parser.IndexAssignmentStmt:
		c.compileIndexAssignmentStmt(s)
	case *parser.ExpressionStmt:
		c.compileExpressionStmt(s)
	case *parser.FunctionStmt:
		c.compileFunctionStmt(s)
	case *parser.ReturnStmt:
		c.compileReturnStmt(s)
	case *parser.IfStmt:
		c.compileIfStmt(s)
	case *parser.WhileStmt:
		c.compileWhileStmt(s)
	case *parser.ForStmt:
		c.compileForStmt(s)
	case *parser.ForInStmt:
		c.compileForInStmt(s)
	case *parser.BreakStmt:
		c.compileBreakStmt(s)
	case *parser.ContinueStmt:
		c.compileContinueStmt(s)
	case *parser.ImportStmt:
		c.compileImportStmt(s)
	case *parser.ExportStmt:
		c.compileExportStmt(s)
	case *parser.TryStmt:
		c.compileTryStmt(s)
	case *parser.ThrowStmt:
		c.compileThrowStmt(s)
	case *parser.ClassStmt:
		c.compileClassStmt(s)
	case *parser.MatchStmt:
		c.compileMatchStmt(s)
	default:
		c.error(fmt.Sprintf("unknown statement type: %T", stmt))
	}
}

// compilePrintStmt compiles a print statement
func (c *Compiler) compilePrintStmt(s *parser.PrintStmt) {
	reg := c.compileExpr(s.Expr)
	c.emit(vmregister.CreateABC(vmregister.OP_PRINT, uint8(reg), 0, 0))
	c.allocator.Free(reg)
}

// compileLetStmt compiles a let statement
func (c *Compiler) compileLetStmt(s *parser.LetStmt) {
	if c.scopeDepth == 0 {
		// Global variable
		globalID := c.getOrAssignGlobalID(s.Name)
		if s.Expr != nil {
			reg := c.compileExpr(s.Expr)
			c.emit(vmregister.CreateABx(vmregister.OP_SETGLOBAL, uint8(reg), globalID))
			c.allocator.Free(reg)
		} else {
			// Initialize to nil
			reg := c.allocator.Alloc()
			c.emit(vmregister.CreateABC(vmregister.OP_LOADNIL, uint8(reg), 0, 0))
			c.emit(vmregister.CreateABx(vmregister.OP_SETGLOBAL, uint8(reg), globalID))
			c.allocator.Free(reg)
		}
	} else {
		// Local variable - compile init FIRST to avoid register conflicts
		if s.Expr != nil {
			initReg := c.compileExpr(s.Expr)
			// Now define the local and move result into it
			reg := c.defineLocal(s.Name)
			if initReg != reg {
				c.emit(vmregister.CreateABC(vmregister.OP_MOVE, uint8(reg), uint8(initReg), 0))
				c.allocator.Free(initReg)
			} else {
				// initReg == reg means the init expression result is already in the right place
				// This shouldn't happen often, but handle it
			}
		} else {
			reg := c.defineLocal(s.Name)
			c.emit(vmregister.CreateABC(vmregister.OP_LOADNIL, uint8(reg), 0, 0))
		}
	}
}

// compileAssignmentStmt compiles an assignment statement
func (c *Compiler) compileAssignmentStmt(s *parser.AssignmentStmt) {
	localReg := c.resolveLocal(s.Name)
	if localReg >= 0 {
		// Local variable
		valueReg := c.compileExpr(s.Value)
		if valueReg != localReg {
			c.emit(vmregister.CreateABC(vmregister.OP_MOVE, uint8(localReg), uint8(valueReg), 0))
			c.allocator.Free(valueReg)
		}
	} else {
		// Global variable
		globalID := c.getOrAssignGlobalID(s.Name)
		valueReg := c.compileExpr(s.Value)
		c.emit(vmregister.CreateABx(vmregister.OP_SETGLOBAL, uint8(valueReg), globalID))
		c.allocator.Free(valueReg)
	}
}

// compileIndexAssignmentStmt compiles index assignment (arr[i] = v)
func (c *Compiler) compileIndexAssignmentStmt(s *parser.IndexAssignmentStmt) {
	objReg := c.compileExpr(s.Object)
	indexReg := c.compileExpr(s.Index)
	valueReg := c.compileExpr(s.Value)
	c.emit(vmregister.CreateABC(vmregister.OP_SETTABLE, uint8(objReg), uint8(indexReg), uint8(valueReg)))
	c.allocator.Free(objReg)
	c.allocator.Free(indexReg)
	c.allocator.Free(valueReg)
}

// compileExpressionStmt compiles an expression statement
func (c *Compiler) compileExpressionStmt(s *parser.ExpressionStmt) {
	reg := c.compileExpr(s.Expr)
	c.allocator.Free(reg)
}

// compileFunctionStmt compiles a function declaration
func (c *Compiler) compileFunctionStmt(s *parser.FunctionStmt) {
	// Save current compilation state
	parentCode := c.code
	parentConsts := c.constants
	parentAllocator := c.allocator

	// Create new compilation state for function
	c.code = make([]vmregister.Instruction, 0)
	c.constants = make([]vmregister.Value, 0)
	c.allocator = NewRegisterAllocator()

	// Create scope for function
	c.pushScope()

	// Define parameters as locals
	for _, param := range s.Params {
		c.defineLocal(param)
	}

	// Compile function body
	for _, stmt := range s.Body {
		c.compileStmt(stmt)
	}

	// Add implicit return nil
	c.emit(vmregister.CreateABC(vmregister.OP_RETURN, 0, 1, 0))

	// Create function object
	fn := &vmregister.FunctionObj{
		Object:    vmregister.Object{Type: vmregister.OBJ_FUNCTION},
		Name:      s.Name,
		Arity:     len(s.Params),
		Code:      c.code,
		Constants: c.constants,
	}

	// Pop function scope
	c.popScope()

	// Restore parent compilation state
	c.code = parentCode
	c.constants = parentConsts
	c.allocator = parentAllocator

	// Add function to constants and create closure
	fnIdx := c.addConstant(vmregister.BoxFunction(fn))

	if c.scopeDepth == 0 {
		// Global function
		globalID := c.getOrAssignGlobalID(s.Name)
		closureReg := c.allocator.Alloc()
		c.emit(vmregister.CreateABx(vmregister.OP_CLOSURE, uint8(closureReg), fnIdx))
		c.emit(vmregister.CreateABx(vmregister.OP_SETGLOBAL, uint8(closureReg), globalID))
		c.allocator.Free(closureReg)
	} else {
		// Local function
		reg := c.defineLocal(s.Name)
		c.emit(vmregister.CreateABx(vmregister.OP_CLOSURE, uint8(reg), fnIdx))
	}
}

// compileReturnStmt compiles a return statement
func (c *Compiler) compileReturnStmt(s *parser.ReturnStmt) {
	if s.Value != nil {
		reg := c.compileExpr(s.Value)
		c.emit(vmregister.CreateABC(vmregister.OP_RETURN, uint8(reg), 2, 0))
		c.allocator.Free(reg)
	} else {
		c.emit(vmregister.CreateABC(vmregister.OP_RETURN, 0, 1, 0))
	}
}

// compileIfStmt compiles an if statement
func (c *Compiler) compileIfStmt(s *parser.IfStmt) {
	condReg := c.compileExpr(s.Condition)

	// TEST condReg 0 - skip next if false
	c.emit(vmregister.CreateABC(vmregister.OP_TEST, uint8(condReg), 0, 0))
	c.allocator.Free(condReg)

	// Jump over then branch if false
	jumpToElse := c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, 0))

	// Compile then branch
	c.pushScope()
	for _, stmt := range s.Then {
		c.compileStmt(stmt)
	}
	c.popScope()

	if len(s.Else) > 0 {
		// Jump over else branch
		jumpToEnd := c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, 0))

		// Patch jump to else
		c.patchJump(jumpToElse)

		// Compile else branch
		c.pushScope()
		for _, stmt := range s.Else {
			c.compileStmt(stmt)
		}
		c.popScope()

		// Patch jump to end
		c.patchJump(jumpToEnd)
	} else {
		// Patch jump to after if
		c.patchJump(jumpToElse)
	}
}

// compileWhileStmt compiles a while statement
func (c *Compiler) compileWhileStmt(s *parser.WhileStmt) {
	loopStart := len(c.code)

	// Push loop info for break/continue
	c.loopStack = append(c.loopStack, LoopInfo{
		startPC:    loopStart,
		breakJumps: make([]int, 0),
	})

	// Compile condition
	condReg := c.compileExpr(s.Condition)

	// TEST condReg 0 - skip next if false
	c.emit(vmregister.CreateABC(vmregister.OP_TEST, uint8(condReg), 0, 0))
	c.allocator.Free(condReg)

	// Jump out of loop if false
	exitJump := c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, 0))

	// Compile body
	c.pushScope()
	for _, stmt := range s.Body {
		c.compileStmt(stmt)
	}
	c.popScope()

	// Jump back to condition
	offset := loopStart - len(c.code) - 1
	c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, int16(offset)))

	// Patch exit jump
	c.patchJump(exitJump)

	// Patch break jumps
	loopInfo := c.loopStack[len(c.loopStack)-1]
	for _, breakPC := range loopInfo.breakJumps {
		c.patchJumpAt(breakPC)
	}

	// Pop loop info
	c.loopStack = c.loopStack[:len(c.loopStack)-1]
}

// compileForStmt compiles a for statement
func (c *Compiler) compileForStmt(s *parser.ForStmt) {
	c.pushScope()

	// Compile initializer
	if s.Init != nil {
		c.compileStmt(s.Init)
	}

	loopStart := len(c.code)

	// Push loop info
	c.loopStack = append(c.loopStack, LoopInfo{
		startPC:    loopStart,
		breakJumps: make([]int, 0),
	})

	var exitJump int

	// Compile condition
	if s.Condition != nil {
		condReg := c.compileExpr(s.Condition)
		c.emit(vmregister.CreateABC(vmregister.OP_TEST, uint8(condReg), 0, 0))
		c.allocator.Free(condReg)
		exitJump = c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, 0))
	}

	// Compile body
	for _, stmt := range s.Body {
		c.compileStmt(stmt)
	}

	// Compile update expression
	if s.Update != nil {
		updateReg := c.compileExpr(s.Update)
		c.allocator.Free(updateReg)
	}

	// Jump back to condition
	offset := loopStart - len(c.code) - 1
	c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, int16(offset)))

	// Patch exit jump
	if s.Condition != nil {
		c.patchJump(exitJump)
	}

	// Patch break jumps
	loopInfo := c.loopStack[len(c.loopStack)-1]
	for _, breakPC := range loopInfo.breakJumps {
		c.patchJumpAt(breakPC)
	}

	// Pop loop info and scope
	c.loopStack = c.loopStack[:len(c.loopStack)-1]
	c.popScope()
}

// compileForInStmt compiles a for-in loop
func (c *Compiler) compileForInStmt(s *parser.ForInStmt) {
	c.pushScope()

	// Compile iterable (collection)
	iterableReg := c.compileExpr(s.Collection)

	// Allocate iterator register
	iterReg := c.allocator.Alloc()
	c.allocator.Lock(iterReg)

	// Initialize iterator
	c.emit(vmregister.CreateABC(vmregister.OP_ITERINIT, uint8(iterReg), uint8(iterableReg), 0))
	c.allocator.Free(iterableReg)

	// Define loop variable
	varReg := c.defineLocal(s.Variable)

	loopStart := len(c.code)

	// Push loop info
	c.loopStack = append(c.loopStack, LoopInfo{
		startPC:    loopStart,
		breakJumps: make([]int, 0),
	})

	// ITERNEXT - advances iterator, jumps if done
	iterNextPC := c.emit(vmregister.CreateAsBx(vmregister.OP_ITERNEXT, uint8(iterReg), 0))

	// Get current value into loop variable
	// The iterator stores current value at iterReg+2
	c.emit(vmregister.CreateABC(vmregister.OP_MOVE, uint8(varReg), uint8(iterReg+2), 0))

	// Compile body
	for _, stmt := range s.Body {
		c.compileStmt(stmt)
	}

	// Jump back to ITERNEXT
	offset := loopStart - len(c.code) - 1
	c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, int16(offset)))

	// Patch ITERNEXT jump to after loop
	c.patchJumpAt(iterNextPC)

	// Patch break jumps
	loopInfo := c.loopStack[len(c.loopStack)-1]
	for _, breakPC := range loopInfo.breakJumps {
		c.patchJumpAt(breakPC)
	}

	// Pop loop info
	c.loopStack = c.loopStack[:len(c.loopStack)-1]

	// Free iterator register
	c.allocator.Unlock(iterReg)
	c.allocator.Free(iterReg)

	c.popScope()
}

// compileBreakStmt compiles a break statement
func (c *Compiler) compileBreakStmt(s *parser.BreakStmt) {
	if len(c.loopStack) == 0 {
		c.error("break outside of loop")
		return
	}
	// Add jump to be patched later
	jumpPC := c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, 0))
	c.loopStack[len(c.loopStack)-1].breakJumps = append(
		c.loopStack[len(c.loopStack)-1].breakJumps, jumpPC)
}

// compileContinueStmt compiles a continue statement
func (c *Compiler) compileContinueStmt(s *parser.ContinueStmt) {
	if len(c.loopStack) == 0 {
		c.error("continue outside of loop")
		return
	}
	// Jump back to loop start
	loopInfo := c.loopStack[len(c.loopStack)-1]
	offset := loopInfo.startPC - len(c.code) - 1
	c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, int16(offset)))
}

// compileImportStmt compiles an import statement
func (c *Compiler) compileImportStmt(s *parser.ImportStmt) {
	// Add module path as constant
	pathIdx := c.addStringConstant(s.Path)

	// Import module
	moduleReg := c.allocator.Alloc()
	c.emit(vmregister.CreateABx(vmregister.OP_IMPORT, uint8(moduleReg), pathIdx))

	// Store module in global (using alias or last path component)
	name := s.Alias
	if name == "" {
		// Extract last component from path
		name = s.Path
		for i := len(name) - 1; i >= 0; i-- {
			if name[i] == '/' {
				name = name[i+1:]
				break
			}
		}
	}

	globalID := c.getOrAssignGlobalID(name)
	c.emit(vmregister.CreateABx(vmregister.OP_SETGLOBAL, uint8(moduleReg), globalID))
	c.allocator.Free(moduleReg)
}

// compileExportStmt compiles an export statement
func (c *Compiler) compileExportStmt(s *parser.ExportStmt) {
	// ExportStmt has Stmt (the thing being exported), not Value
	// Compile the inner statement and export the name
	if s.Stmt != nil {
		c.compileStmt(s.Stmt)
	}
	// Add export name as constant
	nameIdx := c.addStringConstant(s.Name)
	// Get the global we just defined
	globalID := c.getOrAssignGlobalID(s.Name)
	valueReg := c.allocator.Alloc()
	c.emit(vmregister.CreateABx(vmregister.OP_GETGLOBAL, uint8(valueReg), globalID))
	c.emit(vmregister.CreateABC(vmregister.OP_EXPORT, uint8(nameIdx), uint8(valueReg), 0))
	c.allocator.Free(valueReg)
}

// compileTryStmt compiles a try-catch statement
func (c *Compiler) compileTryStmt(s *parser.TryStmt) {
	// TRY - setup catch address
	tryPC := c.emit(vmregister.CreateAsBx(vmregister.OP_TRY, 0, 0))

	// Compile try block
	c.pushScope()
	for _, stmt := range s.TryBlock {
		c.compileStmt(stmt)
	}
	c.popScope()

	// ENDTRY
	c.emit(vmregister.CreateABC(vmregister.OP_ENDTRY, 0, 0, 0))

	// Jump over catch block
	jumpOverCatch := c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, 0))

	// Patch TRY to point to catch
	c.patchJumpAt(tryPC)

	// Compile catch block
	c.pushScope()
	if s.CatchVar != "" {
		// Define catch variable
		errReg := c.defineLocal(s.CatchVar)
		c.emit(vmregister.CreateABC(vmregister.OP_GETERROR, uint8(errReg), 0, 0))
	}
	for _, stmt := range s.CatchBlock {
		c.compileStmt(stmt)
	}
	c.popScope()

	// Patch jump over catch
	c.patchJump(jumpOverCatch)

	// Compile finally block if present
	if len(s.FinallyBlock) > 0 {
		c.pushScope()
		for _, stmt := range s.FinallyBlock {
			c.compileStmt(stmt)
		}
		c.popScope()
	}
}

// compileThrowStmt compiles a throw statement
func (c *Compiler) compileThrowStmt(s *parser.ThrowStmt) {
	reg := c.compileExpr(s.Value)
	c.emit(vmregister.CreateABC(vmregister.OP_THROW, uint8(reg), 0, 0))
	c.allocator.Free(reg)
}

// compileClassStmt compiles a class statement (stub for now)
func (c *Compiler) compileClassStmt(s *parser.ClassStmt) {
	// TODO: Implement class compilation
	c.error("class statements not yet implemented")
}

// compileMatchStmt compiles a match statement (stub for now)
func (c *Compiler) compileMatchStmt(s *parser.MatchStmt) {
	// TODO: Implement match compilation
	c.error("match statements not yet implemented")
}

// patchJump patches a jump instruction at the given PC to jump to current position
func (c *Compiler) patchJump(pc int) {
	c.patchJumpAt(pc)
}

// patchJumpAt patches a jump instruction at pc to jump to current position
func (c *Compiler) patchJumpAt(pc int) {
	offset := len(c.code) - pc - 1
	instr := c.code[pc]
	op := instr.OpCode()
	a := instr.A()
	c.code[pc] = vmregister.CreateAsBx(op, a, int16(offset))
}

// compileExpr compiles an expression and returns the register containing the result
func (c *Compiler) compileExpr(expr parser.Expr) int {
	switch e := expr.(type) {
	case *parser.Literal:
		return c.compileLiteral(e)
	case *parser.Variable:
		return c.compileVariable(e)
	case *parser.Binary:
		return c.compileBinary(e)
	case *parser.UnaryExpr:
		return c.compileUnaryExpr(e)
	case *parser.LogicalExpr:
		return c.compileLogicalExpr(e)
	case *parser.CallExpr:
		return c.compileCallExpr(e)
	case *parser.ArrayExpr:
		return c.compileArrayExpr(e)
	case *parser.MapExpr:
		return c.compileMapExpr(e)
	case *parser.IndexExpr:
		return c.compileIndexExpr(e)
	case *parser.PropertyExpr:
		return c.compilePropertyExpr(e)
	case *parser.LambdaExpr:
		return c.compileLambdaExpr(e)
	case *parser.Assign:
		return c.compileAssign(e)
	case *parser.AssignmentExpr:
		return c.compileAssignmentExpr(e)
	case *parser.IfExpr:
		return c.compileIfExpr(e)
	case *parser.InterpolationExpr:
		return c.compileInterpolationExpr(e)
	case *parser.BlockExpr:
		return c.compileBlockExpr(e)
	default:
		c.error(fmt.Sprintf("unknown expression type: %T", expr))
		return c.allocator.Alloc()
	}
}

func (c *Compiler) compileLiteral(e *parser.Literal) int {
	reg := c.allocator.Alloc()

	switch v := e.Value.(type) {
	case float64:
		constIdx := c.addNumberConstant(v)
		c.emit(vmregister.CreateABx(vmregister.OP_LOADK, uint8(reg), constIdx))
	case int:
		constIdx := c.addNumberConstant(float64(v))
		c.emit(vmregister.CreateABx(vmregister.OP_LOADK, uint8(reg), constIdx))
	case int64:
		constIdx := c.addNumberConstant(float64(v))
		c.emit(vmregister.CreateABx(vmregister.OP_LOADK, uint8(reg), constIdx))
	case string:
		constIdx := c.addStringConstant(v)
		c.emit(vmregister.CreateABx(vmregister.OP_LOADK, uint8(reg), constIdx))
	case bool:
		var val uint8 = 0
		if v {
			val = 1
		}
		c.emit(vmregister.CreateABC(vmregister.OP_LOADBOOL, uint8(reg), val, 0))
	case nil:
		c.emit(vmregister.CreateABC(vmregister.OP_LOADNIL, uint8(reg), 0, 0))
	default:
		c.error(fmt.Sprintf("unknown literal type: %T", e.Value))
	}

	return reg
}

func (c *Compiler) compileVariable(e *parser.Variable) int {
	localReg := c.resolveLocal(e.Name)
	if localReg >= 0 {
		// Local variable - return the register directly
		return localReg
	}
	// Global variable
	reg := c.allocator.Alloc()
	globalID := c.getOrAssignGlobalID(e.Name)
	c.emit(vmregister.CreateABx(vmregister.OP_GETGLOBAL, uint8(reg), globalID))
	return reg
}

func (c *Compiler) compileBinary(e *parser.Binary) int {
	leftReg := c.compileExpr(e.Left)
	// Check if left was already locked (e.g., it's a parameter or local)
	leftWasLocked := c.allocator.locked[leftReg]
	// Lock left register to prevent it being clobbered during right expression
	c.allocator.Lock(leftReg)
	rightReg := c.compileExpr(e.Right)
	// Only unlock if we locked it ourselves
	if !leftWasLocked {
		c.allocator.Unlock(leftReg)
	}
	resultReg := c.allocator.Alloc()

	var op vmregister.OpCode
	switch e.Operator {
	case "+":
		op = vmregister.OP_ADD
	case "-":
		op = vmregister.OP_SUB
	case "*":
		op = vmregister.OP_MUL
	case "/":
		op = vmregister.OP_DIV
	case "%":
		op = vmregister.OP_MOD
	case "==":
		op = vmregister.OP_EQ
	case "!=":
		op = vmregister.OP_NEQ
	case "<":
		op = vmregister.OP_LT
	case "<=":
		op = vmregister.OP_LE
	case ">":
		op = vmregister.OP_GT
	case ">=":
		op = vmregister.OP_GE
	default:
		c.error(fmt.Sprintf("unknown binary operator: %s", e.Operator))
		return resultReg
	}

	c.emit(vmregister.CreateABC(op, uint8(resultReg), uint8(leftReg), uint8(rightReg)))
	// Only free if they weren't already locked
	if !leftWasLocked {
		c.allocator.Free(leftReg)
	}
	c.allocator.Free(rightReg)
	return resultReg
}

func (c *Compiler) compileUnaryExpr(e *parser.UnaryExpr) int {
	operandReg := c.compileExpr(e.Operand)
	resultReg := c.allocator.Alloc()

	switch e.Operator {
	case "-":
		c.emit(vmregister.CreateABC(vmregister.OP_UNM, uint8(resultReg), uint8(operandReg), 0))
	case "!":
		c.emit(vmregister.CreateABC(vmregister.OP_NOT, uint8(resultReg), uint8(operandReg), 0))
	default:
		c.error(fmt.Sprintf("unknown unary operator: %s", e.Operator))
	}

	c.allocator.Free(operandReg)
	return resultReg
}

func (c *Compiler) compileLogicalExpr(e *parser.LogicalExpr) int {
	leftReg := c.compileExpr(e.Left)
	resultReg := c.allocator.Alloc()

	// Short-circuit evaluation
	c.emit(vmregister.CreateABC(vmregister.OP_MOVE, uint8(resultReg), uint8(leftReg), 0))

	if e.Operator == "&&" {
		// If left is false, skip right
		c.emit(vmregister.CreateABC(vmregister.OP_TEST, uint8(leftReg), 0, 0))
	} else { // "||"
		// If left is true, skip right
		c.emit(vmregister.CreateABC(vmregister.OP_TEST, uint8(leftReg), 0, 1))
	}

	jumpPC := c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, 0))

	c.allocator.Free(leftReg)

	// Compile right side
	rightReg := c.compileExpr(e.Right)
	c.emit(vmregister.CreateABC(vmregister.OP_MOVE, uint8(resultReg), uint8(rightReg), 0))
	c.allocator.Free(rightReg)

	// Patch jump
	c.patchJump(jumpPC)

	return resultReg
}

func (c *Compiler) compileCallExpr(e *parser.CallExpr) int {
	// Compile arguments FIRST into temporary registers
	// This avoids conflicts between argument computation and call slots
	argRegs := make([]int, len(e.Args))
	for i, arg := range e.Args {
		argRegs[i] = c.compileExpr(arg)
		// Lock each argument register to prevent conflicts
		c.allocator.Lock(argRegs[i])
	}

	// Now compile the callee
	calleeReg := c.compileExpr(e.Callee)

	// Find consecutive slots for the call: callee + args
	numSlots := 1 + len(e.Args)
	baseReg := c.findConsecutiveRegisters(numSlots)

	// Move callee to baseReg if needed
	if calleeReg != baseReg {
		c.emit(vmregister.CreateABC(vmregister.OP_MOVE, uint8(baseReg), uint8(calleeReg), 0))
		c.allocator.Free(calleeReg)
	}

	// Move arguments to their slots
	for i, argReg := range argRegs {
		targetReg := baseReg + 1 + i
		c.allocator.Unlock(argReg)
		if argReg != targetReg {
			c.emit(vmregister.CreateABC(vmregister.OP_MOVE, uint8(targetReg), uint8(argReg), 0))
			c.allocator.Free(argReg)
		}
	}

	// CALL baseReg numArgs+1 wantResults+1
	c.emit(vmregister.CreateABC(vmregister.OP_CALL, uint8(baseReg), uint8(len(e.Args)+1), 2))

	// Result is in baseReg
	return baseReg
}

func (c *Compiler) compileArrayExpr(e *parser.ArrayExpr) int {
	reg := c.allocator.Alloc()
	c.emit(vmregister.CreateABC(vmregister.OP_NEWARRAY, uint8(reg), uint8(len(e.Elements)), 0))

	for _, elem := range e.Elements {
		elemReg := c.compileExpr(elem)
		c.emit(vmregister.CreateABC(vmregister.OP_APPEND, uint8(reg), uint8(elemReg), 0))
		c.allocator.Free(elemReg)
	}

	return reg
}

func (c *Compiler) compileMapExpr(e *parser.MapExpr) int {
	reg := c.allocator.Alloc()
	c.emit(vmregister.CreateABC(vmregister.OP_NEWTABLE, uint8(reg), 0, uint8(len(e.Keys))))

	for i := range e.Keys {
		keyReg := c.compileExpr(e.Keys[i])
		valueReg := c.compileExpr(e.Values[i])
		c.emit(vmregister.CreateABC(vmregister.OP_SETTABLE, uint8(reg), uint8(keyReg), uint8(valueReg)))
		c.allocator.Free(keyReg)
		c.allocator.Free(valueReg)
	}

	return reg
}

func (c *Compiler) compileIndexExpr(e *parser.IndexExpr) int {
	objReg := c.compileExpr(e.Object)
	indexReg := c.compileExpr(e.Index)
	resultReg := c.allocator.Alloc()

	c.emit(vmregister.CreateABC(vmregister.OP_GETTABLE, uint8(resultReg), uint8(objReg), uint8(indexReg)))

	c.allocator.Free(objReg)
	c.allocator.Free(indexReg)
	return resultReg
}

func (c *Compiler) compilePropertyExpr(e *parser.PropertyExpr) int {
	objReg := c.compileExpr(e.Object)
	resultReg := c.allocator.Alloc()

	// Use constant key
	keyIdx := c.addStringConstant(e.Property)
	c.emit(vmregister.CreateABC(vmregister.OP_GETTABLEK, uint8(resultReg), uint8(objReg), uint8(keyIdx)))

	c.allocator.Free(objReg)
	return resultReg
}

func (c *Compiler) compileLambdaExpr(e *parser.LambdaExpr) int {
	// Save current compilation state
	parentCode := c.code
	parentConsts := c.constants
	parentAllocator := c.allocator

	// Create new compilation state for lambda
	c.code = make([]vmregister.Instruction, 0)
	c.constants = make([]vmregister.Value, 0)
	c.allocator = NewRegisterAllocator()

	// Create scope for lambda
	c.pushScope()

	// Define parameters as locals
	for _, param := range e.Params {
		c.defineLocal(param)
	}

	// Compile lambda body (expression)
	if e.Body != nil {
		reg := c.compileExpr(e.Body)
		c.emit(vmregister.CreateABC(vmregister.OP_RETURN, uint8(reg), 2, 0))
	} else {
		c.emit(vmregister.CreateABC(vmregister.OP_RETURN, 0, 1, 0))
	}

	// Create function object
	fn := &vmregister.FunctionObj{
		Object:    vmregister.Object{Type: vmregister.OBJ_FUNCTION},
		Name:      "<lambda>",
		Arity:     len(e.Params),
		Code:      c.code,
		Constants: c.constants,
	}

	// Pop lambda scope
	c.popScope()

	// Restore parent compilation state
	c.code = parentCode
	c.constants = parentConsts
	c.allocator = parentAllocator

	// Add function to constants and create closure
	fnIdx := c.addConstant(vmregister.BoxFunction(fn))
	reg := c.allocator.Alloc()
	c.emit(vmregister.CreateABx(vmregister.OP_CLOSURE, uint8(reg), fnIdx))

	return reg
}

func (c *Compiler) compileAssign(e *parser.Assign) int {
	valueReg := c.compileExpr(e.Value)

	localReg := c.resolveLocal(e.Name)
	if localReg >= 0 {
		// Local variable
		if valueReg != localReg {
			c.emit(vmregister.CreateABC(vmregister.OP_MOVE, uint8(localReg), uint8(valueReg), 0))
		}
		return localReg
	}

	// Global variable
	globalID := c.getOrAssignGlobalID(e.Name)
	c.emit(vmregister.CreateABx(vmregister.OP_SETGLOBAL, uint8(valueReg), globalID))
	return valueReg
}

func (c *Compiler) compileAssignmentExpr(e *parser.AssignmentExpr) int {
	valueReg := c.compileExpr(e.Value)

	localReg := c.resolveLocal(e.Name)
	if localReg >= 0 {
		// Local variable
		if valueReg != localReg {
			c.emit(vmregister.CreateABC(vmregister.OP_MOVE, uint8(localReg), uint8(valueReg), 0))
		}
		return localReg
	}

	// Global variable
	globalID := c.getOrAssignGlobalID(e.Name)
	c.emit(vmregister.CreateABx(vmregister.OP_SETGLOBAL, uint8(valueReg), globalID))
	return valueReg
}

func (c *Compiler) compileIfExpr(e *parser.IfExpr) int {
	resultReg := c.allocator.Alloc()

	condReg := c.compileExpr(e.Cond)
	c.emit(vmregister.CreateABC(vmregister.OP_TEST, uint8(condReg), 0, 0))
	c.allocator.Free(condReg)

	jumpToElse := c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, 0))

	// Then branch
	thenReg := c.compileExpr(e.ThenBranch)
	c.emit(vmregister.CreateABC(vmregister.OP_MOVE, uint8(resultReg), uint8(thenReg), 0))
	c.allocator.Free(thenReg)

	jumpToEnd := c.emit(vmregister.CreateAsBx(vmregister.OP_JMP, 0, 0))

	c.patchJump(jumpToElse)

	// Else branch
	if e.ElseBranch != nil {
		elseReg := c.compileExpr(e.ElseBranch)
		c.emit(vmregister.CreateABC(vmregister.OP_MOVE, uint8(resultReg), uint8(elseReg), 0))
		c.allocator.Free(elseReg)
	} else {
		c.emit(vmregister.CreateABC(vmregister.OP_LOADNIL, uint8(resultReg), 0, 0))
	}

	c.patchJump(jumpToEnd)

	return resultReg
}

func (c *Compiler) compileInterpolationExpr(e *parser.InterpolationExpr) int {
	if len(e.Parts) == 0 {
		reg := c.allocator.Alloc()
		constIdx := c.addStringConstant("")
		c.emit(vmregister.CreateABx(vmregister.OP_LOADK, uint8(reg), constIdx))
		return reg
	}

	// Compile first part
	resultReg := c.compileExpr(e.Parts[0])

	// Concatenate remaining parts
	for i := 1; i < len(e.Parts); i++ {
		partReg := c.compileExpr(e.Parts[i])
		tempReg := c.allocator.Alloc()
		c.emit(vmregister.CreateABC(vmregister.OP_CONCAT, uint8(tempReg), uint8(resultReg), uint8(partReg)))
		c.allocator.Free(resultReg)
		c.allocator.Free(partReg)
		resultReg = tempReg
	}

	return resultReg
}

func (c *Compiler) compileBlockExpr(e *parser.BlockExpr) int {
	c.pushScope()
	var lastReg int
	for _, stmt := range e.Stmts {
		c.compileStmt(stmt)
	}
	// Block expressions should return last value, but we don't track that well
	// For now return nil
	lastReg = c.allocator.Alloc()
	c.emit(vmregister.CreateABC(vmregister.OP_LOADNIL, uint8(lastReg), 0, 0))
	c.popScope()
	return lastReg
}
