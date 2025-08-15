// internal/debugger/debugger.go
package debugger

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sentra/internal/vm"
)

// BreakpointType represents different types of breakpoints
type BreakpointType int

const (
	LineBreakpoint BreakpointType = iota
	FunctionBreakpoint
	ConditionalBreakpoint
)

// Breakpoint represents a debug breakpoint
type Breakpoint struct {
	ID        int
	Type      BreakpointType
	File      string
	Line      int
	Function  string
	Condition string
	Enabled   bool
	HitCount  int
}

// DebugState represents the current debugging state
type DebugState int

const (
	Running DebugState = iota
	Paused
	StepInto
	StepOver
	StepOut
	Terminated
)

// Debugger provides interactive debugging capabilities
type Debugger struct {
	vm           *vm.EnhancedVM
	breakpoints  map[int]*Breakpoint
	nextBpID     int
	state        DebugState
	currentFrame int
	stepTarget   int
	reader       *bufio.Reader
	sourceLines  map[string][]string
	watches      map[string]string
	callStack    []StackFrame
}

// StackFrame represents a frame in the call stack for debugging
type StackFrame struct {
	Function string
	File     string
	Line     int
	IP       int
}

// NewDebugger creates a new debugger instance
func NewDebugger(vm *vm.EnhancedVM) *Debugger {
	return &Debugger{
		vm:          vm,
		breakpoints: make(map[int]*Breakpoint),
		nextBpID:    1,
		state:       Paused,
		reader:      bufio.NewReader(os.Stdin),
		sourceLines: make(map[string][]string),
		watches:     make(map[string]string),
		callStack:   make([]StackFrame, 0),
	}
}

// LoadSourceFile loads source code for debugging
func (d *Debugger) LoadSourceFile(filename, content string) {
	d.sourceLines[filename] = strings.Split(content, "\n")
}

// AddBreakpoint adds a new breakpoint
func (d *Debugger) AddBreakpoint(file string, line int) int {
	bp := &Breakpoint{
		ID:       d.nextBpID,
		Type:     LineBreakpoint,
		File:     file,
		Line:     line,
		Enabled:  true,
		HitCount: 0,
	}
	d.breakpoints[d.nextBpID] = bp
	d.nextBpID++
	fmt.Printf("✓ Breakpoint %d set at %s:%d\n", bp.ID, file, line)
	return bp.ID
}

// RemoveBreakpoint removes a breakpoint by ID
func (d *Debugger) RemoveBreakpoint(id int) bool {
	if bp, exists := d.breakpoints[id]; exists {
		delete(d.breakpoints, id)
		fmt.Printf("✓ Breakpoint %d removed from %s:%d\n", bp.ID, bp.File, bp.Line)
		return true
	}
	fmt.Printf("✗ Breakpoint %d not found\n", id)
	return false
}

// ListBreakpoints shows all current breakpoints
func (d *Debugger) ListBreakpoints() {
	if len(d.breakpoints) == 0 {
		fmt.Println("No breakpoints set")
		return
	}
	
	fmt.Println("Breakpoints:")
	for _, bp := range d.breakpoints {
		status := "enabled"
		if !bp.Enabled {
			status = "disabled"
		}
		fmt.Printf("  %d: %s:%d (%s) hits: %d\n", 
			bp.ID, bp.File, bp.Line, status, bp.HitCount)
	}
}

// CheckBreakpoint checks if execution should break at current location
func (d *Debugger) CheckBreakpoint(file string, line int) bool {
	for _, bp := range d.breakpoints {
		if bp.Enabled && bp.File == file && bp.Line == line {
			bp.HitCount++
			fmt.Printf("\n🔴 Breakpoint %d hit at %s:%d (hit count: %d)\n", 
				bp.ID, file, line, bp.HitCount)
			d.state = Paused
			return true
		}
	}
	return false
}

// ShowCurrentLocation displays the current execution location
func (d *Debugger) ShowCurrentLocation(file string, line int) {
	fmt.Printf("\n📍 Current location: %s:%d\n", file, line)
	
	if lines, exists := d.sourceLines[file]; exists {
		start := max(0, line-3)
		end := min(len(lines), line+2)
		
		for i := start; i < end; i++ {
			marker := "   "
			if i+1 == line {
				marker = "-> "
			}
			fmt.Printf("%s%4d | %s\n", marker, i+1, lines[i])
		}
	}
}

// AddWatch adds a variable to watch list
func (d *Debugger) AddWatch(expression string) {
	d.watches[expression] = ""
	fmt.Printf("✓ Added watch: %s\n", expression)
}

// RemoveWatch removes a variable from watch list
func (d *Debugger) RemoveWatch(expression string) {
	if _, exists := d.watches[expression]; exists {
		delete(d.watches, expression)
		fmt.Printf("✓ Removed watch: %s\n", expression)
	} else {
		fmt.Printf("✗ Watch not found: %s\n", expression)
	}
}

// ShowWatches displays all watched variables
func (d *Debugger) ShowWatches() {
	if len(d.watches) == 0 {
		fmt.Println("No watches set")
		return
	}
	
	fmt.Println("Watches:")
	for expr := range d.watches {
		// In a full implementation, we'd evaluate the expression
		fmt.Printf("  %s = <not implemented yet>\n", expr)
	}
}

// ShowCallStack displays the current call stack
func (d *Debugger) ShowCallStack() {
	fmt.Println("Call Stack:")
	for i, frame := range d.callStack {
		marker := "   "
		if i == d.currentFrame {
			marker = "-> "
		}
		fmt.Printf("%s%d: %s (%s:%d)\n", 
			marker, i, frame.Function, frame.File, frame.Line)
	}
}

// RunDebugger starts the interactive debugging session
func (d *Debugger) RunDebugger() {
	fmt.Println("🐛 Sentra Debugger")
	fmt.Println("Type 'help' for available commands")
	
	for d.state != Terminated {
		fmt.Print("(sentra-debug) ")
		command, err := d.reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading command: %v\n", err)
			continue
		}
		
		command = strings.TrimSpace(command)
		d.executeCommand(command)
	}
}

// executeCommand processes debugger commands
func (d *Debugger) executeCommand(command string) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return
	}
	
	cmd := parts[0]
	args := parts[1:]
	
	switch cmd {
	case "help", "h":
		d.showHelp()
		
	case "break", "b":
		if len(args) >= 2 {
			line, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Printf("Invalid line number: %s\n", args[1])
				return
			}
			d.AddBreakpoint(args[0], line)
		} else {
			fmt.Println("Usage: break <file> <line>")
		}
		
	case "delete", "d":
		if len(args) >= 1 {
			id, err := strconv.Atoi(args[0])
			if err != nil {
				fmt.Printf("Invalid breakpoint ID: %s\n", args[0])
				return
			}
			d.RemoveBreakpoint(id)
		} else {
			fmt.Println("Usage: delete <breakpoint_id>")
		}
		
	case "list", "l":
		d.ListBreakpoints()
		
	case "continue", "c":
		d.state = Running
		fmt.Println("Continuing execution...")
		
	case "step", "s":
		d.state = StepInto
		fmt.Println("Stepping into...")
		
	case "next", "n":
		d.state = StepOver
		fmt.Println("Stepping over...")
		
	case "finish", "f":
		d.state = StepOut
		fmt.Println("Stepping out...")
		
	case "where", "w":
		d.ShowCallStack()
		
	case "watch":
		if len(args) >= 1 {
			d.AddWatch(strings.Join(args, " "))
		} else {
			d.ShowWatches()
		}
		
	case "unwatch":
		if len(args) >= 1 {
			d.RemoveWatch(strings.Join(args, " "))
		} else {
			fmt.Println("Usage: unwatch <expression>")
		}
		
	case "print", "p":
		if len(args) >= 1 {
			fmt.Printf("print %s = <not implemented yet>\n", strings.Join(args, " "))
		} else {
			fmt.Println("Usage: print <expression>")
		}
		
	case "quit", "q":
		d.state = Terminated
		fmt.Println("Debugging session terminated")
		
	default:
		fmt.Printf("Unknown command: %s (type 'help' for available commands)\n", cmd)
	}
}

// showHelp displays available debugger commands
func (d *Debugger) showHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  help, h               - Show this help")
	fmt.Println("  break <file> <line>   - Set breakpoint at file:line")
	fmt.Println("  delete <id>           - Remove breakpoint by ID")
	fmt.Println("  list                  - List all breakpoints")
	fmt.Println("  continue, c           - Continue execution")
	fmt.Println("  step, s               - Step into next instruction")
	fmt.Println("  next, n               - Step over next instruction")
	fmt.Println("  finish, f             - Step out of current function")
	fmt.Println("  where, w              - Show call stack")
	fmt.Println("  watch <expr>          - Add expression to watch list")
	fmt.Println("  unwatch <expr>        - Remove expression from watch list")
	fmt.Println("  print <expr>          - Evaluate and print expression")
	fmt.Println("  quit, q               - Exit debugger")
}

// GetState returns the current debug state
func (d *Debugger) GetState() DebugState {
	return d.state
}

// SetState sets the debug state
func (d *Debugger) SetState(state DebugState) {
	d.state = state
}

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}