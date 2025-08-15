// internal/debugger/vm_hook.go
package debugger

import (
	"sentra/internal/bytecode"
	"sentra/internal/vm"
)

// VMDebugHook implements the DebugHook interface for the VM
type VMDebugHook struct {
	debugger *Debugger
	stepping bool
	stepMode DebugState
}

// NewVMDebugHook creates a new VM debug hook
func NewVMDebugHook(debugger *Debugger) *VMDebugHook {
	return &VMDebugHook{
		debugger: debugger,
		stepping: false,
		stepMode: Running,
	}
}

// OnInstruction is called before each VM instruction
func (h *VMDebugHook) OnInstruction(vm *vm.EnhancedVM, ip int, debug bytecode.DebugInfo) bool {
	// Update call stack for debugger
	h.updateCallStack(vm)
	
	// Check for breakpoints
	if h.debugger.CheckBreakpoint(debug.File, debug.Line) {
		h.debugger.ShowCurrentLocation(debug.File, debug.Line)
		h.debugger.RunDebugger()
		return h.debugger.GetState() == Running
	}
	
	// Handle step execution
	switch h.debugger.GetState() {
	case StepInto:
		h.debugger.ShowCurrentLocation(debug.File, debug.Line)
		h.debugger.SetState(Paused)
		h.debugger.RunDebugger()
		return h.debugger.GetState() == Running
		
	case StepOver:
		// Step over - don't break on function calls at deeper levels
		if h.shouldStepOver(vm) {
			h.debugger.ShowCurrentLocation(debug.File, debug.Line)
			h.debugger.SetState(Paused)
			h.debugger.RunDebugger()
		}
		return h.debugger.GetState() == Running
		
	case StepOut:
		// Step out - break when we return to a shallower call level
		if h.shouldStepOut(vm) {
			h.debugger.ShowCurrentLocation(debug.File, debug.Line)
			h.debugger.SetState(Paused)
			h.debugger.RunDebugger()
		}
		return h.debugger.GetState() == Running
		
	case Paused:
		// Paused - don't continue until debugger says so
		return false
		
	case Terminated:
		return false
		
	default:
		return true
	}
}

// OnCall is called when entering a function
func (h *VMDebugHook) OnCall(vm *vm.EnhancedVM, function string, debug bytecode.DebugInfo) {
	// Update call stack
	h.updateCallStack(vm)
}

// OnReturn is called when returning from a function
func (h *VMDebugHook) OnReturn(vm *vm.EnhancedVM, debug bytecode.DebugInfo) {
	// Update call stack
	h.updateCallStack(vm)
}

// OnError is called when an error occurs
func (h *VMDebugHook) OnError(vm *vm.EnhancedVM, err error, debug bytecode.DebugInfo) {
	h.debugger.ShowCurrentLocation(debug.File, debug.Line)
	// Don't automatically enter debugger on error - let the error handler deal with it
}

// updateCallStack updates the debugger's call stack from the VM
func (h *VMDebugHook) updateCallStack(vm *vm.EnhancedVM) {
	vmStack := vm.GetCallStack()
	h.debugger.callStack = make([]StackFrame, 0, len(vmStack))
	
	for _, frame := range vmStack {
		debugFrame := StackFrame{
			Function: frame["function"].(string),
			File:     frame["file"].(string),
			Line:     frame["line"].(int),
			IP:       frame["ip"].(int),
		}
		h.debugger.callStack = append(h.debugger.callStack, debugFrame)
	}
}

// shouldStepOver determines if we should break for step-over
func (h *VMDebugHook) shouldStepOver(vm *vm.EnhancedVM) bool {
	// For now, always break on step over (simplified implementation)
	// In a full implementation, we'd track call depth
	return true
}

// shouldStepOut determines if we should break for step-out
func (h *VMDebugHook) shouldStepOut(vm *vm.EnhancedVM) bool {
	// For now, always break on step out (simplified implementation)
	// In a full implementation, we'd track call depth
	return true
}