package vm

import (
	"sentra/internal/bytecode"
	"sentra/internal/compiler"
)

type CallFrame struct {
	ip       int
	slotBase int
	chunk    *bytecode.Chunk
}

type VM struct {
	chunk      *bytecode.Chunk
	ip         int
	stack      []interface{}
	globals    map[string]interface{}
	frames     []CallFrame
	frameCount int
}

func NewVM(chunk *bytecode.Chunk) *VM {
	initialFrame := CallFrame{
		ip:       0,
		slotBase: 0,
		chunk:    chunk,
	}
	return &VM{
		chunk:   chunk,
		stack:   []interface{}{},
		globals: make(map[string]interface{}),
		frames:  []CallFrame{initialFrame},
	}
}

func (vm *VM) ResetWithChunk(chunk *bytecode.Chunk) {
	vm.chunk = chunk
	vm.frames = []CallFrame{
		{ip: 0, slotBase: 0, chunk: chunk},
	}
}

func (vm *VM) push(val interface{}) {
	vm.stack = append(vm.stack, val)
}

func (vm *VM) pop() interface{} {
	if len(vm.stack) == 0 {
		panic("Stack underflow: attempted to pop from an empty stack")
	}
	val := vm.stack[len(vm.stack)-1]
	vm.stack = vm.stack[:len(vm.stack)-1]
	return val
}

func (vm *VM) peek() interface{} {
	return vm.stack[len(vm.stack)-1]
}

func (vm *VM) readShort() int {
	frame := vm.currentFrame()
	high := int(frame.chunk.Code[frame.ip])
	low := int(frame.chunk.Code[frame.ip+1])
	frame.ip += 2
	return (high << 8) | low
}

func (vm *VM) readByte() byte {
	frame := vm.currentFrame()
	b := frame.chunk.Code[frame.ip]
	frame.ip++
	return b
}

func (vm *VM) currentFrame() *CallFrame {
	return &vm.frames[len(vm.frames)-1]
}

func (vm *VM) Run() interface{} {
	for {
		frame := vm.currentFrame()
		op := bytecode.OpCode(frame.chunk.Code[frame.ip])
		frame.ip++

		switch op {
		case bytecode.OpConstant:
			constIndex := vm.readByte()
			val := frame.chunk.Constants[constIndex]
			vm.push(val)

		case bytecode.OpAdd:
			b := vm.pop()
			a := vm.pop()
			switch a := a.(type) {
			case float64:
				vm.push(a + b.(float64))
			case string:
				vm.push(a + b.(string))
			default:
				panic("unsupported types for OpAdd")
			}

		case bytecode.OpSub:
			b := vm.pop().(float64)
			a := vm.pop().(float64)
			vm.push(a - b)

		case bytecode.OpMul:
			b := vm.pop().(float64)
			a := vm.pop().(float64)
			vm.push(a * b)

		case bytecode.OpDiv:
			b := vm.pop().(float64)
			a := vm.pop().(float64)
			vm.push(a / b)

		case bytecode.OpMod:
			b := vm.pop().(float64)
			a := vm.pop().(float64)
			vm.push(float64(int(a) % int(b)))

		case bytecode.OpNegate:
			a := vm.pop().(float64)
			vm.push(-a)

		case bytecode.OpEqual:
			b := vm.pop()
			a := vm.pop()
			vm.push(a == b)

		case bytecode.OpNotEqual:
			b := vm.pop()
			a := vm.pop()
			vm.push(a != b)

		case bytecode.OpGreater:
			b := vm.pop().(float64)
			a := vm.pop().(float64)
			vm.push(a > b)

		case bytecode.OpLess:
			b := vm.pop().(float64)
			a := vm.pop().(float64)
			vm.push(a < b)

		case bytecode.OpGreaterEqual:
			b := vm.pop().(float64)
			a := vm.pop().(float64)
			vm.push(a >= b)

		case bytecode.OpLessEqual:
			b := vm.pop().(float64)
			a := vm.pop().(float64)
			vm.push(a <= b)

		case bytecode.OpGetLocal:
			slot := int(vm.readByte())
			base := frame.slotBase
			vm.push(vm.stack[base+slot])

		case bytecode.OpSetLocal:
			slot := int(vm.readByte())
			base := frame.slotBase
			// Expand stack for new locals if necessary
			if base+slot >= len(vm.stack) {
				for len(vm.stack) <= base+slot {
					vm.stack = append(vm.stack, nil)
				}
			}
			vm.stack[base+slot] = vm.peek()

		case bytecode.OpDefineGlobal:
			nameIndex := vm.readByte()
			name := frame.chunk.Constants[nameIndex].(string)
			vm.globals[name] = vm.pop()

		case bytecode.OpGetGlobal:
			nameIndex := vm.readByte()
			name := frame.chunk.Constants[nameIndex].(string)
			val, ok := vm.globals[name]
			if !ok {
				panic("undefined variable: " + name)
			}
			vm.push(val)

		case bytecode.OpSetGlobal:
			nameIndex := vm.readByte()
			name := frame.chunk.Constants[nameIndex].(string)
			vm.globals[name] = vm.peek()

		case bytecode.OpCall:
			argCount := int(vm.readByte())
			// Check if we actually have a function
			if len(vm.stack) <= 0 {
				panic("Attempt to call a non-function value")
			}

			callee, ok := vm.pop().(*compiler.Function)
			if !ok {
				panic("Can only call functions")
			}

			// Ensure we have enough args on the stack
			if len(vm.stack) < argCount {
				panic("Not enough arguments for function call")
			}

			// Calculate where the args start on the stack
			newSlotBase := len(vm.stack) - argCount

			// Create a new frame
			newFrame := CallFrame{
				ip:       0,
				slotBase: newSlotBase,
				chunk:    callee.Chunk,
			}

			vm.frames = append(vm.frames, newFrame)
			vm.frameCount++

		case bytecode.OpJump:
			offset := vm.readShort()
			frame.ip += offset

		case bytecode.OpJumpIfFalse:
			offset := vm.readShort()
			cond := vm.pop()
			if cond == false || cond == nil {
				frame.ip += offset
			}

		case bytecode.OpLoop:
			offset := vm.readShort()
			frame.ip -= offset

		case bytecode.OpNil:
			vm.push(nil)

		case bytecode.OpPop:
			_ = vm.pop()

		case bytecode.OpDup:
			vm.push(vm.peek())

		case bytecode.OpPrint:
			PrintValue(vm.pop())

		case bytecode.OpReturn:
			// Get the return value (or nil if nothing on stack)
			var returnValue interface{} = nil

			if len(vm.stack) > frame.slotBase {
				returnValue = vm.pop()
			}

			// Get current frame's slot base to know where to pop to
			currentBase := frame.slotBase

			// Clean up the stack - pop everything after the current frame's base
			vm.stack = vm.stack[:currentBase]

			// Pop the current frame
			vm.frames = vm.frames[:len(vm.frames)-1]

			// If this was the last frame, exit
			if len(vm.frames) == 0 {
				return returnValue
			}

			// Push the return value for the caller
			vm.push(returnValue)
		}
	}
}
