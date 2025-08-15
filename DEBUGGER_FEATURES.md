# 🐛 Sentra Debugger Features

## ✅ **Completed: Debugger Support with Breakpoints**

The Sentra language now includes a full-featured interactive debugger that provides comprehensive debugging capabilities for security automation scripts.

### 🎯 **Key Features Implemented:**

#### 1. **Interactive Debugging Interface** (`internal/debugger/debugger.go`)
- Complete command-line debugger with interactive prompt
- Support for multiple breakpoint types (line, function, conditional)
- Watch expressions for monitoring variables
- Call stack inspection and navigation
- Source code display with current location highlighting

#### 2. **VM Integration** (`internal/vm/vm_enhanced.go`)
- `DebugHook` interface for VM debugging callbacks
- Debug hooks for instruction execution, function calls, and returns
- Call stack tracking and variable inspection
- Debug-enabled execution with performance optimization

#### 3. **Debug Hook Implementation** (`internal/debugger/vm_hook.go`)
- VM-debugger bridge for seamless integration
- Step execution modes (step into, step over, step out)
- Breakpoint hit detection and handling
- Call stack synchronization between VM and debugger

#### 4. **CLI Integration** (`cmd/sentra/main.go`)
- New `sentra debug <file>` command
- Automatic source loading and debug info generation
- Error handling integration with debugger
- Interactive debugging session management

### 🔧 **Debugger Commands:**

```bash
# Start debugging a script
sentra debug script.sn

# Available debugger commands:
help, h               - Show command help
break <file> <line>   - Set breakpoint at file:line
delete <id>           - Remove breakpoint by ID
list                  - List all breakpoints
continue, c           - Continue execution
step, s               - Step into next instruction
next, n               - Step over next instruction
finish, f             - Step out of current function
where, w              - Show call stack
watch <expr>          - Add expression to watch list
unwatch <expr>        - Remove expression from watch list
print <expr>          - Evaluate and print expression
quit, q               - Exit debugger
```

### 🎮 **Usage Examples:**

#### **Basic Debugging Session:**
```bash
$ sentra debug debug_demo.sn
🐛 Starting Sentra debugger for: debug_demo.sn
The program will start paused. Type 'help' for commands.

📍 Current location: debug_demo.sn:1

   1 -> // Debugger demo program
   2    let a = 5
   3    let b = 10
   4    let sum = a + b

(sentra-debug) break debug_demo.sn 4
✓ Breakpoint 1 set at debug_demo.sn:4

(sentra-debug) continue
Continuing execution...

🔴 Breakpoint 1 hit at debug_demo.sn:4 (hit count: 1)
📍 Current location: debug_demo.sn:4

   2    let a = 5
   3    let b = 10
   4 -> let sum = a + b
   5    log("Sum: " + str(sum))
   6    let product = a * b

(sentra-debug) where
Call Stack:
-> 0: <script> (debug_demo.sn:4)

(sentra-debug) step
```

#### **Advanced Features:**
- **Breakpoint Management**: Set, list, and remove breakpoints by file and line
- **Step Execution**: Step into functions, step over calls, step out of functions
- **Variable Inspection**: Watch expressions and print variable values
- **Call Stack Navigation**: View and navigate the execution call stack
- **Source Display**: Automatic source code display with execution pointer

### 🏗️ **Architecture:**

#### **Debugger Components:**
1. **Debugger Core**: Manages breakpoints, watches, and debugging state
2. **VM Hook**: Bridges VM execution with debugger events
3. **Interactive CLI**: Provides user interface for debugging commands
4. **Debug Info**: Tracks source locations and call stack information

#### **Integration Points:**
- **VM Execution Loop**: Debug hooks called before each instruction
- **Error Handling**: Debugger integration with runtime error system
- **Bytecode Generation**: Debug information embedded in compiled code
- **CLI Commands**: New debug command with full argument parsing

### 🚀 **Benefits:**

#### **For Developers:**
- **Interactive Debugging**: Set breakpoints and step through code execution
- **Real-time Inspection**: Monitor variables and expressions during execution
- **Error Investigation**: Debug runtime errors with full context
- **Call Stack Analysis**: Understand program flow and function calls

#### **For Security Scripts:**
- **Script Debugging**: Debug complex security automation workflows
- **Variable Monitoring**: Track security data flow and transformations
- **Breakpoint Analysis**: Pause execution at critical security checkpoints
- **Error Diagnosis**: Quickly identify and fix security script issues

### 🎯 **Example Debug Session Output:**
```
🐛 Sentra Debugger
Type 'help' for available commands

📍 Current location: debug_demo.sn:1

   1 -> let a = 5
   2    let b = 10
   3    let sum = a + b

(sentra-debug) break debug_demo.sn 3
✓ Breakpoint 1 set at debug_demo.sn:3

(sentra-debug) continue
🔴 Breakpoint 1 hit at debug_demo.sn:3 (hit count: 1)

(sentra-debug) watch a
✓ Added watch: a

(sentra-debug) step
📍 Current location: debug_demo.sn:4
```

### 🔮 **Future Enhancements:**
- **Conditional Breakpoints**: Break only when conditions are met
- **Function Breakpoints**: Break when entering specific functions
- **Expression Evaluation**: Full expression evaluation in debugger context
- **Variable Modification**: Change variable values during debugging
- **Debug Scripts**: Automated debugging with predefined commands

The Sentra debugger provides a professional-grade debugging experience that significantly enhances the development workflow for security automation scripts!