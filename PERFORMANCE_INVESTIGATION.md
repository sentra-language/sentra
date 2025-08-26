# Sentra VM Performance Investigation - Deep Dive

## Profiling Results Analysis

### CPU Hotspots Identified

| Function | % CPU | Issue | Impact |
|----------|-------|--------|--------|
| `runtime.mapaccess2_faststr` | 14.29% | **Builtin function lookups via globalMap** | Critical |
| `EnhancedVM.readByte` | 14.29% | **Per-instruction bytecode fetching** | Critical |
| `runtime.mallocgcTiny` | 9.52% | **Memory allocation pressure** | High |
| `EnhancedVM.Run` | 85.71% | Main execution loop (cumulative) | - |

## Critical Performance Issues

### 1. Builtin Function Resolution (14.29% CPU)

**Problem**: Every builtin function call requires a map lookup:
```go
// Line 1253 in performCall()
if idx, ok := vm.globalMap[methodName]; ok {
```

**Impact**: 
- Map lookups for `log()`, `push()`, `len()`, `time()`, etc.
- String hashing + map traversal for every function call
- No caching of frequently used functions

**Solution**: Pre-resolve builtin function pointers

### 2. Instruction Fetching (14.29% CPU)

**Problem**: Per-instruction byte reading with bounds checking:
```go
// Line 210-215: readByte()
func (vm *EnhancedVM) readByte() byte {
    frame := &vm.frames[vm.frameCount-1]  // Frame deref every instruction
    b := frame.chunk.Code[frame.ip]       // Bounds check every instruction  
    frame.ip++
    return b
}
```

**Impact**: 
- Frame dereferencing on every instruction
- Array bounds checking on every instruction
- Function call overhead for byte reading

**Solution**: Inline instruction reading + batch bounds checks

### 3. Memory Allocation (9.52% CPU)

**Problem**: Continuous small allocations during execution
- Argument arrays for function calls
- String concatenation
- Value boxing/unboxing

**Solution**: Object pooling + pre-allocation

## Optimization Strategy

### Phase 1: Function Resolution Cache (Expected: 10-15% improvement)

Create a direct function pointer cache to eliminate map lookups:

```go
type OptimizedVM struct {
    *EnhancedVM
    builtinCache map[string]*NativeFunction // Pre-resolved pointers
    hotFunctions []*NativeFunction         // Most common builtins
}
```

### Phase 2: Inline Instruction Reading (Expected: 8-12% improvement)

Replace `readByte()` calls with inline code:

```go
// Instead of: constIndex := vm.readByte()
// Use: 
constIndex := frame.chunk.Code[frame.ip]
frame.ip++
```

### Phase 3: Type-Specialized Operations (Expected: 15-20% improvement)

Based on our benchmark, arithmetic operations dominate. Create fast paths:

```go
// Instead of generic ToNumber() conversion every time
// Use type-specific operations detected at runtime
switch a := a.(type) {
case int:
    if b, ok := b.(int); ok {
        return a + b  // Direct int addition
    }
}
```

### Phase 4: Memory Pool (Expected: 5-8% improvement)

Reduce allocation pressure with object pools for common operations.

## Implementation Priority

1. **Function Resolution Cache** (Highest ROI)
2. **Inline Instruction Reading** (Easy win)  
3. **Type Specialization** (Biggest potential)
4. **Memory Pooling** (Long-term benefit)

## Expected Combined Impact

- **Conservative**: 25-30% total improvement
- **Optimistic**: 40-50% total improvement
- **Current FastVM**: 11-20% improvement
- **Total Potential**: 50-70% improvement over baseline

This would bring Sentra VM performance much closer to Python levels while maintaining the unique stack-tree architecture and security capabilities.

## Next Steps

Implement the function resolution cache first, as it has the highest immediate impact with relatively low implementation complexity.