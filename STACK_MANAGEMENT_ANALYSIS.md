# Stack Management: Fixed vs Dynamic Growth

## The Problem

You're absolutely right - unbounded stack growth is dangerous! A badly written or malicious program could consume all available memory and crash the system.

## How Other VMs Handle This

### Fixed Stack Size VMs

**V8 (JavaScript/Node.js)**
```javascript
// Fixed ~1MB stack
function recurse(n) {
    return recurse(n + 1);  // Crashes at ~10,000 calls
}
// Error: Maximum call stack size exceeded
```
- **Stack size**: 1MB fixed
- **Pros**: Predictable memory usage
- **Cons**: Can't handle large workloads

**CPython (Python)**
```python
# Default: 1000 frame limit
import sys
sys.setrecursionlimit(10000)  # Can adjust, but risky!
```
- **Stack size**: 1000 frames (configurable)
- **Pros**: Safe by default
- **Cons**: Arbitrary limit, not based on memory

### Dynamic Stack Growth VMs

**Go Runtime**
```go
// Starts at 2KB, grows to 1GB
func recurse() {
    var arr [1000]int  // Stack grows automatically
    recurse()
}
```
- **Stack size**: 2KB → 1GB (dynamic)
- **Pros**: Efficient memory use, handles large workloads
- **Cons**: Complex implementation

**JVM (Java)**
```java
// Configured per thread: -Xss1m to -Xss10m
public void recurse() {
    recurse();  // StackOverflowError at limit
}
```
- **Stack size**: 1MB default (configurable)
- **Pros**: Tunable per application
- **Cons**: Must know requirements upfront

## Recommended Approach for Sentra VM

### Smart Growth with Hard Limits

```go
const (
    InitialStack = 8192     // Start small: 64KB
    MaxStack     = 524288   // Hard limit: 4MB
    WarnStack    = 262144   // Warning at: 2MB
)
```

### Why This Is Better

1. **Memory Efficient**
   - Small programs use only 64KB
   - Large programs can grow to 4MB
   - Most programs stay under 512KB

2. **Safety Guaranteed**
   - Hard limit prevents memory exhaustion
   - 4MB is enough for 500K+ operations
   - Malicious code can't crash the system

3. **Performance**
   - No allocation for small programs
   - Amortized O(1) push/pop operations
   - Predictable performance

### Implementation Strategy

```go
// Current (Fixed)
if vm.stackTop >= 65536 {
    panic("stack overflow")
}

// Better (Dynamic with Limit)
if vm.stackTop >= len(vm.stack) {
    if len(vm.stack) >= MaxStackSize {
        return errorWithStackTrace("stack overflow")
    }
    vm.growStack()  // Double size up to max
}
```

## Memory Usage Comparison

| Approach | Min Memory | Max Memory | Iterations |
|----------|------------|------------|------------|
| Current Fixed | 512KB | 512KB | ~30K |
| Unlimited Growth | 64KB | ∞ (dangerous!) | ∞ |
| **Smart Growth** | **64KB** | **4MB** | **~500K** |

## Protection Mechanisms

### 1. Hard Upper Limit
```go
if newSize > MaxStackSize {
    return fmt.Errorf("stack overflow: program too complex")
}
```

### 2. Warning System
```go
if stackSize > WarnThreshold {
    log.Warn("Large stack usage detected - consider refactoring")
}
```

### 3. Recovery Options
```go
// Option A: Fail gracefully
defer func() {
    if r := recover(); r != nil {
        if err, ok := r.(StackOverflowError); ok {
            return handleStackOverflow(err)
        }
    }
}()

// Option B: Increase limit for specific operations
vm.WithExpandedStack(func() {
    // Run heavy operation with 2x stack
})
```

## Real-World Requirements

| Use Case | Stack Depth Needed | Our Limit OK? |
|----------|-------------------|---------------|
| Web Request | 100-1,000 | ✅ Yes |
| Template Render | 1,000-10,000 | ✅ Yes |
| Data Processing | 10,000-50,000 | ✅ Yes |
| Large Batch Job | 50,000-200,000 | ✅ Yes (with 4MB) |
| Infinite Recursion | ∞ | ✅ Safely caught |

## Conclusion

**You should implement dynamic growth with a hard limit** because:

1. **Safety**: Hard limit prevents memory exhaustion
2. **Efficiency**: Small programs use minimal memory
3. **Flexibility**: Can handle both small and large workloads
4. **Production-ready**: Matches industry standards (Go, JVM approach)

The key insight: **It's not about preventing all stack overflows** (that's impossible with recursion), but about **preventing memory exhaustion** while supporting legitimate use cases.

### Recommended Implementation
- Start: 8K entries (64KB)
- Grow: 2x each time
- Warn: At 256K entries (2MB) 
- Max: 512K entries (4MB)
- Error: "Stack overflow: exceeds 512K depth"

This gives you 10-20x more capacity than current, while still protecting against runaway memory usage.