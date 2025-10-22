package vmregister

import (
	"fmt"
	"math"
	"strings"
	"unsafe"
)

// NaN-Boxing Value Representation
// ================================
//
// This implementation uses NaN-boxing to store all Sentra values in 64 bits.
// This eliminates heap allocations for primitive types and improves cache locality.
//
// Encoding scheme:
// - Numbers (float64):    [any value where (bits & NaN_MASK) != NaN_MASK]
// - Nil:                  0x7FF8000000000000
// - False:                0x7FF8000000000001
// - True:                 0x7FF8000000000002
// - Small Int (48-bit):   0x7FFE000000000000 | (int48 & 0xFFFFFFFFFFFF)
// - Pointer (48-bit):     0x7FFC000000000000 | (ptr48 & 0xFFFFFFFFFFFF)
//
// Benefits:
// - Zero allocations for numbers, booleans, nil, small integers
// - 8 bytes per value (vs 24+ bytes with interface{})
// - CPU register-friendly
// - Fast type checking (single bit operation)
// - Better cache utilization

type Value uint64

// Global object cache to prevent Go's GC from collecting NaN-boxed pointers
var globalObjectCache = make([]interface{}, 0, 1000)

// Masks and tags for NaN-boxing
const (
	// IEEE 754 NaN mask: all exponent bits set
	NaN_MASK = 0x7FF8000000000000

	// Quiet NaN space for our tags (bits 51-0 available)
	// We use bits 50-48 to distinguish types
	TAG_MASK = 0xFFFF000000000000

	// Specific tags
	TAG_NIL     = 0x7FF8000000000000
	TAG_FALSE   = 0x7FF8000000000001
	TAG_TRUE    = 0x7FF8000000000002

	// Pointer tag: 0x7FFC... (bits 50-49 = 11, bit 48 = 1)
	TAG_PTR     = 0x7FFC000000000000
	PTR_MASK    = 0x0000FFFFFFFFFFFF

	// Small integer tag: 0x7FFE... (bits 50-49 = 11, bit 48 = 1, bit 47 = 1)
	TAG_INT     = 0x7FFE000000000000
	INT_MASK    = 0x0000FFFFFFFFFFFF
	INT_SIGN    = 0x0000800000000000

	// Masks for quick type checks
	NUMBER_MASK = 0x7FF8000000000000
)

// Heap-allocated object types (pointed to by TAG_PTR)
type ObjectType uint8

const (
	OBJ_STRING ObjectType = iota
	OBJ_ARRAY
	OBJ_MAP
	OBJ_FUNCTION
	OBJ_CLOSURE
	OBJ_NATIVE_FN
	OBJ_UPVALUE
	OBJ_MODULE
	OBJ_ERROR
	OBJ_CHANNEL
	OBJ_ITERATOR
	OBJ_CLASS      // Class definition
	OBJ_INSTANCE   // Class instance
	OBJ_FIBER      // Lightweight coroutine
)

// Object header for all heap-allocated objects
type Object struct {
	Type     ObjectType
	Marked   bool // For GC
	Next     *Object // GC linked list
}

// Heap-allocated types
type (
	StringObj struct {
		Object
		Value string
		Hash  uint64
	}

	ArrayObj struct {
		Object
		Elements []Value
		Methods  map[string]Value // Cached method objects (push, pop, etc.)
	}

	MapObj struct {
		Object
		Items map[string]Value
	}

	FunctionObj struct {
		Object
		Name       string
		Arity      int
		Code       []Instruction // Register-based bytecode
		Constants  []Value
		ObjectRefs []interface{} // GC-visible references to keep objects alive
		Upvalues   []UpvalueDesc
		IsVariadic bool
	}

	ClosureObj struct {
		Object
		Function *FunctionObj
		Upvalues []*UpvalueObj
	}

	NativeFnObj struct {
		Object
		Name     string
		Arity    int
		Function func([]Value) (Value, error)
	}

	UpvalueObj struct {
		Object
		Location *Value // Points to stack or closed value
		Closed   Value
	}

	ModuleObj struct {
		Object
		Name    string
		Path    string
		Exports map[string]Value
		Loaded  bool
	}

	ErrorObj struct {
		Object
		Message string
		Stack   []StackFrame
	}

	ChannelObj struct {
		Object
		Ch     chan Value
		Closed bool
	}

	IteratorObj struct {
		Object
		Collection Value
		Index      int
		Keys       []string
	}

	// OOP: Class definition
	ClassObj struct {
		Object
		Name       string
		Methods    map[string]Value // Method name -> Function
		Properties map[string]Value // Class properties (static)
		Parent     *ClassObj        // Inheritance support
		Constructor Value           // Constructor function
	}

	// OOP: Class instance
	InstanceObj struct {
		Object
		Class      *ClassObj
		Fields     map[string]Value // Instance properties
	}

	// Fiber: Lightweight coroutine
	FiberObj struct {
		Object
		State      FiberState
		Registers  [256]Value       // Fiber has its own register set
		RegTop     int
		Frames     [64]CallFrame    // Fiber has its own call stack
		FrameTop   int
		PC         int              // Current program counter
		Function   *FunctionObj     // Current function
		Parent     *FiberObj        // Parent fiber (for nested yields)
		YieldValue Value            // Last yielded value
	}
)

// FiberState represents the execution state of a fiber
type FiberState uint8

const (
	FIBER_NEW FiberState = iota      // Just created
	FIBER_RUNNING                     // Currently executing
	FIBER_SUSPENDED                   // Yielded, can be resumed
	FIBER_DEAD                        // Finished execution
)

// UpvalueDesc describes an upvalue in the function prototype
type UpvalueDesc struct {
	Index   uint8
	IsLocal bool
}

// StackFrame for error traces
type StackFrame struct {
	Function string
	File     string
	Line     int
	Column   int
}

// ============================================================================
// Value Construction (Boxing)
// ============================================================================

// BoxNumber creates a Value from float64
//
//go:inline
func BoxNumber(n float64) Value {
	return Value(math.Float64bits(n))
}

// BoxInt creates a Value from int64
// Uses small int encoding if possible, otherwise converts to float64
func BoxInt(i int64) Value {
	// Check if fits in 48 bits (signed)
	if i >= -(1<<47) && i < (1<<47) {
		if i < 0 {
			// Negative: set sign bit and use two's complement
			return Value(TAG_INT | uint64(i&0xFFFFFFFFFFFF))
		}
		return Value(TAG_INT | uint64(i))
	}
	// Too large: use float64
	return BoxNumber(float64(i))
}

// BoxBool creates a Value from bool
//
//go:inline
func BoxBool(b bool) Value {
	if b {
		return TAG_TRUE
	}
	return TAG_FALSE
}

// NilValue returns the nil Value
//
//go:inline
func NilValue() Value {
	return TAG_NIL
}

// BoxPointer creates a Value from a pointer
func BoxPointer(ptr unsafe.Pointer) Value {
	ptrBits := uint64(uintptr(ptr))
	// Ensure pointer fits in 48 bits (should be true on all modern systems)
	if ptrBits > PTR_MASK {
		panic("pointer too large for NaN-boxing")
	}
	return Value(TAG_PTR | ptrBits)
}

// BoxObject creates a Value from an Object pointer
func BoxObject(obj *Object) Value {
	return BoxPointer(unsafe.Pointer(obj))
}

// Convenience constructors for specific types
func BoxString(s string) Value {
	obj := &StringObj{
		Object: Object{Type: OBJ_STRING},
		Value:  s,
		Hash:   HashString(s),
	}
	// Add to global cache to prevent Go's GC from collecting it
	globalObjectCache = append(globalObjectCache, obj)
	return BoxPointer(unsafe.Pointer(obj))
}

func BoxArray(elements []Value) Value {
	obj := &ArrayObj{
		Object:   Object{Type: OBJ_ARRAY},
		Elements: elements,
	}
	// Add to global cache to prevent Go's GC from collecting it
	globalObjectCache = append(globalObjectCache, obj)
	return BoxPointer(unsafe.Pointer(obj))
}

func BoxMap(items map[string]Value) Value {
	if items == nil {
		items = make(map[string]Value)
	}
	obj := &MapObj{
		Object: Object{Type: OBJ_MAP},
		Items:  items,
	}
	// Add to global cache to prevent Go's GC from collecting it
	globalObjectCache = append(globalObjectCache, obj)
	return BoxPointer(unsafe.Pointer(obj))
}

// ============================================================================
// Value Extraction (Unboxing)
// ============================================================================

// AsNumber extracts float64 from Value (assumes IsNumber check done)
//
//go:inline
func AsNumber(v Value) float64 {
	return math.Float64frombits(uint64(v))
}

// AsInt extracts int64 from Value (assumes IsInt check done)
//
//go:inline
func AsInt(v Value) int64 {
	raw := int64(v & INT_MASK)
	// Check sign bit and extend
	if raw&int64(INT_SIGN) != 0 {
		// Negative: sign-extend from 48 bits
		return raw | ^int64(INT_MASK)
	}
	return raw
}

// AsBool extracts bool from Value (assumes IsBool check done)
//
//go:inline
func AsBool(v Value) bool {
	return v == TAG_TRUE
}

// AsPointer extracts pointer from Value (assumes IsPointer check done)
//
//go:inline
func AsPointer(v Value) unsafe.Pointer {
	return unsafe.Pointer(uintptr(v & PTR_MASK))
}

// AsObject extracts Object pointer from Value
func AsObject(v Value) *Object {
	return (*Object)(AsPointer(v))
}

// Type-specific extractors
func AsString(v Value) *StringObj {
	return (*StringObj)(AsPointer(v))
}

func AsArray(v Value) *ArrayObj {
	return (*ArrayObj)(AsPointer(v))
}

func AsMap(v Value) *MapObj {
	return (*MapObj)(AsPointer(v))
}

func AsFunction(v Value) *FunctionObj {
	return (*FunctionObj)(AsPointer(v))
}

func AsClosure(v Value) *ClosureObj {
	return (*ClosureObj)(AsPointer(v))
}

func AsNativeFn(v Value) *NativeFnObj {
	return (*NativeFnObj)(AsPointer(v))
}

func AsModule(v Value) *ModuleObj {
	return (*ModuleObj)(AsPointer(v))
}

func AsError(v Value) *ErrorObj {
	return (*ErrorObj)(AsPointer(v))
}

func AsIterator(v Value) *IteratorObj {
	return (*IteratorObj)(AsPointer(v))
}

// ============================================================================
// Type Checking (Ultra-fast bit operations)
// ============================================================================

// IsNumber checks if Value is a float64
//
//go:inline
func IsNumber(v Value) bool {
	return (v & NUMBER_MASK) != NUMBER_MASK
}

// IsInt checks if Value is a small integer
//
//go:inline
func IsInt(v Value) bool {
	return (v & TAG_MASK) == TAG_INT
}

// IsBool checks if Value is a boolean
//
//go:inline
func IsBool(v Value) bool {
	return v == TAG_TRUE || v == TAG_FALSE
}

// IsNil checks if Value is nil
//
//go:inline
func IsNil(v Value) bool {
	return v == TAG_NIL
}

// IsPointer checks if Value is a pointer
//
//go:inline
func IsPointer(v Value) bool {
	return (v & TAG_PTR) == TAG_PTR && (v & TAG_INT) != TAG_INT
}

// IsObject checks if Value is an object pointer
//
//go:inline
func IsObject(v Value) bool {
	return IsPointer(v)
}

// Object type checks
func IsString(v Value) bool {
	return IsPointer(v) && AsObject(v).Type == OBJ_STRING
}

func IsArray(v Value) bool {
	return IsPointer(v) && AsObject(v).Type == OBJ_ARRAY
}

func IsMap(v Value) bool {
	return IsPointer(v) && AsObject(v).Type == OBJ_MAP
}

func IsFunction(v Value) bool {
	obj := AsObject(v)
	return IsPointer(v) && (obj.Type == OBJ_FUNCTION || obj.Type == OBJ_CLOSURE)
}

func IsClosure(v Value) bool {
	return IsPointer(v) && AsObject(v).Type == OBJ_CLOSURE
}

func IsIterator(v Value) bool {
	return IsPointer(v) && AsObject(v).Type == OBJ_ITERATOR
}

// ============================================================================
// Value Operations
// ============================================================================

// ValueType returns the type name of a Value
func ValueType(v Value) string {
	if IsNil(v) {
		return "nil"
	}
	if IsBool(v) {
		return "bool"
	}
	if IsInt(v) {
		return "int"
	}
	if IsNumber(v) {
		return "number"
	}
	if IsPointer(v) {
		switch AsObject(v).Type {
		case OBJ_STRING:
			return "string"
		case OBJ_ARRAY:
			return "array"
		case OBJ_MAP:
			return "map"
		case OBJ_FUNCTION:
			return "function"
		case OBJ_CLOSURE:
			return "function"
		case OBJ_NATIVE_FN:
			return "function"
		case OBJ_MODULE:
			return "module"
		case OBJ_ERROR:
			return "error"
		case OBJ_CHANNEL:
			return "channel"
		case OBJ_CLASS:
			return "class"
		case OBJ_INSTANCE:
			return "instance"
		case OBJ_FIBER:
			return "fiber"
		default:
			return "object"
		}
	}
	return "unknown"
}

// IsTruthy determines if a Value is truthy
func IsTruthy(v Value) bool {
	if IsNil(v) {
		return false
	}
	if IsBool(v) {
		return AsBool(v)
	}
	if IsInt(v) {
		return AsInt(v) != 0
	}
	if IsNumber(v) {
		return AsNumber(v) != 0.0
	}
	if IsString(v) {
		return AsString(v).Value != ""
	}
	if IsArray(v) {
		return len(AsArray(v).Elements) > 0
	}
	if IsMap(v) {
		return len(AsMap(v).Items) > 0
	}
	return true // Objects are truthy
}

// ValuesEqual checks if two Values are equal
func ValuesEqual(a, b Value) bool {
	// Fast path: same bits means equal
	if a == b {
		return true
	}

	// Number comparison (handles int/float mixing)
	if (IsNumber(a) || IsInt(a)) && (IsNumber(b) || IsInt(b)) {
		return ToNumber(a) == ToNumber(b)
	}

	// String comparison
	if IsString(a) && IsString(b) {
		return AsString(a).Value == AsString(b).Value
	}

	// Array comparison
	if IsArray(a) && IsArray(b) {
		arrA := AsArray(a)
		arrB := AsArray(b)
		if len(arrA.Elements) != len(arrB.Elements) {
			return false
		}
		for i := range arrA.Elements {
			if !ValuesEqual(arrA.Elements[i], arrB.Elements[i]) {
				return false
			}
		}
		return true
	}

	// Map comparison
	if IsMap(a) && IsMap(b) {
		mapA := AsMap(a)
		mapB := AsMap(b)
		if len(mapA.Items) != len(mapB.Items) {
			return false
		}
		for k, v := range mapA.Items {
			if bv, exists := mapB.Items[k]; !exists || !ValuesEqual(v, bv) {
				return false
			}
		}
		return true
	}

	return false
}

// ToNumber converts a Value to float64
func ToNumber(v Value) float64 {
	if IsNumber(v) {
		return AsNumber(v)
	}
	if IsInt(v) {
		return float64(AsInt(v))
	}
	if IsBool(v) {
		if AsBool(v) {
			return 1.0
		}
		return 0.0
	}
	return 0.0
}

// ToInt converts a Value to int64
func ToInt(v Value) int64 {
	if IsInt(v) {
		return AsInt(v)
	}
	if IsNumber(v) {
		return int64(AsNumber(v))
	}
	if IsBool(v) {
		if AsBool(v) {
			return 1
		}
		return 0
	}
	return 0
}

// ToString converts a Value to string representation
func ToString(v Value) string {
	if IsNil(v) {
		return "nil"
	}
	if IsBool(v) {
		if AsBool(v) {
			return "true"
		}
		return "false"
	}
	if IsInt(v) {
		return fmt.Sprintf("%d", AsInt(v))
	}
	if IsNumber(v) {
		return fmt.Sprintf("%g", AsNumber(v))
	}
	if IsString(v) {
		return AsString(v).Value
	}
	if IsArray(v) {
		arr := AsArray(v)
		parts := make([]string, len(arr.Elements))
		for i, elem := range arr.Elements {
			parts[i] = ToString(elem)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	if IsMap(v) {
		m := AsMap(v)
		pairs := make([]string, 0, len(m.Items))
		for k, val := range m.Items {
			pairs = append(pairs, fmt.Sprintf("%s: %s", k, ToString(val)))
		}
		return "{" + strings.Join(pairs, ", ") + "}"
	}
	if IsFunction(v) || IsClosure(v) {
		return "<function>"
	}
	if IsPointer(v) {
		switch AsObject(v).Type {
		case OBJ_NATIVE_FN:
			return "<native function>"
		case OBJ_MODULE:
			return fmt.Sprintf("<module %s>", AsModule(v).Name)
		case OBJ_ERROR:
			return fmt.Sprintf("Error: %s", AsError(v).Message)
		case OBJ_CHANNEL:
			return "<channel>"
		}
	}
	return "<object>"
}

// PrintValue prints a Value to stdout
func PrintValue(v Value) {
	fmt.Println(ToString(v))
}

// ============================================================================
// Helper Functions
// ============================================================================

// Simple string hash function (FNV-1a)
// HashString computes FNV-1a hash for strings
func HashString(s string) uint64 {
	hash := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		hash ^= uint64(s[i])
		hash *= 1099511628211
	}
	return hash
}

// ============================================================================
// Small Integer Cache (common values)
// ============================================================================

var intCache [512]Value // Cache for -256 to +255

func InitIntCache() {
	for i := -256; i <= 255; i++ {
		intCache[i+256] = BoxInt(int64(i))
	}
}

func CachedInt(i int64) Value {
	if i >= -256 && i <= 255 {
		return intCache[i+256]
	}
	return BoxInt(i)
}

// ============================================================================
// Object Pool (reduce allocations)
// ============================================================================

// ArrayPool for common array sizes
var arrayPools = [8]*ArrayPool{
	newArrayPool(0),   // 0-1 elements
	newArrayPool(2),   // 2-3
	newArrayPool(4),   // 4-7
	newArrayPool(8),   // 8-15
	newArrayPool(16),  // 16-31
	newArrayPool(32),  // 32-63
	newArrayPool(64),  // 64-127
	newArrayPool(128), // 128+
}

type ArrayPool struct {
	capacity int
	free     []*ArrayObj
}

func newArrayPool(cap int) *ArrayPool {
	return &ArrayPool{
		capacity: cap,
		free:     make([]*ArrayObj, 0, 32),
	}
}

func NewArray(capacity int) Value {
	// Find appropriate pool
	poolIdx := 0
	for capacity > arrayPools[poolIdx].capacity && poolIdx < len(arrayPools)-1 {
		poolIdx++
	}

	pool := arrayPools[poolIdx]

	var arr *ArrayObj
	if len(pool.free) > 0 {
		// Reuse from pool
		arr = pool.free[len(pool.free)-1]
		pool.free = pool.free[:len(pool.free)-1]
		arr.Elements = arr.Elements[:0]
	} else {
		// Allocate new
		arr = &ArrayObj{
			Object:   Object{Type: OBJ_ARRAY},
			Elements: make([]Value, 0, pool.capacity),
		}
	}

	return BoxPointer(unsafe.Pointer(arr))
}

func NewMap() Value {
	return BoxMap(make(map[string]Value))
}

func NewError(message string) Value {
	obj := &ErrorObj{
		Object:  Object{Type: OBJ_ERROR},
		Message: message,
		Stack:   []StackFrame{},
	}
	return BoxPointer(unsafe.Pointer(obj))
}

// ============================================================================
// OOP Helper Functions
// ============================================================================

// Class functions
func NewClass(name string) Value {
	obj := &ClassObj{
		Object:     Object{Type: OBJ_CLASS},
		Name:       name,
		Methods:    make(map[string]Value),
		Properties: make(map[string]Value),
		Parent:     nil,
	}
	return BoxPointer(unsafe.Pointer(obj))
}

func IsClass(v Value) bool {
	return IsPointer(v) && AsObject(v).Type == OBJ_CLASS
}

func AsClass(v Value) *ClassObj {
	return (*ClassObj)(unsafe.Pointer(uintptr(v & PTR_MASK)))
}

// Instance functions
func NewInstance(class *ClassObj) Value {
	obj := &InstanceObj{
		Object: Object{Type: OBJ_INSTANCE},
		Class:  class,
		Fields: make(map[string]Value),
	}
	return BoxPointer(unsafe.Pointer(obj))
}

func IsInstance(v Value) bool {
	return IsPointer(v) && AsObject(v).Type == OBJ_INSTANCE
}

func AsInstance(v Value) *InstanceObj {
	return (*InstanceObj)(unsafe.Pointer(uintptr(v & PTR_MASK)))
}

// Module functions
func IsModule(v Value) bool {
	return IsPointer(v) && AsObject(v).Type == OBJ_MODULE
}

// Fiber functions
func NewFiber(fn *FunctionObj) Value {
	obj := &FiberObj{
		Object:   Object{Type: OBJ_FIBER},
		State:    FIBER_NEW,
		Function: fn,
		PC:       0,
		RegTop:   0,
		FrameTop: 0,
	}
	return BoxPointer(unsafe.Pointer(obj))
}

func IsFiber(v Value) bool {
	return IsPointer(v) && AsObject(v).Type == OBJ_FIBER
}

func AsFiber(v Value) *FiberObj {
	return (*FiberObj)(unsafe.Pointer(uintptr(v & PTR_MASK)))
}
