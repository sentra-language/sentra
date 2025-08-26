package vm

import (
	"strings"
	"sync"
)

// String optimization extensions for SuperVM

var (
	// Global string builder pool for all VMs
	stringBuilderPool = &sync.Pool{
		New: func() interface{} {
			return &strings.Builder{}
		},
	}
	
	// Cache for small string concatenations
	stringCache = make(map[string]string, 1000)
	stringCacheMu sync.RWMutex
)

// optimizedStringConcat uses pooled builders for efficient concatenation
func (vm *SuperVM) optimizedStringConcat(a, b Value) string {
	aStr := ToString(a)
	bStr := ToString(b)
	
	// Check cache for small strings
	if len(aStr)+len(bStr) < 50 {
		cacheKey := aStr + "\x00" + bStr
		stringCacheMu.RLock()
		if cached, ok := stringCache[cacheKey]; ok {
			stringCacheMu.RUnlock()
			return cached
		}
		stringCacheMu.RUnlock()
	}
	
	// Use pooled string builder for larger strings
	builder := stringBuilderPool.Get().(*strings.Builder)
	defer func() {
		builder.Reset()
		stringBuilderPool.Put(builder)
	}()
	
	builder.WriteString(aStr)
	builder.WriteString(bStr)
	result := builder.String()
	
	// Cache small results
	if len(result) < 50 {
		stringCacheMu.Lock()
		if len(stringCache) < 10000 { // Limit cache size
			cacheKey := aStr + "\x00" + bStr
			stringCache[cacheKey] = result
		}
		stringCacheMu.Unlock()
	}
	
	return result
}

// Array optimization extensions

// ArrayValue represents an optimized array with type hints
type OptimizedArray struct {
	*Array
	isIntArray   bool
	isFloatArray bool
	intCache     []int     // Cache for homogeneous int arrays
	floatCache   []float64 // Cache for homogeneous float arrays
}

// optimizedArrayPush adds type-aware array optimization
func (vm *SuperVM) optimizedArrayPush(arr Value, item Value) {
	switch a := arr.(type) {
	case *OptimizedArray:
		// Check if we can maintain type specialization
		if intVal, ok := item.(int); ok && a.isIntArray {
			a.intCache = append(a.intCache, intVal)
			a.Elements = append(a.Elements, item)
			return
		}
		if floatVal, ok := item.(float64); ok && a.isFloatArray {
			a.floatCache = append(a.floatCache, floatVal)
			a.Elements = append(a.Elements, item)
			return
		}
		
		// Type changed, fall back to generic
		a.isIntArray = false
		a.isFloatArray = false
		a.Elements = append(a.Elements, item)
		
	case *Array:
		a.Elements = append(a.Elements, item)
		
	default:
		panic("push requires an array")
	}
}

// optimizedArraySum provides fast summation for numeric arrays
func (vm *SuperVM) optimizedArraySum(arr Value) Value {
	switch a := arr.(type) {
	case *OptimizedArray:
		if a.isIntArray && len(a.intCache) > 0 {
			sum := 0
			for _, v := range a.intCache {
				sum += v
			}
			return sum
		}
		if a.isFloatArray && len(a.floatCache) > 0 {
			sum := 0.0
			for _, v := range a.floatCache {
				sum += v
			}
			return sum
		}
	}
	
	// Fall back to generic summation
	sum := 0.0
	if a, ok := arr.(*Array); ok {
		for _, item := range a.Elements {
			sum += ToNumber(item)
		}
	}
	return sum
}

// Map optimization with type hints

// OptimizedMap provides faster map operations
type OptimizedMap struct {
	*Map
	intValues   map[string]int     // Specialized storage for int values
	floatValues map[string]float64 // Specialized storage for float values
	hasIntVals  bool
	hasFloatVals bool
}

// optimizedMapSet provides type-aware map setting
func (vm *SuperVM) optimizedMapSet(m Value, key string, val Value) {
	switch mp := m.(type) {
	case *OptimizedMap:
		// Try to maintain type specialization
		if intVal, ok := val.(int); ok {
			if mp.intValues == nil {
				mp.intValues = make(map[string]int)
			}
			mp.intValues[key] = intVal
			mp.hasIntVals = true
			mp.Items[key] = val
			return
		}
		
		if floatVal, ok := val.(float64); ok {
			if mp.floatValues == nil {
				mp.floatValues = make(map[string]float64)
			}
			mp.floatValues[key] = floatVal
			mp.hasFloatVals = true
			mp.Items[key] = val
			return
		}
		
		// Generic value
		mp.Items[key] = val
		
	case *Map:
		mp.Items[key] = val
		
	default:
		panic("map set requires a map")
	}
}

// optimizedMapGet provides fast typed retrieval
func (vm *SuperVM) optimizedMapGet(m Value, key string) Value {
	switch mp := m.(type) {
	case *OptimizedMap:
		// Try specialized storage first
		if mp.hasIntVals {
			if val, ok := mp.intValues[key]; ok {
				return val
			}
		}
		if mp.hasFloatVals {
			if val, ok := mp.floatValues[key]; ok {
				return val
			}
		}
		// Fall back to generic
		return mp.Items[key]
		
	case *Map:
		return mp.Items[key]
		
	default:
		return nil
	}
}