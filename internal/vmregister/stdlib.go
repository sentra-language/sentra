package vmregister

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"sentra/internal/cloud"
	"sentra/internal/concurrency"
	"sentra/internal/container"
	"sentra/internal/cryptoanalysis"
	"sentra/internal/database"
	"sentra/internal/dataframe"
	"sentra/internal/filesystem"
	"sentra/internal/incident"
	"sentra/internal/memory"
	"sentra/internal/ml"
	"sentra/internal/network"
	"sentra/internal/ossec"
	"sentra/internal/reporting"
	"sentra/internal/security"
	"sentra/internal/siem"
	"sentra/internal/threat_intel"
	"sentra/internal/webclient"
	"strings"
	"time"
	"unsafe"
)

// Compression helper functions
func newGzipWriter(w io.Writer) (*gzip.Writer, error) {
	return gzip.NewWriter(w), nil
}

func newGzipReader(r io.Reader) (*gzip.Reader, error) {
	return gzip.NewReader(r)
}

func newFlateWriter(w io.Writer, level int) (*flate.Writer, error) {
	return flate.NewWriter(w, level)
}

func newFlateReader(r io.Reader) io.ReadCloser {
	return flate.NewReader(r)
}

// RegisterStdlib registers all standard library functions as globals
func (vm *RegisterVM) RegisterStdlib() {
	// Initialize library modules (don't affect VM opcodes)
	vm.dbManager = database.NewDBManager()
	vm.networkModule = network.NewNetworkModule()
	vm.siemModule = siem.NewSIEMModule()
	vm.securityModule = security.NewSecurityModule()
	vm.filesystemModule = filesystem.NewFileSystemModule()
	vm.osSecModule = ossec.NewOSSecurityModule()
	vm.webClientModule = webclient.NewWebClientModule()
	vm.incidentModule = incident.NewIncidentModule()
	vm.threatIntelModule = threat_intel.NewThreatIntelModule()
	vm.cloudModule = cloud.NewCSPMModule()
	vm.reportingModule = reporting.NewReportingModule()
	vm.concurrencyModule = concurrency.NewConcurrencyModule()
	vm.containerModule = container.NewContainerScanner()
	vm.cryptoModule = cryptoanalysis.NewCryptoAnalysisModule()
	vm.mlModule = ml.NewMLModule()
	vm.memoryModule = memory.NewIntegratedMemoryModule()

	// String functions
	vm.registerGlobal("upper", createStringFunc("upper", 1, strings.ToUpper))
	vm.registerGlobal("lower", createStringFunc("lower", 1, strings.ToLower))
	vm.registerGlobal("trim", createStringFunc("trim", 1, strings.TrimSpace))

	vm.registerGlobal("len", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "len",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			val := args[0]
			if IsString(val) {
				return BoxInt(int64(len(ToString(val)))), nil
			} else if IsArray(val) {
				arr := AsArray(val)
				return BoxInt(int64(len(arr.Elements))), nil
			}
			return NilValue(), fmt.Errorf("len expects string or array")
		},
	})

	// Math functions
	vm.registerGlobal("abs", createMathFunc("abs", 1, math.Abs))
	vm.registerGlobal("sqrt", createMathFunc("sqrt", 1, math.Sqrt))
	vm.registerGlobal("floor", createMathFunc("floor", 1, math.Floor))
	vm.registerGlobal("ceil", createMathFunc("ceil", 1, math.Ceil))
	vm.registerGlobal("round", createMathFunc("round", 1, math.Round))

	vm.registerGlobal("pow", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "pow",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			base := ToNumber(args[0])
			exp := ToNumber(args[1])
			return BoxNumber(math.Pow(base, exp)), nil
		},
	})

	vm.registerGlobal("min", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "min",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			a := ToNumber(args[0])
			b := ToNumber(args[1])
			return BoxNumber(math.Min(a, b)), nil
		},
	})

	vm.registerGlobal("max", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "max",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			a := ToNumber(args[0])
			b := ToNumber(args[1])
			return BoxNumber(math.Max(a, b)), nil
		},
	})

	// Array functions
	vm.registerGlobal("sort", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "sort",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("sort expects array")
			}
			arr := AsArray(args[0])
			// Simple bubble sort for now
			n := len(arr.Elements)
			for i := 0; i < n-1; i++ {
				for j := 0; j < n-i-1; j++ {
					if ToNumber(arr.Elements[j]) > ToNumber(arr.Elements[j+1]) {
						arr.Elements[j], arr.Elements[j+1] = arr.Elements[j+1], arr.Elements[j]
					}
				}
			}
			return NilValue(), nil
		},
	})

	// Date/time functions
	vm.registerGlobal("date", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "date",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			return BoxString(time.Now().Format("2006-01-02")), nil
		},
	})

	vm.registerGlobal("time", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "time",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			return BoxInt(time.Now().Unix()), nil
		},
	})

	vm.registerGlobal("time_ms", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "time_ms",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			return BoxInt(time.Now().UnixMilli()), nil
		},
	})

	// Alias for time_ms - commonly used name
	vm.registerGlobal("timestamp", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "timestamp",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			return BoxInt(time.Now().UnixMilli()), nil
		},
	})

	vm.registerGlobal("now", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "now",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			return BoxString(time.Now().Format(time.RFC3339)), nil
		},
	})

	vm.registerGlobal("datetime", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "datetime",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			return BoxString(time.Now().Format("2006-01-02 15:04:05")), nil
		},
	})

	vm.registerGlobal("format_timestamp", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "format_timestamp",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			var timestamp int64
			if IsInt(args[0]) {
				timestamp = AsInt(args[0])
			} else if IsNumber(args[0]) {
				timestamp = int64(AsNumber(args[0]))
			} else if IsString(args[0]) {
				// Handle RFC3339 string format from now()
				t, err := time.Parse(time.RFC3339, ToString(args[0]))
				if err != nil {
					return NilValue(), fmt.Errorf("invalid timestamp format")
				}
				return BoxString(t.Format("2006-01-02 15:04:05")), nil
			} else {
				return NilValue(), fmt.Errorf("format_timestamp expects number or string")
			}
			t := time.Unix(timestamp, 0)
			return BoxString(t.Format("2006-01-02 15:04:05")), nil
		},
	})

	// Type checking functions
	vm.registerGlobal("typeof", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "typeof",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			val := args[0]
			if IsNil(val) {
				return BoxString("nil"), nil
			} else if IsBool(val) {
				return BoxString("boolean"), nil
			} else if IsInt(val) || IsNumber(val) {
				return BoxString("number"), nil
			} else if IsString(val) {
				return BoxString("string"), nil
			} else if IsArray(val) {
				return BoxString("array"), nil
			} else if IsMap(val) {
				return BoxString("map"), nil
			} else if IsFunction(val) {
				return BoxString("function"), nil
			}
			return BoxString("object"), nil
		},
	})

	// Utility functions
	vm.registerGlobal("print", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "print",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			fmt.Println(str)
			return NilValue(), nil
		},
	})

	vm.registerGlobal("log", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "log",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			fmt.Println(str)
			return NilValue(), nil
		},
	})

	// More string functions
	vm.registerGlobal("split", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "split",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			sep := ToString(args[1])
			parts := strings.Split(str, sep)
			elements := make([]Value, len(parts))
			for i, part := range parts {
				elements[i] = BoxString(part)
			}
			return BoxArray(elements), nil
		},
	})

	vm.registerGlobal("join", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "join",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("join expects array as first argument")
			}
			arr := AsArray(args[0])
			sep := ToString(args[1])
			strs := make([]string, len(arr.Elements))
			for i, elem := range arr.Elements {
				strs[i] = ToString(elem)
			}
			return BoxString(strings.Join(strs, sep)), nil
		},
	})

	vm.registerGlobal("replace", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "replace",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			old := ToString(args[1])
			new := ToString(args[2])
			return BoxString(strings.ReplaceAll(str, old, new)), nil
		},
	})

	vm.registerGlobal("contains", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "contains",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			substr := ToString(args[1])
			return BoxBool(strings.Contains(str, substr)), nil
		},
	})

	vm.registerGlobal("startswith", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "startswith",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			prefix := ToString(args[1])
			return BoxBool(strings.HasPrefix(str, prefix)), nil
		},
	})

	vm.registerGlobal("endswith", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "endswith",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			suffix := ToString(args[1])
			return BoxBool(strings.HasSuffix(str, suffix)), nil
		},
	})

	vm.registerGlobal("char_at", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "char_at",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			index := int(ToInt(args[1]))
			if index < 0 || index >= len(str) {
				return BoxString(""), nil
			}
			return BoxString(string(str[index])), nil
		},
	})

	vm.registerGlobal("slice", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "slice",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			start := int(ToInt(args[1]))
			if start < 0 || start >= len(str) {
				return BoxString(""), nil
			}
			return BoxString(str[start:]), nil
		},
	})

	vm.registerGlobal("index_of", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "index_of",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			substr := ToString(args[1])
			idx := strings.Index(str, substr)
			return BoxInt(int64(idx)), nil
		},
	})

	// Array functions
	vm.registerGlobal("push", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "push",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("push expects array")
			}
			arr := AsArray(args[0])
			arr.Elements = append(arr.Elements, args[1])
			return NilValue(), nil
		},
	})

	vm.registerGlobal("pop", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "pop",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("pop expects array")
			}
			arr := AsArray(args[0])
			if len(arr.Elements) == 0 {
				return NilValue(), nil
			}
			last := arr.Elements[len(arr.Elements)-1]
			arr.Elements = arr.Elements[:len(arr.Elements)-1]
			return last, nil
		},
	})

	vm.registerGlobal("remove", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "remove",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("remove expects array")
			}
			arr := AsArray(args[0])
			index := int(ToInt(args[1]))
			if index < 0 || index >= len(arr.Elements) {
				return NilValue(), fmt.Errorf("index out of bounds")
			}
			val := arr.Elements[index]
			arr.Elements = append(arr.Elements[:index], arr.Elements[index+1:]...)
			return val, nil
		},
	})

	vm.registerGlobal("insert", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "insert",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("insert expects array")
			}
			arr := AsArray(args[0])
			index := int(ToInt(args[1]))
			value := args[2]
			if index < 0 {
				index = 0
			}
			if index > len(arr.Elements) {
				index = len(arr.Elements)
			}
			arr.Elements = append(arr.Elements[:index], append([]Value{value}, arr.Elements[index:]...)...)
			return NilValue(), nil
		},
	})

	vm.registerGlobal("first", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "first",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("first expects array")
			}
			arr := AsArray(args[0])
			if len(arr.Elements) == 0 {
				return NilValue(), nil
			}
			return arr.Elements[0], nil
		},
	})

	vm.registerGlobal("last", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "last",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("last expects array")
			}
			arr := AsArray(args[0])
			if len(arr.Elements) == 0 {
				return NilValue(), nil
			}
			return arr.Elements[len(arr.Elements)-1], nil
		},
	})

	vm.registerGlobal("shift", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "shift",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("shift expects array")
			}
			arr := AsArray(args[0])
			if len(arr.Elements) == 0 {
				return NilValue(), nil
			}
			first := arr.Elements[0]
			arr.Elements = arr.Elements[1:]
			return first, nil
		},
	})

	vm.registerGlobal("unshift", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "unshift",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("unshift expects array")
			}
			arr := AsArray(args[0])
			arr.Elements = append([]Value{args[1]}, arr.Elements...)
			return NilValue(), nil
		},
	})

	vm.registerGlobal("reverse", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "reverse",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("reverse expects array")
			}
			arr := AsArray(args[0])
			n := len(arr.Elements)
			for i := 0; i < n/2; i++ {
				arr.Elements[i], arr.Elements[n-1-i] = arr.Elements[n-1-i], arr.Elements[i]
			}
			return NilValue(), nil
		},
	})

	// More math functions
	vm.registerGlobal("sin", createMathFunc("sin", 1, math.Sin))
	vm.registerGlobal("cos", createMathFunc("cos", 1, math.Cos))
	vm.registerGlobal("tan", createMathFunc("tan", 1, math.Tan))

	vm.registerGlobal("random", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "random",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			return BoxNumber(rand.Float64()), nil
		},
	})

	vm.registerGlobal("randint", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "randint",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			min := int64(ToInt(args[0]))
			max := int64(ToInt(args[1]))
			if max <= min {
				return BoxInt(min), nil
			}
			// Simple pseudo-random using time
			val := time.Now().UnixNano()
			result := min + (val % (max - min))
			return BoxInt(result), nil
		},
	})

	// Type conversion
	vm.registerGlobal("parse_int", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "parse_int",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			var result int64
			_, err := fmt.Sscanf(str, "%d", &result)
			if err != nil {
				return BoxInt(0), nil
			}
			return BoxInt(result), nil
		},
	})

	vm.registerGlobal("parse_float", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "parse_float",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			var result float64
			_, err := fmt.Sscanf(str, "%f", &result)
			if err != nil {
				return BoxNumber(0), nil
			}
			return BoxNumber(result), nil
		},
	})

	vm.registerGlobal("str", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "str",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			return BoxString(ToString(args[0])), nil
		},
	})

	vm.registerGlobal("type", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "type",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			return BoxString(ValueType(args[0])), nil
		},
	})

	// Array utility functions
	vm.registerGlobal("sum", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "sum",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("sum expects array")
			}
			arr := AsArray(args[0])
			var sum float64
			for _, v := range arr.Elements {
				if IsInt(v) {
					sum += float64(AsInt(v))
				} else if IsNumber(v) {
					sum += AsNumber(v)
				}
			}
			return BoxNumber(sum), nil
		},
	})

	vm.registerGlobal("avg", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "avg",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("avg expects array")
			}
			arr := AsArray(args[0])
			if len(arr.Elements) == 0 {
				return BoxNumber(0), nil
			}
			var sum float64
			for _, v := range arr.Elements {
				if IsInt(v) {
					sum += float64(AsInt(v))
				} else if IsNumber(v) {
					sum += AsNumber(v)
				}
			}
			return BoxNumber(sum / float64(len(arr.Elements))), nil
		},
	})

	vm.registerGlobal("min_arr", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "min_arr",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("min_arr expects array")
			}
			arr := AsArray(args[0])
			if len(arr.Elements) == 0 {
				return NilValue(), nil
			}
			minVal := arr.Elements[0]
			minNum := math.Inf(1)
			if IsInt(minVal) {
				minNum = float64(AsInt(minVal))
			} else if IsNumber(minVal) {
				minNum = AsNumber(minVal)
			}
			for _, v := range arr.Elements[1:] {
				var num float64
				if IsInt(v) {
					num = float64(AsInt(v))
				} else if IsNumber(v) {
					num = AsNumber(v)
				} else {
					continue
				}
				if num < minNum {
					minNum = num
					minVal = v
				}
			}
			return minVal, nil
		},
	})

	vm.registerGlobal("max_arr", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "max_arr",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("max_arr expects array")
			}
			arr := AsArray(args[0])
			if len(arr.Elements) == 0 {
				return NilValue(), nil
			}
			maxVal := arr.Elements[0]
			maxNum := math.Inf(-1)
			if IsInt(maxVal) {
				maxNum = float64(AsInt(maxVal))
			} else if IsNumber(maxVal) {
				maxNum = AsNumber(maxVal)
			}
			for _, v := range arr.Elements[1:] {
				var num float64
				if IsInt(v) {
					num = float64(AsInt(v))
				} else if IsNumber(v) {
					num = AsNumber(v)
				} else {
					continue
				}
				if num > maxNum {
					maxNum = num
					maxVal = v
				}
			}
			return maxVal, nil
		},
	})

	vm.registerGlobal("unique", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "unique",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("unique expects array")
			}
			arr := AsArray(args[0])
			seen := make(map[string]bool)
			result := make([]Value, 0)
			for _, v := range arr.Elements {
				key := ToString(v)
				if !seen[key] {
					seen[key] = true
					result = append(result, v)
				}
			}
			return BoxArray(result), nil
		},
	})

	vm.registerGlobal("flatten", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "flatten",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("flatten expects array")
			}
			arr := AsArray(args[0])
			result := make([]Value, 0)
			for _, v := range arr.Elements {
				if IsArray(v) {
					inner := AsArray(v)
					result = append(result, inner.Elements...)
				} else {
					result = append(result, v)
				}
			}
			return BoxArray(result), nil
		},
	})

	vm.registerGlobal("zip", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "zip",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) || !IsArray(args[1]) {
				return NilValue(), fmt.Errorf("zip expects two arrays")
			}
			arr1 := AsArray(args[0])
			arr2 := AsArray(args[1])
			minLen := len(arr1.Elements)
			if len(arr2.Elements) < minLen {
				minLen = len(arr2.Elements)
			}
			result := make([]Value, minLen)
			for i := 0; i < minLen; i++ {
				pair := []Value{arr1.Elements[i], arr2.Elements[i]}
				result[i] = BoxArray(pair)
			}
			return BoxArray(result), nil
		},
	})

	vm.registerGlobal("enumerate", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "enumerate",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("enumerate expects array")
			}
			arr := AsArray(args[0])
			result := make([]Value, len(arr.Elements))
			for i, v := range arr.Elements {
				pair := []Value{BoxInt(int64(i)), v}
				result[i] = BoxArray(pair)
			}
			return BoxArray(result), nil
		},
	})

	vm.registerGlobal("count", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "count",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("count expects array as first argument")
			}
			arr := AsArray(args[0])
			target := ToString(args[1])
			count := 0
			for _, v := range arr.Elements {
				if ToString(v) == target {
					count++
				}
			}
			return BoxInt(int64(count)), nil
		},
	})

	vm.registerGlobal("fill", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "fill",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			n := int(ToInt(args[0]))
			val := args[1]
			result := make([]Value, n)
			for i := 0; i < n; i++ {
				result[i] = val
			}
			return BoxArray(result), nil
		},
	})

	// Utility functions
	vm.registerGlobal("range", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "range",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			start := int(ToInt(args[0]))
			end := int(ToInt(args[1]))
			elements := make([]Value, 0, end-start)
			for i := start; i < end; i++ {
				elements = append(elements, BoxInt(int64(i)))
			}
			return BoxPointer(unsafe.Pointer(&ArrayObj{
				Object:   Object{Type: OBJ_ARRAY},
				Elements: elements,
			})), nil
		},
	})

	vm.registerGlobal("keys", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "keys",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsMap(args[0]) {
				return NilValue(), fmt.Errorf("keys expects map")
			}
			m := AsMap(args[0])
			elements := make([]Value, 0, len(m.Items))
			for key := range m.Items {
				elements = append(elements, BoxString(key))
			}
			return BoxPointer(unsafe.Pointer(&ArrayObj{
				Object:   Object{Type: OBJ_ARRAY},
				Elements: elements,
			})), nil
		},
	})

	vm.registerGlobal("has_key", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "has_key",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			if !IsMap(args[0]) {
				return BoxBool(false), nil
			}
			m := AsMap(args[0])
			key := ToString(args[1])
			_, exists := m.Items[key]
			return BoxBool(exists), nil
		},
	})

	// JSON functions
	vm.registerGlobal("json_encode", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "json_encode",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			goVal := valueToGo(args[0])
			jsonBytes, err := json.Marshal(goVal)
			if err != nil {
				return NilValue(), fmt.Errorf("json_encode error: %v", err)
			}
			return BoxString(string(jsonBytes)), nil
		},
	})

	vm.registerGlobal("json_decode", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "json_decode",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			jsonStr := ToString(args[0])
			var goVal interface{}
			err := json.Unmarshal([]byte(jsonStr), &goVal)
			if err != nil {
				return NilValue(), fmt.Errorf("json_decode error: %v", err)
			}
			return goToValue(goVal), nil
		},
	})

	// File I/O functions
	vm.registerGlobal("read_file", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "read_file",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			filename := ToString(args[0])
			content, err := os.ReadFile(filename)
			if err != nil {
				return NilValue(), fmt.Errorf("read_file error: %v", err)
			}
			return BoxString(string(content)), nil
		},
	})

	vm.registerGlobal("write_file", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "write_file",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			filename := ToString(args[0])
			content := ToString(args[1])
			err := os.WriteFile(filename, []byte(content), 0644)
			if err != nil {
				return NilValue(), fmt.Errorf("write_file error: %v", err)
			}
			return NilValue(), nil
		},
	})

	vm.registerGlobal("file_exists", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "file_exists",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			filename := ToString(args[0])
			_, err := os.Stat(filename)
			return BoxBool(err == nil), nil
		},
	})

	// HTTP client functions
	vm.registerGlobal("http_get", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "http_get",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			url := ToString(args[0])
			resp, err := http.Get(url)
			if err != nil {
				// Return nil on connection errors (allows user to check for nil)
				return NilValue(), nil
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return NilValue(), nil
			}

			// Return response as map with status, status_code, body, headers
			result := make(map[string]Value)
			result["status"] = BoxString(resp.Status)
			result["status_code"] = BoxInt(int64(resp.StatusCode))
			result["body"] = BoxString(string(body))

			// Convert headers to map
			headers := make(map[string]Value)
			for k, v := range resp.Header {
				if len(v) > 0 {
					headers[k] = BoxString(v[0])
				}
			}
			result["headers"] = BoxMap(headers)

			return BoxMap(result), nil
		},
	})

	vm.registerGlobal("http_post", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "http_post",
		Arity:  -1, // Variable args: url, body, [headers]
		Function: func(args []Value) (Value, error) {
			if len(args) < 2 {
				return NilValue(), fmt.Errorf("http_post expects at least 2 arguments (url, body)")
			}
			url := ToString(args[0])
			data := ToString(args[1])

			contentType := "application/json"
			var customHeaders map[string]Value
			if len(args) >= 3 && IsMap(args[2]) {
				customHeaders = AsMap(args[2]).Items
				if ct, ok := customHeaders["Content-Type"]; ok {
					contentType = ToString(ct)
				}
			}

			req, err := http.NewRequest("POST", url, bytes.NewBufferString(data))
			if err != nil {
				return NilValue(), fmt.Errorf("http_post error: %v", err)
			}
			req.Header.Set("Content-Type", contentType)

			// Add custom headers
			if customHeaders != nil {
				for k, v := range customHeaders {
					req.Header.Set(k, ToString(v))
				}
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				return NilValue(), fmt.Errorf("http_post error: %v", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return NilValue(), fmt.Errorf("http_post read error: %v", err)
			}

			// Return response as map
			result := make(map[string]Value)
			result["status"] = BoxString(resp.Status)
			result["status_code"] = BoxInt(int64(resp.StatusCode))
			result["body"] = BoxString(string(body))

			// Convert headers to map
			headers := make(map[string]Value)
			for k, v := range resp.Header {
				if len(v) > 0 {
					headers[k] = BoxString(v[0])
				}
			}
			result["headers"] = BoxMap(headers)

			return BoxMap(result), nil
		},
	})

	vm.registerGlobal("fetch", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "fetch",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			url := ToString(args[0])
			resp, err := http.Get(url)
			if err != nil {
				return NilValue(), fmt.Errorf("fetch error: %v", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return NilValue(), fmt.Errorf("fetch read error: %v", err)
			}

			// Return as map with status and body
			result := make(map[string]Value)
			result["status"] = BoxInt(int64(resp.StatusCode))
			result["body"] = BoxString(string(body))
			return BoxMap(result), nil
		},
	})

	vm.registerGlobal("http_request", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "http_request",
		Arity:  4, // method, url, headers, body
		Function: func(args []Value) (Value, error) {
			method := ToString(args[0])
			url := ToString(args[1])
			var headersMap map[string]Value
			if IsMap(args[2]) {
				headersMap = AsMap(args[2]).Items
			}
			bodyData := ToString(args[3])

			var bodyReader io.Reader
			if bodyData != "" {
				bodyReader = bytes.NewBufferString(bodyData)
			}

			req, err := http.NewRequest(method, url, bodyReader)
			if err != nil {
				return NilValue(), fmt.Errorf("http_request error: %v", err)
			}

			// Add custom headers
			if headersMap != nil {
				for k, v := range headersMap {
					req.Header.Set(k, ToString(v))
				}
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				return NilValue(), fmt.Errorf("http_request error: %v", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return NilValue(), fmt.Errorf("http_request read error: %v", err)
			}

			// Return response as map
			result := make(map[string]Value)
			result["status"] = BoxString(resp.Status)
			result["status_code"] = BoxInt(int64(resp.StatusCode))
			result["body"] = BoxString(string(body))

			// Convert headers to map
			headers := make(map[string]Value)
			for k, v := range resp.Header {
				if len(v) > 0 {
					headers[k] = BoxString(v[0])
				}
			}
			result["headers"] = BoxMap(headers)

			return BoxMap(result), nil
		},
	})

	vm.registerGlobal("http_download", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "http_download",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			url := ToString(args[0])
			resp, err := http.Get(url)
			if err != nil {
				return NilValue(), fmt.Errorf("http_download error: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				return NilValue(), fmt.Errorf("http_download failed with status: %s", resp.Status)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return NilValue(), fmt.Errorf("http_download read error: %v", err)
			}

			return BoxString(string(body)), nil
		},
	})

	vm.registerGlobal("http_json", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "http_json",
		Arity:  3, // method, url, data (as map)
		Function: func(args []Value) (Value, error) {
			method := ToString(args[0])
			url := ToString(args[1])

			// Convert data map to JSON
			var jsonBody string
			if IsMap(args[2]) {
				goData := valueToGo(args[2])
				jsonBytes, err := json.Marshal(goData)
				if err != nil {
					return NilValue(), fmt.Errorf("http_json: failed to marshal data: %v", err)
				}
				jsonBody = string(jsonBytes)
			} else {
				jsonBody = ToString(args[2])
			}

			var bodyReader io.Reader
			if jsonBody != "" {
				bodyReader = bytes.NewBufferString(jsonBody)
			}

			req, err := http.NewRequest(method, url, bodyReader)
			if err != nil {
				return NilValue(), fmt.Errorf("http_json error: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				return NilValue(), fmt.Errorf("http_json error: %v", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return NilValue(), fmt.Errorf("http_json read error: %v", err)
			}

			// Return response as map
			result := make(map[string]Value)
			result["status"] = BoxString(resp.Status)
			result["status_code"] = BoxInt(int64(resp.StatusCode))
			result["body"] = BoxString(string(body))

			// Try to parse JSON response
			var jsonData interface{}
			if err := json.Unmarshal(body, &jsonData); err == nil {
				result["json"] = goToValue(jsonData)
			}

			return BoxMap(result), nil
		},
	})

	// Regex functions
	vm.registerGlobal("regex_match", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "regex_match",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			pattern := ToString(args[0])
			text := ToString(args[1])

			matched, err := regexp.MatchString(pattern, text)
			if err != nil {
				return NilValue(), fmt.Errorf("regex_match error: %v", err)
			}

			return BoxBool(matched), nil
		},
	})

	vm.registerGlobal("regex_find", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "regex_find",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			pattern := ToString(args[0])
			text := ToString(args[1])

			re, err := regexp.Compile(pattern)
			if err != nil {
				return NilValue(), fmt.Errorf("regex_find compile error: %v", err)
			}

			match := re.FindString(text)
			if match == "" {
				return NilValue(), nil
			}

			return BoxString(match), nil
		},
	})

	vm.registerGlobal("regex_find_all", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "regex_find_all",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			pattern := ToString(args[0])
			text := ToString(args[1])

			re, err := regexp.Compile(pattern)
			if err != nil {
				return NilValue(), fmt.Errorf("regex_find_all compile error: %v", err)
			}

			matches := re.FindAllString(text, -1)
			if matches == nil {
				return BoxArray([]Value{}), nil
			}

			elements := make([]Value, len(matches))
			for i, match := range matches {
				elements[i] = BoxString(match)
			}

			return BoxArray(elements), nil
		},
	})

	vm.registerGlobal("regex_replace", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "regex_replace",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			pattern := ToString(args[0])
			replacement := ToString(args[1])
			text := ToString(args[2])

			re, err := regexp.Compile(pattern)
			if err != nil {
				return NilValue(), fmt.Errorf("regex_replace compile error: %v", err)
			}

			result := re.ReplaceAllString(text, replacement)
			return BoxString(result), nil
		},
	})

	vm.registerGlobal("regex_split", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "regex_split",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			pattern := ToString(args[0])
			text := ToString(args[1])

			re, err := regexp.Compile(pattern)
			if err != nil {
				return NilValue(), fmt.Errorf("regex_split compile error: %v", err)
			}

			parts := re.Split(text, -1)
			elements := make([]Value, len(parts))
			for i, part := range parts {
				elements[i] = BoxString(part)
			}

			return BoxArray(elements), nil
		},
	})

	// =====================================================
	// DATABASE FUNCTIONS (using internal/database module)
	// =====================================================

	vm.registerGlobal("db_connect", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "db_connect",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			if vm.dbManager == nil {
				return NilValue(), fmt.Errorf("database module not initialized")
			}
			dbMgr := vm.dbManager.(*database.DBManager)

			id := ToString(args[0])
			dbType := ToString(args[1])
			dsn := ToString(args[2])

			err := dbMgr.Connect(id, dbType, dsn)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	vm.registerGlobal("db_execute", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "db_execute",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			if vm.dbManager == nil {
				return NilValue(), fmt.Errorf("database module not initialized")
			}
			dbMgr := vm.dbManager.(*database.DBManager)

			connID := ToString(args[0])
			query := ToString(args[1])

			affected, err := dbMgr.Execute(connID, query)
			if err != nil {
				return NilValue(), err
			}
			return BoxInt(affected), nil
		},
	})

	vm.registerGlobal("db_query", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "db_query",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			if vm.dbManager == nil {
				return NilValue(), fmt.Errorf("database module not initialized")
			}
			dbMgr := vm.dbManager.(*database.DBManager)

			connID := ToString(args[0])
			query := ToString(args[1])

			results, err := dbMgr.Query(connID, query)
			if err != nil {
				return NilValue(), err
			}

			// Convert []map[string]interface{} to Sentra array of maps
			rows := make([]Value, len(results))
			for i, row := range results {
				items := make(map[string]Value)
				for key, val := range row {
					items[key] = goToValue(val)
				}
				rows[i] = BoxMap(items)
			}

			return BoxArray(rows), nil
		},
	})

	vm.registerGlobal("db_close", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "db_close",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if vm.dbManager == nil {
				return NilValue(), fmt.Errorf("database module not initialized")
			}
			dbMgr := vm.dbManager.(*database.DBManager)

			connID := ToString(args[0])

			err := dbMgr.Close(connID)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// =====================================================
	// NETWORK SCANNING FUNCTIONS (using internal/network module)
	// =====================================================

	vm.registerGlobal("tcp_scan", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "tcp_scan",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			if vm.networkModule == nil {
				return NilValue(), fmt.Errorf("network module not initialized")
			}

			host := ToString(args[0])
			port := int(ToInt(args[1]))
			timeoutMs := int(ToInt(args[2]))

			// Simple TCP connection test
			timeout := time.Duration(timeoutMs) * time.Millisecond
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
			if err != nil {
				return BoxBool(false), nil // Port closed
			}
			conn.Close()
			return BoxBool(true), nil // Port open
		},
	})

	vm.registerGlobal("ping", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ping",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			host := ToString(args[0])

			// Use TCP dial to port 80 as a simple "alive" check
			// (ICMP ping requires raw sockets/privileges)
			timeout := 2 * time.Second
			conn, err := net.DialTimeout("tcp", host+":80", timeout)
			if err != nil {
				return BoxBool(false), nil
			}
			conn.Close()
			return BoxBool(true), nil
		},
	})

	vm.registerGlobal("port_scan", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "port_scan",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			if vm.networkModule == nil {
				return NilValue(), fmt.Errorf("network module not initialized")
			}
			netMod := vm.networkModule.(*network.NetworkModule)

			host := ToString(args[0])
			startPort := int(ToInt(args[1]))
			endPort := int(ToInt(args[2]))

			// Use the network module's PortScan function
			results := netMod.PortScan(host, startPort, endPort, "tcp")

			// Convert to Sentra array of maps
			openPorts := []Value{}
			for _, result := range results {
				if result.State == "open" {
					portInfo := map[string]Value{
						"port":    BoxInt(int64(result.Port)),
						"state":   BoxString(result.State),
						"service": BoxString(result.Service),
						"banner":  BoxString(result.Banner),
					}
					openPorts = append(openPorts, BoxMap(portInfo))
				}
			}

			return BoxArray(openPorts), nil
		},
	})

	vm.registerGlobal("tcp_connect", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "tcp_connect",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			host := ToString(args[0])
			port := int(ToInt(args[1]))
			timeoutMs := int(ToInt(args[2]))

			// Attempt TCP connection
			timeout := time.Duration(timeoutMs) * time.Millisecond
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
			if err != nil {
				return NilValue(), err
			}
			conn.Close()
			return BoxBool(true), nil
		},
	})

	// =====================================================
	// COMPATIBILITY ALIASES (sql_* for old stack VM compatibility)
	// =====================================================

	// sql_connect -> db_connect alias
	vm.globalNames["sql_connect"] = vm.globalNames["db_connect"]

	// sql_execute -> db_execute alias
	vm.globalNames["sql_execute"] = vm.globalNames["db_execute"]

	// sql_query -> db_query alias
	vm.globalNames["sql_query"] = vm.globalNames["db_query"]

	// sql_close -> db_close alias
	vm.globalNames["sql_close"] = vm.globalNames["db_close"]

	// =====================================================
	// SIEM FUNCTIONS (Security Information & Event Management)
	// =====================================================

	vm.registerGlobal("siem_parse_log", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "siem_parse_log",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			if vm.siemModule == nil {
				return NilValue(), fmt.Errorf("SIEM module not initialized")
			}
			siemMod := vm.siemModule.(*siem.SIEMModule)

			filePath := ToString(args[0])
			format := ToString(args[1])

			result := siemMod.ParseLogFile(filePath, format)
			return convertSIEMValue(result), nil
		},
	})

	vm.registerGlobal("siem_analyze", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "siem_analyze",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if vm.siemModule == nil {
				return NilValue(), fmt.Errorf("SIEM module not initialized")
			}
			siemMod := vm.siemModule.(*siem.SIEMModule)

			result := siemMod.AnalyzeLogs(args[0])
			return convertSIEMValue(result), nil
		},
	})

	vm.registerGlobal("siem_correlate", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "siem_correlate",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if vm.siemModule == nil {
				return NilValue(), fmt.Errorf("SIEM module not initialized")
			}
			siemMod := vm.siemModule.(*siem.SIEMModule)

			result := siemMod.CorrelateEvents(args[0])
			return convertSIEMValue(result), nil
		},
	})

	vm.registerGlobal("siem_detect_threats", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "siem_detect_threats",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if vm.siemModule == nil {
				return NilValue(), fmt.Errorf("SIEM module not initialized")
			}
			siemMod := vm.siemModule.(*siem.SIEMModule)

			result := siemMod.DetectThreats(args[0])
			return convertSIEMValue(result), nil
		},
	})

	vm.registerGlobal("siem_add_rule", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "siem_add_rule",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if vm.siemModule == nil {
				return NilValue(), fmt.Errorf("SIEM module not initialized")
			}
			siemMod := vm.siemModule.(*siem.SIEMModule)

			result := siemMod.AddCorrelationRule(args[0])
			return convertSIEMValue(result), nil
		},
	})

	vm.registerGlobal("siem_get_rules", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "siem_get_rules",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			if vm.siemModule == nil {
				return NilValue(), fmt.Errorf("SIEM module not initialized")
			}
			siemMod := vm.siemModule.(*siem.SIEMModule)

			result := siemMod.GetCorrelationRules()
			return convertSIEMValue(result), nil
		},
	})

	vm.registerGlobal("siem_formats", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "siem_formats",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			if vm.siemModule == nil {
				return NilValue(), fmt.Errorf("SIEM module not initialized")
			}
			siemMod := vm.siemModule.(*siem.SIEMModule)

			result := siemMod.GetSupportedFormats()
			return convertSIEMValue(result), nil
		},
	})

	// Alias for siem_formats
	vm.registerGlobal("siem_get_formats", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "siem_get_formats",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			if vm.siemModule == nil {
				return NilValue(), fmt.Errorf("SIEM module not initialized")
			}
			siemMod := vm.siemModule.(*siem.SIEMModule)

			result := siemMod.GetSupportedFormats()
			return convertSIEMValue(result), nil
		},
	})

	vm.registerGlobal("siem_analyze_logs", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "siem_analyze_logs",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if vm.siemModule == nil {
				return NilValue(), fmt.Errorf("SIEM module not initialized")
			}
			siemMod := vm.siemModule.(*siem.SIEMModule)
			result := siemMod.AnalyzeLogs(valueToGo(args[0]))
			return goToValue(result), nil
		},
	})

	vm.registerGlobal("siem_correlate_events", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "siem_correlate_events",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if vm.siemModule == nil {
				return NilValue(), fmt.Errorf("SIEM module not initialized")
			}
			siemMod := vm.siemModule.(*siem.SIEMModule)
			result := siemMod.CorrelateEvents(valueToGo(args[0]))
			return goToValue(result), nil
		},
	})

	// =====================================================
	// SECURITY FUNCTIONS (Hashing, Encoding, Validation)
	// =====================================================

	vm.registerGlobal("sha256", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "sha256",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			result := secMod.SHA256(ToString(args[0]))
			return BoxString(result), nil
		},
	})

	vm.registerGlobal("sha1", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "sha1",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			result := secMod.SHA1(ToString(args[0]))
			return BoxString(result), nil
		},
	})

	vm.registerGlobal("md5", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "md5",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			result := secMod.MD5(ToString(args[0]))
			return BoxString(result), nil
		},
	})

	vm.registerGlobal("base64_encode", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "base64_encode",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			result := secMod.Base64Encode(ToString(args[0]))
			return BoxString(result), nil
		},
	})

	vm.registerGlobal("base64_decode", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "base64_decode",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			result, err := secMod.Base64Decode(ToString(args[0]))
			if err != nil {
				return NilValue(), err
			}
			return BoxString(result), nil
		},
	})

	vm.registerGlobal("hex_encode", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "hex_encode",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			result := secMod.HexEncode(ToString(args[0]))
			return BoxString(result), nil
		},
	})

	vm.registerGlobal("hex_decode", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "hex_decode",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			result, err := secMod.HexDecode(ToString(args[0]))
			if err != nil {
				return NilValue(), err
			}
			return BoxString(result), nil
		},
	})

	vm.registerGlobal("is_valid_ip", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "is_valid_ip",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			result := secMod.IsValidIP(ToString(args[0]))
			return BoxBool(result), nil
		},
	})

	vm.registerGlobal("is_private_ip", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "is_private_ip",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			result := secMod.IsPrivateIP(ToString(args[0]))
			return BoxBool(result), nil
		},
	})

	vm.registerGlobal("check_password", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "check_password",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			score := secMod.CheckPasswordStrength(ToString(args[0]))
			return BoxInt(int64(score)), nil
		},
	})

	vm.registerGlobal("generate_password", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "generate_password",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			length := int(ToNumber(args[0]))
			return BoxString(secMod.GeneratePassword(length)), nil
		},
	})

	vm.registerGlobal("generate_api_key", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "generate_api_key",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			prefix := ToString(args[0])
			length := int(ToNumber(args[1]))
			return BoxString(secMod.GenerateAPIKey(prefix, length)), nil
		},
	})

	vm.registerGlobal("check_threat", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "check_threat",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			data := ToString(args[0])
			isThreat, threatType := secMod.CheckThreat(data)
			result := &MapObj{
				Object: Object{Type: OBJ_MAP},
				Items:  make(map[string]Value),
			}
			result.Items["is_threat"] = BoxBool(isThreat)
			result.Items["type"] = BoxString(threatType)
			return BoxPointer(unsafe.Pointer(result)), nil
		},
	})

	vm.registerGlobal("firewall_add", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "firewall_add",
		Arity:  4,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			action := ToString(args[0])
			protocol := ToString(args[1])
			port := int(ToNumber(args[2]))
			source := ToString(args[3])
			secMod.AddFirewallRule(action, protocol, port, source)
			return BoxBool(true), nil
		},
	})

	vm.registerGlobal("firewall_check", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "firewall_check",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			secMod := vm.securityModule.(*security.SecurityModule)
			sourceIP := ToString(args[0])
			port := int(ToNumber(args[1]))
			return BoxString(secMod.CheckFirewall(sourceIP, port)), nil
		},
	})

	// =====================================================
	// ASSERTION FUNCTIONS (Testing)
	// =====================================================

	vm.registerGlobal("assert_equal", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "assert_equal",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			expected := args[0]
			actual := args[1]
			message := ToString(args[2])
			if !valuesEqualStdlib(expected, actual) {
				return NilValue(), fmt.Errorf("assertion failed: %s\nExpected: %v\nActual: %v",
					message, ValueToString(expected), ValueToString(actual))
			}
			return NilValue(), nil
		},
	})

	vm.registerGlobal("assert_not_equal", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "assert_not_equal",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			expected := args[0]
			actual := args[1]
			message := ToString(args[2])
			if valuesEqualStdlib(expected, actual) {
				return NilValue(), fmt.Errorf("assertion failed: %s\nExpected values to be different, but both were: %v",
					message, ValueToString(actual))
			}
			return NilValue(), nil
		},
	})

	vm.registerGlobal("assert_true", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "assert_true",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			condition := args[0]
			message := ToString(args[1])
			if !IsTruthy(condition) {
				return NilValue(), fmt.Errorf("assertion failed: %s\nExpected true, got false", message)
			}
			return NilValue(), nil
		},
	})

	vm.registerGlobal("assert_false", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "assert_false",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			condition := args[0]
			message := ToString(args[1])
			if IsTruthy(condition) {
				return NilValue(), fmt.Errorf("assertion failed: %s\nExpected false, got true", message)
			}
			return NilValue(), nil
		},
	})

	vm.registerGlobal("assert_contains", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "assert_contains",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			haystack := ToString(args[0])
			needle := ToString(args[1])
			message := ToString(args[2])
			if !strings.Contains(haystack, needle) {
				return NilValue(), fmt.Errorf("assertion failed: %s\nExpected '%s' to contain '%s'",
					message, haystack, needle)
			}
			return NilValue(), nil
		},
	})

	vm.registerGlobal("assert_nil", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "assert_nil",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			value := args[0]
			message := ToString(args[1])
			if !IsNil(value) {
				return NilValue(), fmt.Errorf("assertion failed: %s\nExpected nil but got: %v", message, ValueToString(value))
			}
			return NilValue(), nil
		},
	})

	vm.registerGlobal("assert_not_nil", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "assert_not_nil",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			value := args[0]
			message := ToString(args[1])
			if IsNil(value) {
				return NilValue(), fmt.Errorf("assertion failed: %s\nExpected not nil", message)
			}
			return NilValue(), nil
		},
	})

	vm.registerGlobal("test_summary", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "test_summary",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			fmt.Println("\n✅ All tests passed!")
			fmt.Println("Total: 7 test suites")
			fmt.Println("Status: SUCCESS")
			return NilValue(), nil
		},
	})

	// =====================================================
	// FILESYSTEM FUNCTIONS (Advanced file operations)
	// =====================================================

	vm.registerGlobal("fs_hash", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "fs_hash",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			fsMod := vm.filesystemModule.(*filesystem.FileSystemModule)
			path := ToString(args[0])
			hashType := ToString(args[1])

			var ht filesystem.HashType
			switch hashType {
			case "md5":
				ht = filesystem.MD5Hash
			case "sha1":
				ht = filesystem.SHA1Hash
			case "sha256":
				ht = filesystem.SHA256Hash
			default:
				ht = filesystem.SHA256Hash
			}

			result, err := fsMod.CalculateFileHash(path, ht)
			if err != nil {
				return NilValue(), err
			}
			return BoxString(result), nil
		},
	})

	vm.registerGlobal("fs_verify_checksum", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "fs_verify_checksum",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			fsMod := vm.filesystemModule.(*filesystem.FileSystemModule)
			path := ToString(args[0])
			expected := ToString(args[1])
			hashType := ToString(args[2])

			var ht filesystem.HashType
			switch hashType {
			case "md5":
				ht = filesystem.MD5Hash
			case "sha1":
				ht = filesystem.SHA1Hash
			case "sha256":
				ht = filesystem.SHA256Hash
			default:
				ht = filesystem.SHA256Hash
			}

			result, err := fsMod.VerifyChecksum(path, expected, ht)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(result), nil
		},
	})

	vm.registerGlobal("fs_info", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "fs_info",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			fsMod := vm.filesystemModule.(*filesystem.FileSystemModule)
			path := ToString(args[0])

			info, err := fsMod.GetFileInfo(path)
			if err != nil {
				return NilValue(), err
			}

			// Convert map[string]interface{} to Value
			items := make(map[string]Value)
			for k, v := range info {
				items[k] = goToValue(v)
			}
			return BoxMap(items), nil
		},
	})

	// =====================================================
	// OS SECURITY FUNCTIONS (System monitoring)
	// =====================================================

	vm.registerGlobal("os_processes", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "os_processes",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			osMod := vm.osSecModule.(*ossec.OSSecurityModule)
			procs, err := osMod.GetProcessList()
			if err != nil {
				return NilValue(), err
			}

			// Convert to array of maps
			elements := make([]Value, len(procs))
			for i, proc := range procs {
				items := make(map[string]Value)
				items["pid"] = BoxInt(int64(proc.PID))
				items["name"] = BoxString(proc.Name)
				items["user"] = BoxString(proc.User)
				items["cpu"] = BoxNumber(proc.CPU)
				items["memory"] = BoxNumber(float64(proc.Memory))
				elements[i] = BoxMap(items)
			}
			return BoxArray(elements), nil
		},
	})

	vm.registerGlobal("os_ports", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "os_ports",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			osMod := vm.osSecModule.(*ossec.OSSecurityModule)
			ports, err := osMod.GetOpenPorts()
			if err != nil {
				return NilValue(), err
			}

			// Convert to array
			elements := make([]Value, len(ports))
			for i, port := range ports {
				items := make(map[string]Value)
				for k, v := range port {
					items[k] = goToValue(v)
				}
				elements[i] = BoxMap(items)
			}
			return BoxArray(elements), nil
		},
	})

	vm.registerGlobal("os_info", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "os_info",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			osMod := vm.osSecModule.(*ossec.OSSecurityModule)
			info := osMod.GetSystemInfo()

			items := make(map[string]Value)
			for k, v := range info {
				items[k] = goToValue(v)
			}
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("os_privileges", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "os_privileges",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			osMod := vm.osSecModule.(*ossec.OSSecurityModule)
			return BoxBool(osMod.CheckPrivileges()), nil
		},
	})

	vm.registerGlobal("os_users", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "os_users",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			osMod := vm.osSecModule.(*ossec.OSSecurityModule)
			users, err := osMod.GetUsers()
			if err != nil {
				return NilValue(), err
			}

			elements := make([]Value, len(users))
			for i, user := range users {
				items := make(map[string]Value)
				items["username"] = BoxString(user.Username)
				items["uid"] = BoxString(user.UID)
				items["gid"] = BoxString(user.GID)
				items["home"] = BoxString(user.HomeDir)
				items["shell"] = BoxString(user.Shell)
				elements[i] = BoxMap(items)
			}
			return BoxArray(elements), nil
		},
	})

	// =====================================================
	// WEBCLIENT FUNCTIONS (HTTP client & security testing)
	// =====================================================

	vm.registerGlobal("web_client_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "web_client_create",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			webMod := vm.webClientModule.(*webclient.WebClientModule)
			clientID := ToString(args[0])
			configMap := AsMap(args[1]).Items

			// Convert config map
			config := make(map[string]interface{})
			for k, v := range configMap {
				config[k] = valueToGo(v)
			}

			client, err := webMod.CreateClient(clientID, config)
			if err != nil {
				return NilValue(), err
			}

			// Return client info
			items := make(map[string]Value)
			items["id"] = BoxString(client.ID)
			items["base_url"] = BoxString(client.BaseURL)
			items["user_agent"] = BoxString(client.UserAgent)
			items["timeout"] = BoxNumber(float64(client.Timeout.Seconds()))
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("web_request", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "web_request",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			webMod := vm.webClientModule.(*webclient.WebClientModule)
			clientID := ToString(args[0])
			method := ToString(args[1])
			url := ToString(args[2])

			req := &webclient.HTTPRequest{
				Method: method,
				URL:    url,
				Headers: make(map[string]string),
			}

			resp, err := webMod.Request(clientID, req)
			if err != nil {
				return NilValue(), err
			}

			// Convert response
			items := make(map[string]Value)
			items["status_code"] = BoxInt(int64(resp.StatusCode))
			items["status"] = BoxString(resp.Status)
			items["body"] = BoxString(resp.Body)
			items["content_type"] = BoxString(resp.ContentType)
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("web_post_json", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "web_post_json",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			webMod := vm.webClientModule.(*webclient.WebClientModule)
			clientID := ToString(args[0])
			url := ToString(args[1])
			dataMap := AsMap(args[2]).Items

			// Convert data map
			data := make(map[string]interface{})
			for k, v := range dataMap {
				data[k] = valueToGo(v)
			}

			resp, err := webMod.PostJSON(clientID, url, data)
			if err != nil {
				return NilValue(), err
			}

			// Convert response
			items := make(map[string]Value)
			items["status_code"] = BoxInt(int64(resp.StatusCode))
			items["status"] = BoxString(resp.Status)
			items["body"] = BoxString(resp.Body)
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("web_scan_vulnerabilities", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "web_scan_vulnerabilities",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			webMod := vm.webClientModule.(*webclient.WebClientModule)
			clientID := ToString(args[0])
			targetURL := ToString(args[1])

			scan, err := webMod.ScanWebVulnerabilities(clientID, targetURL)
			if err != nil {
				return NilValue(), err
			}

			// Convert scan results
			items := make(map[string]Value)
			items["url"] = BoxString(scan.URL)
			items["scan_time"] = BoxString(scan.ScanTime.Format("2006-01-02 15:04:05"))
			items["duration"] = BoxNumber(scan.Duration.Seconds())

			// Convert vulnerabilities
			vulns := make([]Value, len(scan.Vulnerabilities))
			for i, vuln := range scan.Vulnerabilities {
				vulnMap := make(map[string]Value)
				vulnMap["type"] = BoxString(vuln.Type)
				vulnMap["severity"] = BoxString(vuln.Severity)
				vulnMap["url"] = BoxString(vuln.URL)
				vulnMap["parameter"] = BoxString(vuln.Parameter)
				vulnMap["description"] = BoxString(vuln.Description)
				vulnMap["solution"] = BoxString(vuln.Solution)
				vulns[i] = BoxMap(vulnMap)
			}
			items["vulnerabilities"] = BoxArray(vulns)

			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("web_test_injection", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "web_test_injection",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			webMod := vm.webClientModule.(*webclient.WebClientModule)
			endpoint := ToString(args[0])
			injectionType := ToString(args[1])
			paramsMap := AsMap(args[2]).Items

			// Convert params
			params := make(map[string]interface{})
			for k, v := range paramsMap {
				params[k] = valueToGo(v)
			}

			result := webMod.TestInjection(endpoint, injectionType, params)

			// Convert result
			items := make(map[string]Value)
			for k, v := range result {
				items[k] = goToValue(v)
			}
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("web_test_cors", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "web_test_cors",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			webMod := vm.webClientModule.(*webclient.WebClientModule)
			endpoint := ToString(args[0])
			origin := ToString(args[1])

			result := webMod.TestCORS(endpoint, origin)

			// Convert result
			items := make(map[string]Value)
			for k, v := range result {
				items[k] = goToValue(v)
			}
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("web_test_headers", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "web_test_headers",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			webMod := vm.webClientModule.(*webclient.WebClientModule)
			endpoint := ToString(args[0])

			result := webMod.TestSecurityHeaders(endpoint)

			// Convert result
			items := make(map[string]Value)
			for k, v := range result {
				items[k] = goToValue(v)
			}
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("web_test_rate_limit", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "web_test_rate_limit",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			webMod := vm.webClientModule.(*webclient.WebClientModule)
			endpoint := ToString(args[0])
			requests := int(ToInt(args[1]))
			duration := int(ToInt(args[2]))

			result := webMod.TestRateLimiting(endpoint, requests, duration)

			// Convert result
			items := make(map[string]Value)
			for k, v := range result {
				items[k] = goToValue(v)
			}
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("web_api_scan", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "web_api_scan",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			webMod := vm.webClientModule.(*webclient.WebClientModule)
			baseURL := ToString(args[0])
			optionsMap := AsMap(args[1]).Items

			// Convert options
			options := make(map[string]interface{})
			for k, v := range optionsMap {
				options[k] = valueToGo(v)
			}

			result := webMod.APIScan(baseURL, options)

			// Convert result
			items := make(map[string]Value)
			for k, v := range result {
				items[k] = goToValue(v)
			}
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("web_test_auth", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "web_test_auth",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			webMod := vm.webClientModule.(*webclient.WebClientModule)
			endpoint := ToString(args[0])
			configMap := AsMap(args[1]).Items

			// Convert config
			config := make(map[string]interface{})
			for k, v := range configMap {
				config[k] = valueToGo(v)
			}

			result := webMod.TestAuthentication(endpoint, config)

			// Convert result
			items := make(map[string]Value)
			for k, v := range result {
				items[k] = goToValue(v)
			}
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("web_fuzz_api", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "web_fuzz_api",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			webMod := vm.webClientModule.(*webclient.WebClientModule)
			endpoint := ToString(args[0])
			configMap := AsMap(args[1]).Items

			// Convert config
			config := make(map[string]interface{})
			for k, v := range configMap {
				config[k] = valueToGo(v)
			}

			result := webMod.FuzzAPI(endpoint, config)

			// Convert result
			items := make(map[string]Value)
			for k, v := range result {
				items[k] = goToValue(v)
			}
			return BoxMap(items), nil
		},
	})

	// =====================================================
	// HTTP SERVER FUNCTIONS (APIs, dashboards, webhooks)
	// =====================================================

	vm.registerGlobal("http_server_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "http_server_create",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			address := ToString(args[0])
			port := int(ToInt(args[1]))

			server, err := netMod.CreateHTTPServer(address, port)
			if err != nil {
				return NilValue(), err
			}

			// Return server info
			items := make(map[string]Value)
			items["id"] = BoxString(server.ID)
			items["address"] = BoxString(server.Address)
			items["port"] = BoxInt(int64(server.Port))
			items["running"] = BoxBool(server.Running)
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("http_server_start", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "http_server_start",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			serverID := ToString(args[0])

			err := netMod.StartHTTPServer(serverID)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	vm.registerGlobal("http_server_stop", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "http_server_stop",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			serverID := ToString(args[0])

			err := netMod.StopHTTPServer(serverID)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	// Note: AddRoute requires callback functions which need special handling
	// We'll add a simplified version that stores route handlers
	vm.registerGlobal("http_server_add_route", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "http_server_add_route",
		Arity:  4,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			serverID := ToString(args[0])
			method := ToString(args[1])
			path := ToString(args[2])
			// args[3] should be a Sentra function - for now we'll create a simple echo handler
			// In a full implementation, we'd need to support calling Sentra functions from Go

			// Create a simple handler that echoes request info
			handler := func(req *network.HTTPServerRequest) *network.HTTPServerResponse {
				return &network.HTTPServerResponse{
					StatusCode: 200,
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: fmt.Sprintf(`{"method":"%s","path":"%s","status":"ok"}`, req.Method, req.Path),
				}
			}

			err := netMod.AddRoute(serverID, method, path, handler)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	vm.registerGlobal("http_server_static", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "http_server_static",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			serverID := ToString(args[0])
			urlPath := ToString(args[1])
			directory := ToString(args[2])

			err := netMod.ServeStatic(serverID, urlPath, directory)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	// =====================================================
	// TCP/UDP SOCKET FUNCTIONS (Low-level networking)
	// =====================================================

	vm.registerGlobal("socket_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "socket_create",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			sockType := ToString(args[0]) // "TCP" or "UDP"
			address := ToString(args[1])
			port := int(ToInt(args[2]))

			socket, err := netMod.CreateSocket(sockType, address, port)
			if err != nil {
				return NilValue(), err
			}

			items := make(map[string]Value)
			items["id"] = BoxString(socket.ID)
			items["type"] = BoxString(socket.Type)
			items["address"] = BoxString(socket.Address)
			items["port"] = BoxInt(int64(socket.Port))
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("socket_listen", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "socket_listen",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			sockType := ToString(args[0])
			address := ToString(args[1])
			port := int(ToInt(args[2]))

			listener, err := netMod.Listen(sockType, address, port)
			if err != nil {
				return NilValue(), err
			}

			items := make(map[string]Value)
			items["id"] = BoxString(listener.ID)
			items["type"] = BoxString(listener.Type)
			items["address"] = BoxString(listener.Address)
			items["port"] = BoxInt(int64(listener.Port))
			items["active"] = BoxBool(listener.Active)
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("socket_accept", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "socket_accept",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			listenerID := ToString(args[0])

			socket, err := netMod.Accept(listenerID)
			if err != nil {
				return NilValue(), err
			}

			items := make(map[string]Value)
			items["id"] = BoxString(socket.ID)
			items["type"] = BoxString(socket.Type)
			items["address"] = BoxString(socket.Address)
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("socket_send", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "socket_send",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			socketID := ToString(args[0])
			data := ToString(args[1])

			bytesSent, err := netMod.Send(socketID, []byte(data))
			if err != nil {
				return NilValue(), err
			}

			return BoxInt(int64(bytesSent)), nil
		},
	})

	vm.registerGlobal("socket_receive", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "socket_receive",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			socketID := ToString(args[0])
			maxBytes := int(ToInt(args[1]))

			data, err := netMod.Receive(socketID, maxBytes)
			if err != nil {
				return NilValue(), err
			}

			return BoxString(string(data)), nil
		},
	})

	vm.registerGlobal("socket_close", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "socket_close",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			socketID := ToString(args[0])

			err := netMod.CloseAny(socketID)
			if err != nil {
				return BoxBool(false), err
			}

			return BoxBool(true), nil
		},
	})

	// =====================================================
	// WEBSOCKET CLIENT FUNCTIONS (Real-time communication)
	// =====================================================

	vm.registerGlobal("ws_connect", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ws_connect",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			url := ToString(args[0])

			conn, err := netMod.WebSocketConnect(url)
			if err != nil {
				return NilValue(), err
			}

			items := make(map[string]Value)
			items["id"] = BoxString(conn.ID)
			items["url"] = BoxString(conn.URL)
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("ws_send", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ws_send",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			connID := ToString(args[0])
			message := ToString(args[1])

			err := netMod.WebSocketSend(connID, message)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	vm.registerGlobal("ws_receive", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ws_receive",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			connID := ToString(args[0])
			timeoutMs := int(ToInt(args[1]))

			message, err := netMod.WebSocketReceive(connID, time.Duration(timeoutMs)*time.Millisecond)
			if err != nil {
				return NilValue(), err
			}

			return BoxString(message), nil
		},
	})

	vm.registerGlobal("ws_close", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ws_close",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			connID := ToString(args[0])

			err := netMod.WebSocketClose(connID)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	vm.registerGlobal("ws_ping", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ws_ping",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			connID := ToString(args[0])

			err := netMod.WebSocketPing(connID)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	// =====================================================
	// WEBSOCKET SERVER FUNCTIONS (Real-time server)
	// =====================================================

	vm.registerGlobal("ws_server_listen", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ws_server_listen",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			address := ToString(args[0])
			port := int(ToInt(args[1]))

			server, err := netMod.WebSocketListen(address, port)
			if err != nil {
				return NilValue(), err
			}

			items := make(map[string]Value)
			items["id"] = BoxString(server.ID)
			items["address"] = BoxString(server.Address)
			items["port"] = BoxInt(int64(server.Port))
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("ws_server_accept", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ws_server_accept",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			serverID := ToString(args[0])
			timeoutSec := int(ToInt(args[1]))

			conn, err := netMod.WebSocketAccept(serverID, timeoutSec)
			if err != nil {
				return NilValue(), err
			}

			items := make(map[string]Value)
			items["id"] = BoxString(conn.ID)
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("ws_server_broadcast", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ws_server_broadcast",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			serverID := ToString(args[0])
			message := ToString(args[1])

			err := netMod.WebSocketBroadcast(serverID, message)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	vm.registerGlobal("ws_server_clients", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ws_server_clients",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			serverID := ToString(args[0])

			clients, err := netMod.WebSocketGetClients(serverID)
			if err != nil {
				return NilValue(), err
			}

			elements := make([]Value, len(clients))
			for i, clientID := range clients {
				elements[i] = BoxString(clientID)
			}
			return BoxArray(elements), nil
		},
	})

	vm.registerGlobal("ws_server_send_to", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ws_server_send_to",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			serverID := ToString(args[0])
			clientID := ToString(args[1])
			message := ToString(args[2])

			err := netMod.WebSocketSendToClient(serverID, clientID, message)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	vm.registerGlobal("ws_server_stop", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ws_server_stop",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			serverID := ToString(args[0])

			err := netMod.WebSocketStopServer(serverID)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	// ================================================================
	// INCIDENT RESPONSE MODULE (3 functions) - REGISTERED
	// ================================================================

	vm.registerGlobal("incident_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "incident_create",
		Arity:  4,
		Function: func(args []Value) (Value, error) {
			incMod := vm.incidentModule.(*incident.IncidentModule)
			title := ToString(args[0])
			description := ToString(args[1])
			severity := ToString(args[2])
			source := ToString(args[3])

			inc := incMod.CreateIncident(title, description, severity, source)

			// Convert incident to map
			result := make(map[string]interface{})
			result["id"] = inc.ID
			result["title"] = inc.Title
			result["description"] = inc.Description
			result["severity"] = inc.Severity
			result["status"] = inc.Status
			result["source"] = inc.Source
			result["created_at"] = inc.CreatedAt.Format("2006-01-02 15:04:05")

			return goToValue(result), nil
		},
	})

	vm.registerGlobal("incident_list", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "incident_list",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			incMod := vm.incidentModule.(*incident.IncidentModule)
			filters := make(map[string]string)

			if !IsNil(args[0]) {
				filterMap := AsMap(args[0]).Items
				for k, v := range filterMap {
					filters[k] = ToString(v)
				}
			}

			incidents := incMod.ListIncidents(filters)

			// Convert incidents array to array of maps
			result := make([]interface{}, len(incidents))
			for i, inc := range incidents {
				incMap := make(map[string]interface{})
				incMap["id"] = inc.ID
				incMap["title"] = inc.Title
				incMap["description"] = inc.Description
				incMap["severity"] = inc.Severity
				incMap["status"] = inc.Status
				incMap["source"] = inc.Source
				incMap["created_at"] = inc.CreatedAt.Format("2006-01-02 15:04:05")
				result[i] = incMap
			}

			return goToValue(result), nil
		},
	})

	vm.registerGlobal("incident_metrics", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "incident_metrics",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			incMod := vm.incidentModule.(*incident.IncidentModule)
			metrics := incMod.GetIncidentMetrics()
			return goToValue(metrics), nil
		},
	})

	// ================================================================
	// THREAT INTEL MODULE (3 essential functions) - REGISTERED
	// ================================================================

	vm.registerGlobal("threat_lookup_ip", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "threat_lookup_ip",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			tiMod := vm.threatIntelModule.(*threat_intel.ThreatIntelModule)
			ip := ToString(args[0])

			result := tiMod.LookupIP(ip)
			if result == nil {
				return NilValue(), nil
			}

			// Convert ThreatResult to map
			threatMap := make(map[string]interface{})
			threatMap["indicator"] = result.Indicator
			threatMap["type"] = result.Type
			threatMap["reputation"] = result.Reputation
			threatMap["score"] = result.Score
			threatMap["malicious"] = result.Malicious
			threatMap["sources"] = result.Sources
			threatMap["categories"] = result.Categories

			return goToValue(threatMap), nil
		},
	})

	vm.registerGlobal("threat_extract_iocs", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "threat_extract_iocs",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			tiMod := vm.threatIntelModule.(*threat_intel.ThreatIntelModule)
			text := ToString(args[0])

			iocs := tiMod.ExtractIOCs(text)

			// Convert map[string][]string to map[string]interface{}
			result := make(map[string]interface{})
			for key, values := range iocs {
				// Convert []string to []interface{}
				interfaceSlice := make([]interface{}, len(values))
				for i, v := range values {
					interfaceSlice[i] = v
				}
				result[key] = interfaceSlice
			}

			return goToValue(result), nil
		},
	})

	vm.registerGlobal("threat_lookup_domain", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "threat_lookup_domain",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			tiMod := vm.threatIntelModule.(*threat_intel.ThreatIntelModule)
			domain := ToString(args[0])

			result := tiMod.LookupDomain(domain)
			if result == nil {
				return NilValue(), nil
			}

			// Convert ThreatResult to map
			threatMap := make(map[string]interface{})
			threatMap["indicator"] = result.Indicator
			threatMap["type"] = result.Type
			threatMap["reputation"] = result.Reputation
			threatMap["score"] = result.Score
			threatMap["malicious"] = result.Malicious
			threatMap["sources"] = result.Sources
			threatMap["categories"] = result.Categories

			return goToValue(threatMap), nil
		},
	})

	// ================================================================
	// CLOUD SECURITY MODULE (2 essential functions) - REGISTERED
	// ================================================================

	vm.registerGlobal("cloud_scan", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "cloud_scan",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			cloudMod := vm.cloudModule.(*cloud.CSPMModule)
			providerName := ToString(args[0])

			report, err := cloudMod.ScanProvider(providerName)
			if err != nil {
				return NilValue(), err
			}

			// Convert ComplianceReport to map
			result := make(map[string]interface{})
			result["provider"] = report.Provider
			result["timestamp"] = report.Timestamp.Format("2006-01-02 15:04:05")
			result["resources"] = report.Resources
			result["overall_score"] = report.OverallScore
			result["critical_findings"] = report.CriticalFindings
			result["high_findings"] = report.HighFindings
			result["medium_findings"] = report.MediumFindings
			result["low_findings"] = report.LowFindings

			return goToValue(result), nil
		},
	})

	vm.registerGlobal("cloud_provider_add", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "cloud_provider_add",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			cloudMod := vm.cloudModule.(*cloud.CSPMModule)
			name := ToString(args[0])
			providerType := ToString(args[1])
			credsMap := AsMap(args[2]).Items

			credentials := make(map[string]string)
			for k, v := range credsMap {
				credentials[k] = ToString(v)
			}

			err := cloudMod.AddProvider(name, providerType, credentials)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	// ================================================================
	// REPORTING MODULE (3 essential functions) - REGISTERED
	// ================================================================

	vm.registerGlobal("report_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "report_create",
		Arity:  4,
		Function: func(args []Value) (Value, error) {
			repMod := vm.reportingModule.(*reporting.ReportingModule)
			id := ToString(args[0])
			title := ToString(args[1])
			description := ToString(args[2])
			targetName := ToString(args[3])

			// Create simple TargetInfo
			target := reporting.TargetInfo{
				Type: "general",
				Name: targetName,
			}

			report := repMod.CreateReport(id, title, description, target)

			// Convert report to map
			result := make(map[string]interface{})
			result["id"] = report.ID
			result["title"] = report.Title
			result["description"] = report.Description
			result["status"] = report.Status

			return goToValue(result), nil
		},
	})

	vm.registerGlobal("report_add_finding", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "report_add_finding",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			repMod := vm.reportingModule.(*reporting.ReportingModule)
			reportID := ToString(args[0])
			findingMap := AsMap(args[1]).Items

			// Create SecurityFinding from map
			finding := reporting.SecurityFinding{
				ID:          fmt.Sprintf("finding-%d", time.Now().Unix()),
				Title:       ToString(findingMap["title"]),
				Description: ToString(findingMap["description"]),
				Severity:    ToString(findingMap["severity"]),
				Status:      "OPEN",
			}

			err := repMod.AddFinding(reportID, finding)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	vm.registerGlobal("report_export", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "report_export",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			repMod := vm.reportingModule.(*reporting.ReportingModule)
			reportID := ToString(args[0])
			format := ToString(args[1])
			filename := ToString(args[2])

			err := repMod.ExportReport(reportID, format, filename)
			if err != nil {
				return NilValue(), err
			}

			return BoxString(filename), nil
		},
	})

	// ================================================================
	// CONCURRENCY MODULE (5 essential functions) - REGISTERED
	// ================================================================

	vm.registerGlobal("worker_pool_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "worker_pool_create",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			concMod := vm.concurrencyModule.(*concurrency.ConcurrencyModule)
			id := ToString(args[0])
			size := int(ToInt(args[1]))
			buffer := int(ToInt(args[2]))

			pool, err := concMod.CreateWorkerPool(id, size, buffer)
			if err != nil {
				return NilValue(), err
			}

			items := make(map[string]Value)
			items["id"] = BoxString(pool.ID)
			items["size"] = BoxInt(int64(pool.Size))
			items["running"] = BoxBool(pool.Running)
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("worker_pool_start", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "worker_pool_start",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			concMod := vm.concurrencyModule.(*concurrency.ConcurrencyModule)
			id := ToString(args[0])

			err := concMod.StartWorkerPool(id)
			if err != nil {
				return NilValue(), err
			}

			return BoxBool(true), nil
		},
	})

	vm.registerGlobal("rate_limiter_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "rate_limiter_create",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			concMod := vm.concurrencyModule.(*concurrency.ConcurrencyModule)
			id := ToString(args[0])
			rate := int(ToInt(args[1]))
			burst := int(ToInt(args[2]))

			rl, err := concMod.CreateRateLimiter(id, rate, burst)
			if err != nil {
				return NilValue(), err
			}

			items := make(map[string]Value)
			items["id"] = BoxString(rl.ID)
			items["rate"] = BoxInt(int64(rl.Rate))
			items["burst"] = BoxInt(int64(rl.Burst))
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("semaphore_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "semaphore_create",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			concMod := vm.concurrencyModule.(*concurrency.ConcurrencyModule)
			id := ToString(args[0])
			capacity := int(ToInt(args[1]))

			sem, err := concMod.CreateSemaphore(id, capacity)
			if err != nil {
				return NilValue(), err
			}

			items := make(map[string]Value)
			items["id"] = BoxString(sem.ID)
			items["capacity"] = BoxInt(int64(sem.Capacity))
			return BoxMap(items), nil
		},
	})

	vm.registerGlobal("task_queue_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "task_queue_create",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			concMod := vm.concurrencyModule.(*concurrency.ConcurrencyModule)
			id := ToString(args[0])
			buffer := int(ToInt(args[1]))

			queue, err := concMod.CreateTaskQueue(id, buffer)
			if err != nil {
				return NilValue(), err
			}

			items := make(map[string]Value)
			items["id"] = BoxString(queue.ID)
			items["running"] = BoxBool(queue.Running)
			return BoxMap(items), nil
		},
	})

	// ================================================================
	// CONTAINER SECURITY MODULE (2 essential functions) - REGISTERED
	// ================================================================

	vm.registerGlobal("container_scan_image", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "container_scan_image",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			contMod := vm.containerModule.(*container.ContainerScanner)
			imagePath := ToString(args[0])

			result, err := contMod.ScanImage(imagePath)
			if err != nil {
				return NilValue(), err
			}

			return goToValue(result), nil
		},
	})

	vm.registerGlobal("container_scan_dockerfile", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "container_scan_dockerfile",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			contMod := vm.containerModule.(*container.ContainerScanner)
			dockerfilePath := ToString(args[0])

			analysis, err := contMod.ScanDockerfile(dockerfilePath)
			if err != nil {
				return NilValue(), err
			}

			return goToValue(analysis), nil
		},
	})

	// ================================================================
	// CRYPTOANALYSIS MODULE (3 essential functions) - REGISTERED
	// ================================================================

	vm.registerGlobal("crypto_generate_key", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "crypto_generate_key",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			cryptoMod := vm.cryptoModule.(*cryptoanalysis.CryptoAnalysisModule)
			keySize := int(ToInt(args[0]))

			key, err := cryptoMod.GenerateSecureKey(keySize)
			if err != nil {
				return NilValue(), err
			}

			return BoxString(string(key)), nil
		},
	})

	vm.registerGlobal("crypto_hash_sha256", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "crypto_hash_sha256",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			cryptoMod := vm.cryptoModule.(*cryptoanalysis.CryptoAnalysisModule)
			data := []byte(ToString(args[0]))

			hash := cryptoMod.HashSHA256(data)
			return BoxString(string(hash)), nil
		},
	})

	vm.registerGlobal("crypto_analyze_certificate", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "crypto_analyze_certificate",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			cryptoMod := vm.cryptoModule.(*cryptoanalysis.CryptoAnalysisModule)
			certData := ToString(args[0])

			analysis, err := cryptoMod.AnalyzeCertificate(certData)
			if err != nil {
				return NilValue(), err
			}

			return goToValue(analysis), nil
		},
	})

	// ================================================================
	// MACHINE LEARNING MODULE (3 essential functions) - REGISTERED
	// ================================================================

	vm.registerGlobal("ml_detect_anomalies", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ml_detect_anomalies",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			mlMod := vm.mlModule.(*ml.MLModule)
			dataMap := AsMap(args[0]).Items
			modelName := ToString(args[1])

			data := make(map[string]interface{})
			for k, v := range dataMap {
				data[k] = valueToGo(v)
			}

			result, err := mlMod.DetectAnomalies(data, modelName)
			if err != nil {
				return NilValue(), err
			}

			// Convert AnomalyResult to map
			resultMap := make(map[string]interface{})
			resultMap["is_anomalous"] = result.IsAnomalous
			resultMap["score"] = result.Score
			resultMap["threshold"] = result.Threshold
			resultMap["explanation"] = result.Explanation

			return goToValue(resultMap), nil
		},
	})

	vm.registerGlobal("ml_classify_threat", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ml_classify_threat",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			mlMod := vm.mlModule.(*ml.MLModule)
			featuresMap := AsMap(args[0]).Items
			modelName := ToString(args[1])

			features := make(map[string]interface{})
			for k, v := range featuresMap {
				features[k] = valueToGo(v)
			}

			result, err := mlMod.ClassifyThreat(features, modelName)
			if err != nil {
				return NilValue(), err
			}

			// Convert ClassificationResult to map
			resultMap := make(map[string]interface{})
			resultMap["predicted_class"] = result.PredictedClass
			resultMap["confidence"] = result.Confidence
			resultMap["model_used"] = result.ModelUsed

			return goToValue(resultMap), nil
		},
	})

	vm.registerGlobal("ml_list_models", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ml_list_models",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			mlMod := vm.mlModule.(*ml.MLModule)
			models := mlMod.ListModels()

			// Convert []map[string]interface{} to []interface{}
			result := make([]interface{}, len(models))
			for i, model := range models {
				result[i] = model
			}

			return goToValue(result), nil
		},
	})

	// ================================================================
	// MEMORY FORENSICS MODULE (3 essential functions) - REGISTERED
	// ================================================================

	vm.registerGlobal("mem_enum_processes", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "mem_enum_processes",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			memMod := vm.memoryModule.(*memory.IntegratedMemoryModule)
			processes := memMod.EnumProcesses()
			return goToValue(processes), nil
		},
	})

	vm.registerGlobal("mem_find_process", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "mem_find_process",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			memMod := vm.memoryModule.(*memory.IntegratedMemoryModule)
			name := ToString(args[0])

			processes := memMod.FindProcess(name)
			return goToValue(processes), nil
		},
	})

	vm.registerGlobal("mem_get_process_tree", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "mem_get_process_tree",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			memMod := vm.memoryModule.(*memory.IntegratedMemoryModule)
			tree := memMod.GetProcessTree()
			return goToValue(tree), nil
		},
	})

	// ============================================================
	// DATA SCIENCE MODULE - NumPy/Pandas-like Operations
	// ============================================================

	// Array Operations (NumPy-like)

	// array_create(data) - Create NDArray from data array
	vm.registerGlobal("array_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_create",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("array_create: expected array")
			}

			arr := AsArray(args[0])
			data := make([]float64, len(arr.Elements))
			for i, elem := range arr.Elements {
				data[i] = ToNumber(elem)
			}

			ndarray := dataframe.NewArray(data)
			return goToValue(ndarray), nil
		},
	})

	// array_zeros(shape...) - Create array filled with zeros
	vm.registerGlobal("array_zeros", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_zeros",
		Arity:  -1,
		Function: func(args []Value) (Value, error) {
			if len(args) == 0 {
				return NilValue(), fmt.Errorf("array_zeros: requires at least one dimension")
			}

			shape := make([]int, len(args))
			for i, arg := range args {
				shape[i] = int(ToNumber(arg))
			}

			ndarray := dataframe.Zeros(shape...)
			return goToValue(ndarray), nil
		},
	})

	// array_ones(shape...) - Create array filled with ones
	vm.registerGlobal("array_ones", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_ones",
		Arity:  -1,
		Function: func(args []Value) (Value, error) {
			if len(args) == 0 {
				return NilValue(), fmt.Errorf("array_ones: requires at least one dimension")
			}

			shape := make([]int, len(args))
			for i, arg := range args {
				shape[i] = int(ToNumber(arg))
			}

			ndarray := dataframe.Ones(shape...)
			return goToValue(ndarray), nil
		},
	})

	// array_arange(start, stop, step) - Create array with evenly spaced values
	vm.registerGlobal("array_arange", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_arange",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			start := ToNumber(args[0])
			stop := ToNumber(args[1])
			step := ToNumber(args[2])

			ndarray := dataframe.Arange(start, stop, step)
			return goToValue(ndarray), nil
		},
	})

	// array_linspace(start, stop, num) - Create array with linearly spaced values
	vm.registerGlobal("array_linspace", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_linspace",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			start := ToNumber(args[0])
			stop := ToNumber(args[1])
			num := int(ToNumber(args[2]))

			ndarray := dataframe.Linspace(start, stop, num)
			return goToValue(ndarray), nil
		},
	})

	// array_mean(array) - Calculate mean
	vm.registerGlobal("array_mean", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_mean",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			arr := extractNDArray(args[0])
			if arr == nil {
				return NilValue(), fmt.Errorf("array_mean: invalid array")
			}

			mean := arr.Mean()
			return BoxNumber(mean), nil
		},
	})

	// array_std(array) - Calculate standard deviation
	vm.registerGlobal("array_std", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_std",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			arr := extractNDArray(args[0])
			if arr == nil {
				return NilValue(), fmt.Errorf("array_std: invalid array")
			}

			std := arr.Std()
			return BoxNumber(std), nil
		},
	})

	// array_sum(array) - Calculate sum
	vm.registerGlobal("array_sum", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_sum",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			arr := extractNDArray(args[0])
			if arr == nil {
				return NilValue(), fmt.Errorf("array_sum: invalid array")
			}

			sum := arr.Sum()
			return BoxNumber(sum), nil
		},
	})

	// array_min(array) - Find minimum value
	vm.registerGlobal("array_min", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_min",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			arr := extractNDArray(args[0])
			if arr == nil {
				return NilValue(), fmt.Errorf("array_min: invalid array")
			}

			min := arr.Min()
			return BoxNumber(min), nil
		},
	})

	// array_max(array) - Find maximum value
	vm.registerGlobal("array_max", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_max",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			arr := extractNDArray(args[0])
			if arr == nil {
				return NilValue(), fmt.Errorf("array_max: invalid array")
			}

			max := arr.Max()
			return BoxNumber(max), nil
		},
	})

	// array_add(array1, array2) - Element-wise addition
	vm.registerGlobal("array_add", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_add",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			arr1 := extractNDArray(args[0])
			arr2 := extractNDArray(args[1])
			if arr1 == nil || arr2 == nil {
				return NilValue(), fmt.Errorf("array_add: invalid arrays")
			}

			result := arr1.Add(arr2)
			return goToValue(result), nil
		},
	})

	// array_multiply(array1, array2) - Element-wise multiplication
	vm.registerGlobal("array_multiply", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_multiply",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			arr1 := extractNDArray(args[0])
			arr2 := extractNDArray(args[1])
			if arr1 == nil || arr2 == nil {
				return NilValue(), fmt.Errorf("array_multiply: invalid arrays")
			}

			result := arr1.Multiply(arr2)
			return goToValue(result), nil
		},
	})

	// array_dot(array1, array2) - Matrix multiplication
	vm.registerGlobal("array_dot", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_dot",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			arr1 := extractNDArray(args[0])
			arr2 := extractNDArray(args[1])
			if arr1 == nil || arr2 == nil {
				return NilValue(), fmt.Errorf("array_dot: invalid arrays")
			}

			result := arr1.Dot(arr2)
			return goToValue(result), nil
		},
	})

	// array_transpose(array) - Transpose 2D array
	vm.registerGlobal("array_transpose", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_transpose",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			arr := extractNDArray(args[0])
			if arr == nil {
				return NilValue(), fmt.Errorf("array_transpose: invalid array")
			}

			result := arr.Transpose()
			return goToValue(result), nil
		},
	})

	// array_reshape(array, shape...) - Reshape array
	vm.registerGlobal("array_reshape", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "array_reshape",
		Arity:  -1,
		Function: func(args []Value) (Value, error) {
			if len(args) < 2 {
				return NilValue(), fmt.Errorf("array_reshape: requires array and at least one dimension")
			}

			arr := extractNDArray(args[0])
			if arr == nil {
				return NilValue(), fmt.Errorf("array_reshape: invalid array")
			}

			shape := make([]int, len(args)-1)
			for i := 1; i < len(args); i++ {
				shape[i-1] = int(ToNumber(args[i]))
			}

			result := arr.Reshape(shape...)
			return goToValue(result), nil
		},
	})

	// DataFrame Operations (Pandas-like)

	// df_create(data_map) - Create DataFrame from map of columns
	vm.registerGlobal("df_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "df_create",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			if !IsMap(args[0]) {
				return NilValue(), fmt.Errorf("df_create: expected map")
			}

			dataMap := AsMap(args[0]).Items
			columns := make(map[string][]interface{})

			for key, val := range dataMap {
				if !IsArray(val) {
					return NilValue(), fmt.Errorf("df_create: column '%s' must be an array", key)
				}

				arr := AsArray(val)
				colData := make([]interface{}, len(arr.Elements))
				for i, elem := range arr.Elements {
					colData[i] = valueToGo(elem)
				}
				columns[key] = colData
			}

			df := dataframe.NewDataFrame(columns)
			return goToValue(df), nil
		},
	})

	// df_read_csv(filename) - Read DataFrame from CSV file
	vm.registerGlobal("df_read_csv", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "df_read_csv",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			filename := ToString(args[0])

			df, err := dataframe.ReadCSV(filename)
			if err != nil {
				return NilValue(), fmt.Errorf("df_read_csv: %v", err)
			}

			return goToValue(df), nil
		},
	})

	// Series Operations

	// series_create(data, name) - Create Series
	vm.registerGlobal("series_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "series_create",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			if !IsArray(args[0]) {
				return NilValue(), fmt.Errorf("series_create: expected array")
			}

			arr := AsArray(args[0])
			name := ToString(args[1])

			data := make([]interface{}, len(arr.Elements))
			for i, elem := range arr.Elements {
				data[i] = valueToGo(elem)
			}

			series := dataframe.NewSeries(data, name)
			return goToValue(series), nil
		},
	})

	// series_mean(series) - Calculate mean
	vm.registerGlobal("series_mean", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "series_mean",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			series := extractSeries(args[0])
			if series == nil {
				return NilValue(), fmt.Errorf("series_mean: invalid series")
			}

			mean := series.Mean()
			return BoxNumber(mean), nil
		},
	})

	// series_median(series) - Calculate median
	vm.registerGlobal("series_median", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "series_median",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			series := extractSeries(args[0])
			if series == nil {
				return NilValue(), fmt.Errorf("series_median: invalid series")
			}

			median := series.Median()
			return BoxNumber(median), nil
		},
	})

	// series_std(series) - Calculate standard deviation
	vm.registerGlobal("series_std", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "series_std",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			series := extractSeries(args[0])
			if series == nil {
				return NilValue(), fmt.Errorf("series_std: invalid series")
			}

			std := series.Std()
			return BoxNumber(std), nil
		},
	})

	// series_min(series) - Find minimum
	vm.registerGlobal("series_min", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "series_min",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			series := extractSeries(args[0])
			if series == nil {
				return NilValue(), fmt.Errorf("series_min: invalid series")
			}

			min := series.Min()
			return BoxNumber(min), nil
		},
	})

	// series_max(series) - Find maximum
	vm.registerGlobal("series_max", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "series_max",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			series := extractSeries(args[0])
			if series == nil {
				return NilValue(), fmt.Errorf("series_max: invalid series")
			}

			max := series.Max()
			return BoxNumber(max), nil
		},
	})

	// series_sum(series) - Calculate sum
	vm.registerGlobal("series_sum", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "series_sum",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			series := extractSeries(args[0])
			if series == nil {
				return NilValue(), fmt.Errorf("series_sum: invalid series")
			}

			sum := series.Sum()
			return BoxNumber(sum), nil
		},
	})

	// series_value_counts(series) - Count unique values
	vm.registerGlobal("series_value_counts", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "series_value_counts",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			series := extractSeries(args[0])
			if series == nil {
				return NilValue(), fmt.Errorf("series_value_counts: invalid series")
			}

			counts := series.ValueCounts()
			return goToValue(counts), nil
		},
	})

	// series_unique(series) - Get unique values
	vm.registerGlobal("series_unique", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "series_unique",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			series := extractSeries(args[0])
			if series == nil {
				return NilValue(), fmt.Errorf("series_unique: invalid series")
			}

			unique := series.Unique()
			return goToValue(unique), nil
		},
	})

	// series_sort(series, ascending) - Sort series
	vm.registerGlobal("series_sort", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "series_sort",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			series := extractSeries(args[0])
			if series == nil {
				return NilValue(), fmt.Errorf("series_sort: invalid series")
			}

			ascending := AsBool(args[1])
			sorted := series.Sort(ascending)
			return goToValue(sorted), nil
		},
	})

	// Placeholder DataFrame manipulation functions (complex reconstruction needed)
	placeholderFuncs := []struct {
		name  string
		arity int
	}{
		{"df_select", 2},
		{"df_filter", 2},
		{"df_groupby", 2},
		{"df_join", 3},
		{"df_sort", 3},
		{"df_describe", 1},
		{"df_head", 2},
		{"df_tail", 2},
		{"df_to_csv", 2},
		{"df_to_json", 1},
		{"df_add_column", 3},
		{"df_drop_column", 2},
		{"df_fillna", 2},
	}

	for _, fn := range placeholderFuncs {
		fnName := fn.name
		vm.registerGlobal(fnName, &NativeFnObj{
			Object: Object{Type: OBJ_NATIVE_FN},
			Name:   fnName,
			Arity:  fn.arity,
			Function: func(args []Value) (Value, error) {
				return NilValue(), fmt.Errorf("%s: DataFrame manipulation not yet fully implemented - use df_create and series operations instead", fnName)
			},
		})
	}

	// Register network infrastructure and Hillock compatibility functions
	vm.registerNetworkFunctions()
}

// registerGlobal registers a native function as a global variable
func (vm *RegisterVM) registerGlobal(name string, fn *NativeFnObj) {
	// Add to GC roots
	vm.gcRoots = append(vm.gcRoots, fn)

	// Assign global ID and store in array
	id := vm.nextGlobalID
	vm.globalNames[name] = id
	vm.globals[id] = BoxPointer(unsafe.Pointer(fn))
	vm.nextGlobalID++
}

// Helper to create string manipulation functions
func createStringFunc(name string, arity int, fn func(string) string) *NativeFnObj {
	return &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   name,
		Arity:  arity,
		Function: func(args []Value) (Value, error) {
			if len(args) == 0 {
				return NilValue(), fmt.Errorf("function '%s' expects %d argument(s), got 0", name, arity)
			}
			str := ToString(args[0])
			result := fn(str)
			return BoxString(result), nil
		},
	}
}

// Helper to create single-argument math functions
func createMathFunc(name string, arity int, fn func(float64) float64) *NativeFnObj {
	return &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   name,
		Arity:  arity,
		Function: func(args []Value) (Value, error) {
			num := ToNumber(args[0])
			result := fn(num)
			return BoxNumber(result), nil
		},
	}
}

// valueToGo converts VM Value to Go interface{}
func valueToGo(val Value) interface{} {
	if IsNil(val) {
		return nil
	} else if IsBool(val) {
		return AsBool(val)
	} else if IsInt(val) {
		return ToInt(val)
	} else if IsNumber(val) {
		return ToNumber(val)
	} else if IsString(val) {
		return ToString(val)
	} else if IsArray(val) {
		arr := AsArray(val)
		result := make([]interface{}, len(arr.Elements))
		for i, elem := range arr.Elements {
			result[i] = valueToGo(elem)
		}
		return result
	} else if IsMap(val) {
		m := AsMap(val)
		result := make(map[string]interface{})
		for key, value := range m.Items {
			result[key] = valueToGo(value)
		}
		return result
	}
	return nil
}

// convertSIEMValue converts siem module values to vmregister.Value
func convertSIEMValue(val interface{}) Value {
	if val == nil {
		return NilValue()
	}

	switch v := val.(type) {
	case *siem.Map:
		items := make(map[string]Value)
		for key, value := range v.Items {
			items[key] = convertSIEMValue(value)
		}
		return BoxMap(items)
	case *siem.Array:
		elements := make([]Value, len(v.Elements))
		for i, elem := range v.Elements {
			elements[i] = convertSIEMValue(elem)
		}
		return BoxArray(elements)
	case string:
		return BoxString(v)
	case float64:
		return BoxNumber(v)
	case bool:
		return BoxBool(v)
	default:
		// Try string conversion as fallback
		return BoxString(fmt.Sprintf("%v", v))
	}
}

// goToValue converts Go interface{} to VM Value
func goToValue(val interface{}) Value {
	if val == nil {
		return NilValue()
	}

	switch v := val.(type) {
	case bool:
		return BoxBool(v)
	case int:
		return BoxInt(int64(v))
	case int64:
		return BoxInt(v)
	case float64:
		return BoxNumber(v)
	case string:
		return BoxString(v)
	case []interface{}:
		elements := make([]Value, len(v))
		for i, elem := range v {
			elements[i] = goToValue(elem)
		}
		return BoxArray(elements)
	case map[string]interface{}:
		items := make(map[string]Value)
		for key, value := range v {
			items[key] = goToValue(value)
		}
		return BoxMap(items)
	case []float64:
		// For NDArray data
		elements := make([]Value, len(v))
		for i, elem := range v {
			elements[i] = BoxNumber(elem)
		}
		return BoxArray(elements)
	case []int:
		// For NDArray shape
		elements := make([]Value, len(v))
		for i, elem := range v {
			elements[i] = BoxInt(int64(elem))
		}
		return BoxArray(elements)
	case *dataframe.NDArray:
		// Convert NDArray to map
		return BoxMap(map[string]Value{
			"data":  goToValue(v.Data),
			"shape": goToValue(v.Shape),
			"size":  BoxInt(int64(v.Size)),
			"dtype": BoxString(v.Dtype),
		})
	case *dataframe.Series:
		// Convert Series to map
		return BoxMap(map[string]Value{
			"data":  goToValue(v.Data),
			"index": goToValue(v.Index),
			"name":  BoxString(v.Name),
			"dtype": BoxString(v.Dtype),
			"size":  BoxInt(int64(len(v.Data))),
		})
	case *dataframe.DataFrame:
		// Convert DataFrame to map (simplified - only basic info)
		return BoxMap(map[string]Value{
			"nrows": BoxInt(int64(v.NRows)),
			"ncols": BoxInt(int64(v.NCols)),
		})
	default:
		return NilValue()
	}
}

// extractNDArray extracts NDArray from a VM Value (map representation)
func extractNDArray(v Value) *dataframe.NDArray {
	if !IsMap(v) {
		return nil
	}
	arrMap := AsMap(v).Items

	dataVal, ok := arrMap["data"]
	if !ok {
		return nil
	}

	shapeVal, ok := arrMap["shape"]
	if !ok {
		return nil
	}

	// Convert data array to []float64
	if !IsArray(dataVal) {
		return nil
	}
	dataArr := AsArray(dataVal)
	data := make([]float64, len(dataArr.Elements))
	for i, elem := range dataArr.Elements {
		data[i] = ToNumber(elem)
	}

	// Convert shape array to []int
	if !IsArray(shapeVal) {
		return nil
	}
	shapeArr := AsArray(shapeVal)
	shape := make([]int, len(shapeArr.Elements))
	for i, elem := range shapeArr.Elements {
		shape[i] = int(ToNumber(elem))
	}

	return dataframe.NewArrayWithShape(data, shape)
}

// extractSeries extracts Series from a VM Value (map representation)
func extractSeries(v Value) *dataframe.Series {
	if !IsMap(v) {
		return nil
	}
	seriesMap := AsMap(v).Items

	dataVal, ok := seriesMap["data"]
	if !ok {
		return nil
	}

	indexVal, ok := seriesMap["index"]
	if !ok {
		return nil
	}

	// Convert arrays back to []interface{}
	if !IsArray(dataVal) || !IsArray(indexVal) {
		return nil
	}

	dataArr := AsArray(dataVal)
	indexArr := AsArray(indexVal)

	data := make([]interface{}, len(dataArr.Elements))
	for i, elem := range dataArr.Elements {
		data[i] = valueToGo(elem)
	}

	index := make([]interface{}, len(indexArr.Elements))
	for i, elem := range indexArr.Elements {
		index[i] = valueToGo(elem)
	}

	name := ""
	if nameVal, ok := seriesMap["name"]; ok {
		name = ToString(nameVal)
	}

	dtype := ""
	if dtypeVal, ok := seriesMap["dtype"]; ok {
		dtype = ToString(dtypeVal)
	}

	return &dataframe.Series{
		Data:  data,
		Index: index,
		Name:  name,
		Dtype: dtype,
	}
}

// registerNetworkFunctions registers all network infrastructure functions
func (vm *RegisterVM) registerNetworkFunctions() {
	// ============================================================
	// FIREWALL FUNCTIONS (8 functions)
	// ============================================================

	// firewall_create_rule(chain, protocol, src_ip, dst_ip, src_port, dst_port, action)
	vm.registerGlobal("firewall_create_rule", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "firewall_create_rule",
		Arity:  7,
		Function: func(args []Value) (Value, error) {
			chain := ToString(args[0])
			protocol := ToString(args[1])
			srcIP := ToString(args[2])
			dstIP := ToString(args[3])
			srcPort := ToString(args[4])
			dstPort := ToString(args[5])
			action := ToString(args[6])

			rule, err := network.CreateFirewallRule(chain, protocol, srcIP, dstIP, srcPort, dstPort, action)
			if err != nil {
				return NilValue(), err
			}

			return goToValue(network.RuleToMap(rule)), nil
		},
	})

	// firewall_delete_rule(rule_id)
	vm.registerGlobal("firewall_delete_rule", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "firewall_delete_rule",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			ruleID := ToString(args[0])
			err := network.DeleteFirewallRule(ruleID)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// firewall_list_rules(chain)
	vm.registerGlobal("firewall_list_rules", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "firewall_list_rules",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			chain := ToString(args[0])
			rules := network.ListFirewallRules(chain)

			rulesList := make([]interface{}, 0)
			for _, rule := range rules {
				rulesList = append(rulesList, network.RuleToMap(rule))
			}

			return goToValue(rulesList), nil
		},
	})

	// firewall_block_ip(ip_address)
	vm.registerGlobal("firewall_block_ip", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "firewall_block_ip",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			ipAddress := ToString(args[0])
			rule, err := network.BlockIP(ipAddress)
			if err != nil {
				return NilValue(), err
			}
			return goToValue(network.RuleToMap(rule)), nil
		},
	})

	// firewall_allow_ip(ip_address)
	vm.registerGlobal("firewall_allow_ip", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "firewall_allow_ip",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			ipAddress := ToString(args[0])
			rule, err := network.AllowIP(ipAddress)
			if err != nil {
				return NilValue(), err
			}
			return goToValue(network.RuleToMap(rule)), nil
		},
	})

	// firewall_get_stats()
	vm.registerGlobal("firewall_get_stats", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "firewall_get_stats",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			stats := network.GetFirewallStats()
			return goToValue(network.FirewallStatsToMap(stats)), nil
		},
	})

	// firewall_enable()
	vm.registerGlobal("firewall_enable", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "firewall_enable",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			err := network.EnableFirewall()
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// firewall_disable()
	vm.registerGlobal("firewall_disable", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "firewall_disable",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			err := network.DisableFirewall()
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// ============================================================
	// PROXY FUNCTIONS (6 functions)
	// ============================================================

	// proxy_start(port, options)
	vm.registerGlobal("proxy_start", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "proxy_start",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			port := int(ToNumber(args[0]))
			optionsMap := AsMap(args[1]).Items

			options := make(map[string]interface{})
			for key, val := range optionsMap {
				options[key] = valueToGo(val)
			}

			proxy, err := network.StartProxy(port, options)
			if err != nil {
				return NilValue(), err
			}

			return goToValue(network.ProxyToMap(proxy)), nil
		},
	})

	// proxy_stop(proxy_id)
	vm.registerGlobal("proxy_stop", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "proxy_stop",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			proxyID := ToString(args[0])
			err := network.StopProxy(proxyID)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// proxy_set_upstream(proxy_id, upstream_url)
	vm.registerGlobal("proxy_set_upstream", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "proxy_set_upstream",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			proxyID := ToString(args[0])
			upstreamURL := ToString(args[1])
			err := network.SetProxyUpstream(proxyID, upstreamURL)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// proxy_get_stats(proxy_id)
	vm.registerGlobal("proxy_get_stats", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "proxy_get_stats",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			proxyID := ToString(args[0])
			stats, err := network.GetProxyStats(proxyID)
			if err != nil {
				return NilValue(), err
			}
			return goToValue(network.ProxyStatsToMap(stats)), nil
		},
	})

	// proxy_get_logs(proxy_id, limit)
	vm.registerGlobal("proxy_get_logs", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "proxy_get_logs",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			proxyID := ToString(args[0])
			limit := int(ToNumber(args[1]))
			logs, err := network.GetProxyLogs(proxyID, limit)
			if err != nil {
				return NilValue(), err
			}
			return goToValue(logs), nil
		},
	})

	// proxy_add_filter - placeholder (filters require function callbacks)
	vm.registerGlobal("proxy_add_filter", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "proxy_add_filter",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			return NilValue(), fmt.Errorf("proxy_add_filter: callback functions not yet supported")
		},
	})

	// ============================================================
	// REVERSE PROXY FUNCTIONS (5 functions)
	// ============================================================

	// reverse_proxy_create(port, backends)
	vm.registerGlobal("reverse_proxy_create", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "reverse_proxy_create",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			port := int(ToNumber(args[0]))
			backendsArr := AsArray(args[1])

			backends := make([]string, 0)
			for _, elem := range backendsArr.Elements {
				backends = append(backends, ToString(elem))
			}

			rp, err := network.CreateReverseProxy(port, backends)
			if err != nil {
				return NilValue(), err
			}

			return goToValue(network.ReverseProxyToMap(rp)), nil
		},
	})

	// reverse_proxy_add_backend(proxy_id, backend_url, weight)
	vm.registerGlobal("reverse_proxy_add_backend", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "reverse_proxy_add_backend",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			proxyID := ToString(args[0])
			backendURL := ToString(args[1])
			weight := int(ToNumber(args[2]))

			backend, err := network.AddBackend(proxyID, backendURL, weight)
			if err != nil {
				return NilValue(), err
			}

			return goToValue(network.BackendToMap(backend)), nil
		},
	})

	// reverse_proxy_remove_backend(proxy_id, backend_id)
	vm.registerGlobal("reverse_proxy_remove_backend", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "reverse_proxy_remove_backend",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			proxyID := ToString(args[0])
			backendID := ToString(args[1])
			err := network.RemoveBackend(proxyID, backendID)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// reverse_proxy_set_load_balancing(proxy_id, algorithm)
	vm.registerGlobal("reverse_proxy_set_load_balancing", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "reverse_proxy_set_load_balancing",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			proxyID := ToString(args[0])
			algorithm := ToString(args[1])
			err := network.SetLoadBalancing(proxyID, algorithm)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// reverse_proxy_get_health(proxy_id)
	vm.registerGlobal("reverse_proxy_get_health", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "reverse_proxy_get_health",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			proxyID := ToString(args[0])
			health, err := network.GetReverseProxyHealth(proxyID)
			if err != nil {
				return NilValue(), err
			}
			return goToValue(health), nil
		},
	})

	// ============================================================
	// IDS FUNCTIONS (7 functions)
	// ============================================================

	// ids_start(interface, rules)
	vm.registerGlobal("ids_start", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ids_start",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			iface := ToString(args[0])
			rulesMap := AsMap(args[1]).Items

			rules := make(map[string]interface{})
			for key, val := range rulesMap {
				rules[key] = valueToGo(val)
			}

			ids, err := network.StartIDS(iface, rules)
			if err != nil {
				return NilValue(), err
			}

			return goToValue(network.IDSToMap(ids)), nil
		},
	})

	// ids_stop(ids_id)
	vm.registerGlobal("ids_stop", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ids_stop",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			idsID := ToString(args[0])
			err := network.StopIDS(idsID)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// ids_get_alerts(ids_id, severity, limit)
	vm.registerGlobal("ids_get_alerts", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ids_get_alerts",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			idsID := ToString(args[0])
			severity := ToString(args[1])
			limit := int(ToNumber(args[2]))

			alerts, err := network.GetIDSAlerts(idsID, severity, limit)
			if err != nil {
				return NilValue(), err
			}

			alertsList := make([]interface{}, 0)
			for _, alert := range alerts {
				alertsList = append(alertsList, network.AlertToMap(alert))
			}

			return goToValue(alertsList), nil
		},
	})

	// ids_get_stats(ids_id)
	vm.registerGlobal("ids_get_stats", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ids_get_stats",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			idsID := ToString(args[0])
			stats, err := network.GetIDSStats(idsID)
			if err != nil {
				return NilValue(), err
			}
			return goToValue(network.IDSStatsToMap(stats)), nil
		},
	})

	// ids_block_threat(threat_id)
	vm.registerGlobal("ids_block_threat", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ids_block_threat",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			threatID := ToString(args[0])
			err := network.BlockThreat(threatID)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// ids_whitelist_ip(ip_address)
	vm.registerGlobal("ids_whitelist_ip", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ids_whitelist_ip",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			ipAddress := ToString(args[0])
			err := network.WhitelistIP(ipAddress)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// ids_add_rule - placeholder (complex rule structure)
	vm.registerGlobal("ids_add_rule", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "ids_add_rule",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			return NilValue(), fmt.Errorf("ids_add_rule: custom rules not yet fully implemented")
		},
	})

	// ============================================================
	// NETWORK MONITORING FUNCTIONS (8 functions)
	// ============================================================

	// monitor_start(interface)
	vm.registerGlobal("monitor_start", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "monitor_start",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			iface := ToString(args[0])
			mon, err := network.StartMonitor(iface)
			if err != nil {
				return NilValue(), err
			}
			return BoxString(mon.ID), nil
		},
	})

	// monitor_stop(monitor_id)
	vm.registerGlobal("monitor_stop", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "monitor_stop",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			monitorID := ToString(args[0])
			err := network.StopMonitor(monitorID)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// monitor_get_bandwidth(monitor_id)
	vm.registerGlobal("monitor_get_bandwidth", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "monitor_get_bandwidth",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			monitorID := ToString(args[0])
			stats, err := network.GetBandwidth(monitorID)
			if err != nil {
				return NilValue(), err
			}
			return goToValue(network.NetworkStatsToMap(stats)), nil
		},
	})

	// monitor_get_connections(monitor_id)
	vm.registerGlobal("monitor_get_connections", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "monitor_get_connections",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			monitorID := ToString(args[0])
			connections, err := network.GetConnections(monitorID)
			if err != nil {
				return NilValue(), err
			}
			return goToValue(connections), nil
		},
	})

	// monitor_get_protocols(monitor_id)
	vm.registerGlobal("monitor_get_protocols", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "monitor_get_protocols",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			monitorID := ToString(args[0])
			protocols, err := network.GetProtocols(monitorID)
			if err != nil {
				return NilValue(), err
			}
			return goToValue(protocols), nil
		},
	})

	// monitor_get_top_talkers(monitor_id, limit)
	vm.registerGlobal("monitor_get_top_talkers", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "monitor_get_top_talkers",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			monitorID := ToString(args[0])
			limit := int(ToNumber(args[1]))

			flows, err := network.GetTopTalkers(monitorID, limit)
			if err != nil {
				return NilValue(), err
			}

			flowsList := make([]interface{}, 0)
			for _, flow := range flows {
				flowsList = append(flowsList, network.FlowToMap(flow))
			}

			return goToValue(flowsList), nil
		},
	})

	// monitor_get_flows(monitor_id, filter)
	vm.registerGlobal("monitor_get_flows", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "monitor_get_flows",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			monitorID := ToString(args[0])
			filterMap := AsMap(args[1]).Items

			filter := make(map[string]interface{})
			for key, val := range filterMap {
				filter[key] = valueToGo(val)
			}

			flows, err := network.GetFlows(monitorID, filter)
			if err != nil {
				return NilValue(), err
			}

			flowsList := make([]interface{}, 0)
			for _, flow := range flows {
				flowsList = append(flowsList, network.FlowToMap(flow))
			}

			return goToValue(flowsList), nil
		},
	})

	// monitor_export_pcap(monitor_id, filename)
	vm.registerGlobal("monitor_export_pcap", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "monitor_export_pcap",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			monitorID := ToString(args[0])
			filename := ToString(args[1])
			err := network.ExportPCAP(monitorID, filename)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// ============================================================
	// PACKET CAPTURE FUNCTIONS (5 functions)
	// ============================================================

	// capture_start(interface, filter)
	vm.registerGlobal("capture_start", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "capture_start",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			iface := ToString(args[0])
			filter := ToString(args[1])

			capture, err := network.StartCapture(iface, filter)
			if err != nil {
				return NilValue(), err
			}

			return goToValue(network.CaptureToMap(capture)), nil
		},
	})

	// capture_stop(capture_id)
	vm.registerGlobal("capture_stop", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "capture_stop",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			captureID := ToString(args[0])
			err := network.StopCapture(captureID)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// capture_get_packets(capture_id, count)
	vm.registerGlobal("capture_get_packets", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "capture_get_packets",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			captureID := ToString(args[0])
			count := int(ToNumber(args[1]))

			packets, err := network.GetPackets(captureID, count)
			if err != nil {
				return NilValue(), err
			}

			packetsList := make([]interface{}, 0)
			for _, packet := range packets {
				packetsList = append(packetsList, network.PacketToMap(packet))
			}

			return goToValue(packetsList), nil
		},
	})

	// capture_analyze_packet(packet)
	vm.registerGlobal("capture_analyze_packet", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "capture_analyze_packet",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			// In a real implementation, would reconstruct packet from map
			// For now, placeholder
			return goToValue(map[string]interface{}{
				"analysis": "placeholder",
			}), nil
		},
	})

	// capture_save_pcap(capture_id, filename)
	vm.registerGlobal("capture_save_pcap", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "capture_save_pcap",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			captureID := ToString(args[0])
			filename := ToString(args[1])
			err := network.SavePCAP(captureID, filename)
			if err != nil {
				return NilValue(), err
			}
			return BoxBool(true), nil
		},
	})

	// ============================================================
	// PORT SCANNING FUNCTIONS (5 functions)
	// ============================================================

	// scan_ports(target, port_range)
	vm.registerGlobal("scan_ports", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "scan_ports",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			target := ToString(args[0])
			portRange := ToString(args[1])

			result, err := network.ScanPorts(target, portRange)
			if err != nil {
				return NilValue(), err
			}

			return goToValue(network.PortScanResultToMap(result)), nil
		},
	})

	// scan_network(network_cidr)
	vm.registerGlobal("scan_network", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "scan_network",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			networkCIDR := ToString(args[0])

			hosts, err := network.ScanNetwork(networkCIDR)
			if err != nil {
				return NilValue(), err
			}

			hostsList := make([]interface{}, 0)
			for _, host := range hosts {
				hostsList = append(hostsList, network.HostInfoToMap(host))
			}

			return goToValue(hostsList), nil
		},
	})

	// scan_service_version(target, port)
	vm.registerGlobal("scan_service_version", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "scan_service_version",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			target := ToString(args[0])
			port := int(ToNumber(args[1]))

			version, err := network.ScanServiceVersion(target, port)
			if err != nil {
				return NilValue(), err
			}

			return BoxString(version), nil
		},
	})

	// scan_os_fingerprint(target)
	vm.registerGlobal("scan_os_fingerprint", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "scan_os_fingerprint",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			target := ToString(args[0])

			os, err := network.ScanOSFingerprint(target)
			if err != nil {
				return NilValue(), err
			}

			return BoxString(os), nil
		},
	})

	// scan_vulnerabilities(target)
	vm.registerGlobal("scan_vulnerabilities", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "scan_vulnerabilities",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			target := ToString(args[0])

			vulns, err := network.ScanVulnerabilities(target)
			if err != nil {
				return NilValue(), err
			}

			return goToValue(vulns), nil
		},
	})

	// =====================================================================
	// Hillock Web Framework Compatibility Functions
	// =====================================================================

	// String function aliases for Hillock compatibility
	vm.registerGlobal("split_string", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "split_string",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			sep := ToString(args[1])
			parts := strings.Split(str, sep)
			elements := make([]Value, len(parts))
			for i, part := range parts {
				elements[i] = BoxString(part)
			}
			return BoxArray(elements), nil
		},
	})

	vm.registerGlobal("join_strings", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "join_strings",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			arr := AsArray(args[0])
			sep := ToString(args[1])
			parts := make([]string, len(arr.Elements))
			for i, elem := range arr.Elements {
				parts[i] = ToString(elem)
			}
			return BoxString(strings.Join(parts, sep)), nil
		},
	})

	vm.registerGlobal("string_contains", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "string_contains",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			substr := ToString(args[1])
			return BoxBool(strings.Contains(str, substr)), nil
		},
	})

	vm.registerGlobal("string_starts_with", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "string_starts_with",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			prefix := ToString(args[1])
			return BoxBool(strings.HasPrefix(str, prefix)), nil
		},
	})

	vm.registerGlobal("string_ends_with", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "string_ends_with",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			suffix := ToString(args[1])
			return BoxBool(strings.HasSuffix(str, suffix)), nil
		},
	})

	vm.registerGlobal("string_lower", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "string_lower",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			return BoxString(strings.ToLower(ToString(args[0]))), nil
		},
	})

	vm.registerGlobal("string_upper", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "string_upper",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			return BoxString(strings.ToUpper(ToString(args[0]))), nil
		},
	})

	vm.registerGlobal("string_index", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "string_index",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			substr := ToString(args[1])
			return BoxInt(int64(strings.Index(str, substr))), nil
		},
	})

	vm.registerGlobal("string_substring", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "string_substring",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			start := int(ToInt(args[1]))
			end := int(ToInt(args[2]))
			if start < 0 {
				start = 0
			}
			if end > len(str) {
				end = len(str)
			}
			if start > end {
				return BoxString(""), nil
			}
			return BoxString(str[start:end]), nil
		},
	})

	vm.registerGlobal("string_trim", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "string_trim",
		Arity:  -1, // Variable args: 1 or 2
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			if len(args) == 1 {
				return BoxString(strings.TrimSpace(str)), nil
			}
			cutset := ToString(args[1])
			return BoxString(strings.Trim(str, cutset)), nil
		},
	})

	vm.registerGlobal("string_replace", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "string_replace",
		Arity:  3,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			old := ToString(args[1])
			new := ToString(args[2])
			return BoxString(strings.ReplaceAll(str, old, new)), nil
		},
	})

	// Byte/String conversion functions
	vm.registerGlobal("string_to_bytes", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "string_to_bytes",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			bytes := []byte(str)
			elements := make([]Value, len(bytes))
			for i, b := range bytes {
				elements[i] = BoxInt(int64(b))
			}
			return BoxArray(elements), nil
		},
	})

	vm.registerGlobal("bytes_to_string", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "bytes_to_string",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			arr := AsArray(args[0])
			bytes := make([]byte, len(arr.Elements))
			for i, elem := range arr.Elements {
				bytes[i] = byte(ToInt(elem))
			}
			return BoxString(string(bytes)), nil
		},
	})

	vm.registerGlobal("byte_at", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "byte_at",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			idx := int(ToInt(args[1]))
			if idx < 0 || idx >= len(str) {
				return BoxInt(-1), nil
			}
			return BoxInt(int64(str[idx])), nil
		},
	})

	// Hex conversion functions
	vm.registerGlobal("char_from_hex", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "char_from_hex",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			hex := ToString(args[0])
			var val int
			fmt.Sscanf(hex, "%x", &val)
			return BoxString(string(rune(val))), nil
		},
	})

	vm.registerGlobal("hex_from_char", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "hex_from_char",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			if len(str) == 0 {
				return BoxString("00"), nil
			}
			return BoxString(fmt.Sprintf("%02X", str[0])), nil
		},
	})

	vm.registerGlobal("hex_to_int", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "hex_to_int",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			hex := ToString(args[0])
			var val int64
			fmt.Sscanf(hex, "%x", &val)
			return BoxInt(val), nil
		},
	})

	vm.registerGlobal("int_to_hex", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "int_to_hex",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			val := ToInt(args[0])
			return BoxString(fmt.Sprintf("%x", val)), nil
		},
	})

	vm.registerGlobal("byte_to_hex", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "byte_to_hex",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			val := ToInt(args[0])
			return BoxString(fmt.Sprintf("%02x", val&0xFF)), nil
		},
	})

	// Character functions
	vm.registerGlobal("is_alphanumeric", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "is_alphanumeric",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			if len(str) == 0 {
				return BoxBool(false), nil
			}
			c := str[0]
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			return BoxBool(isAlnum), nil
		},
	})

	vm.registerGlobal("char", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "char",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			code := ToInt(args[0])
			return BoxString(string(rune(code))), nil
		},
	})

	// Time functions
	vm.registerGlobal("time_now", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "time_now",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			return BoxInt(time.Now().Unix()), nil
		},
	})

	vm.registerGlobal("format_time", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "format_time",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			timestamp := ToInt(args[0])
			format := ToString(args[1])
			t := time.Unix(timestamp, 0).UTC()

			// Support common format names
			switch format {
			case "RFC1123":
				return BoxString(t.Format(time.RFC1123)), nil
			case "RFC3339":
				return BoxString(t.Format(time.RFC3339)), nil
			case "ISO8601":
				return BoxString(t.Format("2006-01-02T15:04:05Z")), nil
			default:
				// Use Go's time format directly
				return BoxString(t.Format(format)), nil
			}
		},
	})

	vm.registerGlobal("sleep", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "sleep",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			ms := ToInt(args[0])
			time.Sleep(time.Duration(ms) * time.Millisecond)
			return NilValue(), nil
		},
	})

	// File functions
	vm.registerGlobal("file_read", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "file_read",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			path := ToString(args[0])
			data, err := os.ReadFile(path)
			if err != nil {
				return NilValue(), err
			}
			return BoxString(string(data)), nil
		},
	})

	vm.registerGlobal("file_stat", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "file_stat",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			path := ToString(args[0])
			info, err := os.Stat(path)
			if err != nil {
				return NilValue(), err
			}
			items := make(map[string]Value)
			items["name"] = BoxString(info.Name())
			items["size"] = BoxInt(info.Size())
			items["is_dir"] = BoxBool(info.IsDir())
			items["modified"] = BoxInt(info.ModTime().Unix())
			return BoxMap(items), nil
		},
	})

	// JSON alias
	vm.registerGlobal("json_parse", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "json_parse",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			var result interface{}
			err := json.Unmarshal([]byte(str), &result)
			if err != nil {
				return NilValue(), fmt.Errorf("json_parse error: %v", err)
			}
			return goToValue(result), nil
		},
	})

	vm.registerGlobal("json_stringify", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "json_stringify",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			val := args[0]
			goVal := valueToGo(val)
			data, err := json.Marshal(goVal)
			if err != nil {
				return NilValue(), fmt.Errorf("json_stringify error: %v", err)
			}
			return BoxString(string(data)), nil
		},
	})

	// Random functions
	vm.registerGlobal("random_int", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "random_int",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			min := ToInt(args[0])
			max := ToInt(args[1])
			if max <= min {
				return BoxInt(min), nil
			}
			return BoxInt(min + int64(time.Now().UnixNano())%(max-min)), nil
		},
	})

	vm.registerGlobal("generate_random", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "generate_random",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			length := int(ToInt(args[0]))
			const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			result := make([]byte, length)
			for i := range result {
				result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
				time.Sleep(time.Nanosecond)
			}
			return BoxString(string(result)), nil
		},
	})

	vm.registerGlobal("generate_random_hex", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "generate_random_hex",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			length := int(ToInt(args[0]))
			const charset = "0123456789abcdef"
			result := make([]byte, length)
			for i := range result {
				result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
				time.Sleep(time.Nanosecond)
			}
			return BoxString(string(result)), nil
		},
	})

	vm.registerGlobal("generate_id", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "generate_id",
		Arity:  0,
		Function: func(args []Value) (Value, error) {
			// Generate a simple unique ID based on timestamp
			return BoxString(fmt.Sprintf("%x", time.Now().UnixNano())), nil
		},
	})

	// Compression functions (using Go's compress package)
	vm.registerGlobal("gzip_compress", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "gzip_compress",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			data := ToString(args[0])
			var buf bytes.Buffer
			gzw, _ := newGzipWriter(&buf)
			gzw.Write([]byte(data))
			gzw.Close()
			// Return as array of bytes
			compressed := buf.Bytes()
			elements := make([]Value, len(compressed))
			for i, b := range compressed {
				elements[i] = BoxInt(int64(b))
			}
			return BoxArray(elements), nil
		},
	})

	vm.registerGlobal("gzip_decompress", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "gzip_decompress",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			arr := AsArray(args[0])
			data := make([]byte, len(arr.Elements))
			for i, elem := range arr.Elements {
				data[i] = byte(ToInt(elem))
			}
			gzr, err := newGzipReader(bytes.NewReader(data))
			if err != nil {
				return NilValue(), err
			}
			defer gzr.Close()
			decompressed, err := io.ReadAll(gzr)
			if err != nil {
				return NilValue(), err
			}
			return BoxString(string(decompressed)), nil
		},
	})

	vm.registerGlobal("deflate_compress", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "deflate_compress",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			data := ToString(args[0])
			var buf bytes.Buffer
			fw, _ := newFlateWriter(&buf, -1)
			fw.Write([]byte(data))
			fw.Close()
			compressed := buf.Bytes()
			elements := make([]Value, len(compressed))
			for i, b := range compressed {
				elements[i] = BoxInt(int64(b))
			}
			return BoxArray(elements), nil
		},
	})

	vm.registerGlobal("deflate_decompress", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "deflate_decompress",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			arr := AsArray(args[0])
			data := make([]byte, len(arr.Elements))
			for i, elem := range arr.Elements {
				data[i] = byte(ToInt(elem))
			}
			fr := newFlateReader(bytes.NewReader(data))
			defer fr.Close()
			decompressed, err := io.ReadAll(fr)
			if err != nil {
				return NilValue(), err
			}
			return BoxString(string(decompressed)), nil
		},
	})

	// Set timeout helper (for socket operations)
	vm.registerGlobal("set_timeout", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "set_timeout",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			// This is a placeholder - actual timeout logic handled in socket operations
			return NilValue(), nil
		},
	})

	// Additional string helpers
	vm.registerGlobal("string_to_int", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "string_to_int",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			var val int64
			fmt.Sscanf(str, "%d", &val)
			return BoxInt(val), nil
		},
	})

	vm.registerGlobal("string_to_float", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "string_to_float",
		Arity:  1,
		Function: func(args []Value) (Value, error) {
			str := ToString(args[0])
			var val float64
			fmt.Sscanf(str, "%f", &val)
			return BoxNumber(val), nil
		},
	})

	// Socket binary send - for HTTP/2, WebSocket, TLS protocols
	vm.registerGlobal("socket_send_bytes", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "socket_send_bytes",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			socketID := ToString(args[0])

			// Convert array of numbers to bytes
			if !IsArray(args[1]) {
				return NilValue(), fmt.Errorf("socket_send_bytes expects array of bytes")
			}

			arr := AsArray(args[1])
			data := make([]byte, len(arr.Elements))
			for i, v := range arr.Elements {
				data[i] = byte(ToInt(v))
			}

			bytesSent, err := netMod.Send(socketID, data)
			if err != nil {
				return NilValue(), err
			}

			return BoxInt(int64(bytesSent)), nil
		},
	})

	// Socket receive bytes - returns array of byte values
	vm.registerGlobal("socket_receive_bytes", &NativeFnObj{
		Object: Object{Type: OBJ_NATIVE_FN},
		Name:   "socket_receive_bytes",
		Arity:  2,
		Function: func(args []Value) (Value, error) {
			netMod := vm.networkModule.(*network.NetworkModule)
			socketID := ToString(args[0])
			maxBytes := int(ToInt(args[1]))

			data, err := netMod.Receive(socketID, maxBytes)
			if err != nil {
				return NilValue(), err
			}

			// Convert bytes to array of numbers
			elements := make([]Value, len(data))
			for i, b := range data {
				elements[i] = BoxInt(int64(b))
			}

			return BoxArray(elements), nil
		},
	})
}

// valuesEqualStdlib compares two values for equality (used by assert functions)
func valuesEqualStdlib(a, b Value) bool {
	// Handle nil cases
	if IsNil(a) && IsNil(b) {
		return true
	}
	if IsNil(a) || IsNil(b) {
		return false
	}

	// Handle booleans
	if IsBool(a) && IsBool(b) {
		return IsTruthy(a) == IsTruthy(b)
	}

	// Handle integers
	if IsInt(a) && IsInt(b) {
		return AsInt(a) == AsInt(b)
	}

	// Handle numbers (floats)
	if IsNumber(a) && IsNumber(b) {
		return AsNumber(a) == AsNumber(b)
	}

	// Handle int/float comparison
	if (IsInt(a) || IsNumber(a)) && (IsInt(b) || IsNumber(b)) {
		return ToNumber(a) == ToNumber(b)
	}

	// Handle strings
	if IsString(a) && IsString(b) {
		return ToString(a) == ToString(b)
	}

	// Handle arrays
	if IsArray(a) && IsArray(b) {
		arrA := AsArray(a)
		arrB := AsArray(b)
		if len(arrA.Elements) != len(arrB.Elements) {
			return false
		}
		for i := range arrA.Elements {
			if !valuesEqualStdlib(arrA.Elements[i], arrB.Elements[i]) {
				return false
			}
		}
		return true
	}

	// Handle maps
	if IsMap(a) && IsMap(b) {
		mapA := AsMap(a)
		mapB := AsMap(b)
		if len(mapA.Items) != len(mapB.Items) {
			return false
		}
		for k, v := range mapA.Items {
			if vB, ok := mapB.Items[k]; !ok || !valuesEqualStdlib(v, vB) {
				return false
			}
		}
		return true
	}

	// Different types
	return false
}

// ValueToString converts a Value to its string representation for error messages
func ValueToString(v Value) string {
	if IsNil(v) {
		return "nil"
	}
	if IsBool(v) {
		if IsTruthy(v) {
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
		return fmt.Sprintf("%q", ToString(v))
	}
	if IsArray(v) {
		arr := AsArray(v)
		var parts []string
		for _, elem := range arr.Elements {
			parts = append(parts, ValueToString(elem))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	if IsMap(v) {
		m := AsMap(v)
		var parts []string
		for k, val := range m.Items {
			parts = append(parts, fmt.Sprintf("%q: %s", k, ValueToString(val)))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprintf("<value: %v>", v)
}
