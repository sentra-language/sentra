package vm

import (
	"fmt"
	"sentra/internal/database"
)

// Global database manager instance
var dbManager = database.NewDBManager()

// RegisterDatabaseBindings registers database binding functions in the VM
func RegisterDatabaseBindings(vm *EnhancedVM) {
	// Database connection management
	vm.AddBuiltinFunction("sql_connect", &NativeFunction{
		Name:  "sql_connect",
		Arity: 3,
		Function: func(args []Value) (Value, error) {
			if len(args) != 3 {
				return nil, fmt.Errorf("sql_connect expects 3 arguments: id, type, dsn")
			}
			
			id := ToString(args[0])
			dbType := ToString(args[1])
			dsn := ToString(args[2])
			
			err := dbManager.Connect(id, dbType, dsn)
			return err == nil, err
		},
	})
	
	vm.AddBuiltinFunction("sql_close", &NativeFunction{
		Name:  "sql_close",
		Arity: 1,
		Function: func(args []Value) (Value, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("sql_close expects 1 argument: id")
			}
			
			id := ToString(args[0])
			err := dbManager.Close(id)
			return err == nil, err
		},
	})
	
	vm.AddBuiltinFunction("sql_list", &NativeFunction{
		Name:  "sql_list",
		Arity: 0,
		Function: func(args []Value) (Value, error) {
			connections := dbManager.ListConnections()
			
			result := &Array{
				Elements: make([]Value, len(connections)),
			}
			for i, conn := range connections {
				connMap := NewMap()
				for k, v := range conn {
					var value Value
					switch val := v.(type) {
					case string:
						value = &String{Value: val}
					case int:
						value = float64(val)
					case int64:
						value = float64(val)
					case float64:
						value = val
					default:
						value = &String{Value: fmt.Sprintf("%v", val)}
					}
					connMap.Items[k] = value
				}
				result.Elements[i] = connMap
			}
			
			return result, nil
		},
	})
	
	// Query operations
	vm.AddBuiltinFunction("sql_query", &NativeFunction{
		Name:  "sql_query",
		Arity: -1, // Variable arguments
		Function: func(args []Value) (Value, error) {
			if len(args) < 2 {
				return nil, fmt.Errorf("sql_query expects at least 2 arguments: conn_id, query, [args...]")
			}
			
			connID := ToString(args[0])
			query := ToString(args[1])
			
			// Collect query arguments
			var queryArgs []interface{}
			if len(args) > 2 {
				queryArgs = make([]interface{}, len(args)-2)
				for i := 2; i < len(args); i++ {
					queryArgs[i-2] = convertValueToGo(args[i])
				}
			}
			
			// Execute query
			rows, err := dbManager.Query(connID, query, queryArgs...)
			if err != nil {
				return nil, err
			}
			
			// Convert results to VM array of maps
			result := &Array{
				Elements: make([]Value, len(rows)),
			}
			for i, row := range rows {
				rowMap := NewMap()
				for key, val := range row {
					rowMap.Items[key] = convertGoToValue(val)
				}
				result.Elements[i] = rowMap
			}
			
			return result, nil
		},
	})
	
	vm.AddBuiltinFunction("sql_execute", &NativeFunction{
		Name:  "sql_execute",
		Arity: -1, // Variable arguments
		Function: func(args []Value) (Value, error) {
			if len(args) < 2 {
				return nil, fmt.Errorf("sql_execute expects at least 2 arguments: conn_id, query, [args...]")
			}
			
			connID := ToString(args[0])
			query := ToString(args[1])
			
			// Collect query arguments
			var queryArgs []interface{}
			if len(args) > 2 {
				queryArgs = make([]interface{}, len(args)-2)
				for i := 2; i < len(args); i++ {
					queryArgs[i-2] = convertValueToGo(args[i])
				}
			}
			
			// Execute query
			affected, err := dbManager.Execute(connID, query, queryArgs...)
			if err != nil {
				return nil, err
			}
			
			return float64(affected), nil
		},
	})
	
	vm.AddBuiltinFunction("sql_query_one", &NativeFunction{
		Name:  "sql_query_one",
		Arity: -1, // Variable arguments
		Function: func(args []Value) (Value, error) {
			if len(args) < 2 {
				return nil, fmt.Errorf("sql_query_one expects at least 2 arguments: conn_id, query, [args...]")
			}
			
			connID := ToString(args[0])
			query := ToString(args[1])
			
			// Collect query arguments
			var queryArgs []interface{}
			if len(args) > 2 {
				queryArgs = make([]interface{}, len(args)-2)
				for i := 2; i < len(args); i++ {
					queryArgs[i-2] = convertValueToGo(args[i])
				}
			}
			
			// Execute query
			row, err := dbManager.QueryOne(connID, query, queryArgs...)
			if err != nil {
				if err.Error() == "no rows returned" {
					return nil, nil // Return nil for no rows
				}
				return nil, err
			}
			
			// Convert to VM map
			rowMap := NewMap()
			for key, val := range row {
				rowMap.Items[key] = convertGoToValue(val)
			}
			
			return rowMap, nil
		},
	})
	
	// Utility functions
	vm.AddBuiltinFunction("sql_escape", &NativeFunction{
		Name:  "sql_escape",
		Arity: 1,
		Function: func(args []Value) (Value, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("sql_escape expects 1 argument: string")
			}
			
			str := ToString(args[0])
			
			// Basic SQL escaping
			escaped := ""
			for _, ch := range str {
				switch ch {
				case '\'':
					escaped += "''"
				case '"':
					escaped += "\"\""
				case '\\':
					escaped += "\\\\"
				case '\n':
					escaped += "\\n"
				case '\r':
					escaped += "\\r"
				case '\t':
					escaped += "\\t"
				default:
					escaped += string(ch)
				}
			}
			
			return &String{Value: escaped}, nil
		},
	})
}

// Helper function to convert VM Value to Go value
func convertValueToGo(v Value) interface{} {
	switch val := v.(type) {
	case nil:
		return nil
	case bool:
		return val
	case float64:
		return val
	case string:
		return val
	case *String:
		return val.Value
	default:
		return ToString(val)
	}
}

// Helper function to convert Go value to VM Value
func convertGoToValue(v interface{}) Value {
	switch val := v.(type) {
	case nil:
		return nil
	case string:
		return &String{Value: val}
	case int:
		return float64(val)
	case int32:
		return float64(val)
	case int64:
		return float64(val)
	case float32:
		return float64(val)
	case float64:
		return val
	case bool:
		return val
	default:
		return &String{Value: fmt.Sprintf("%v", val)}
	}
}