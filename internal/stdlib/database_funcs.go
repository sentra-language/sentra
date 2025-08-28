package stdlib

import (
	"fmt"
	"sentra/internal/database"
	"sentra/internal/vm"
)

var dbManager = database.NewDBManager()

// RegisterDatabaseFunctions registers database functions in the VM
func RegisterDatabaseFunctions(v *vm.VM) {
	// Connection management
	v.RegisterBuiltin("db_connect", dbConnect)
	v.RegisterBuiltin("db_close", dbClose)
	v.RegisterBuiltin("db_list", dbList)
	
	// Query operations
	v.RegisterBuiltin("db_query", dbQuery)
	v.RegisterBuiltin("db_execute", dbExecute)
	v.RegisterBuiltin("db_query_one", dbQueryOne)
	
	// Transaction support
	v.RegisterBuiltin("db_transaction", dbTransaction)
	
	// Utility functions
	v.RegisterBuiltin("db_escape", dbEscape)
	v.RegisterBuiltin("db_prepare", dbPrepare)
}

// db_connect(id, type, dsn) - Connect to a database
// Example: db_connect("mydb", "sqlite", "test.db")
// Example: db_connect("pgdb", "postgres", "host=localhost user=test dbname=mydb sslmode=disable")
// Example: db_connect("mysql", "mysql", "user:pass@tcp(localhost:3306)/dbname")
func dbConnect(args ...interface{}) (interface{}, error) {
	if len(args) != 3 {
		return nil, fmt.Errorf("db_connect expects 3 arguments: id, type, dsn")
	}

	id, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("db_connect: id must be a string")
	}

	dbType, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("db_connect: type must be a string")
	}

	dsn, ok := args[2].(string)
	if !ok {
		return nil, fmt.Errorf("db_connect: dsn must be a string")
	}

	err := dbManager.Connect(id, dbType, dsn)
	if err != nil {
		return false, err
	}

	return true, nil
}

// db_close(id) - Close a database connection
func dbClose(args ...interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("db_close expects 1 argument: id")
	}

	id, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("db_close: id must be a string")
	}

	err := dbManager.Close(id)
	if err != nil {
		return false, err
	}

	return true, nil
}

// db_list() - List all active database connections
func dbList(args ...interface{}) (interface{}, error) {
	connections := dbManager.ListConnections()
	
	// Convert to VM array
	result := &vm.Array{
		Elements: make([]interface{}, len(connections)),
	}
	
	for i, conn := range connections {
		// Convert map to VM map
		vmMap := &vm.Map{
			Pairs: make(map[vm.HashKey]vm.MapPair),
		}
		
		for k, v := range conn {
			key := &vm.String{Value: k}
			hashKey := key.HashKey()
			
			var value interface{}
			switch val := v.(type) {
			case string:
				value = &vm.String{Value: val}
			case int:
				value = float64(val)
			case int64:
				value = float64(val)
			case float64:
				value = val
			default:
				value = &vm.String{Value: fmt.Sprintf("%v", val)}
			}
			
			vmMap.Pairs[hashKey] = vm.MapPair{
				Key:   key,
				Value: value,
			}
		}
		
		result.Elements[i] = vmMap
	}
	
	return result, nil
}

// db_query(conn_id, query, ...args) - Execute a SELECT query
// Returns array of maps representing rows
func dbQuery(args ...interface{}) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("db_query expects at least 2 arguments: conn_id, query, [args...]")
	}

	connID, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("db_query: conn_id must be a string")
	}

	query, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("db_query: query must be a string")
	}

	// Collect query arguments
	var queryArgs []interface{}
	if len(args) > 2 {
		queryArgs = args[2:]
	}

	// Execute query
	rows, err := dbManager.Query(connID, query, queryArgs...)
	if err != nil {
		return nil, err
	}

	// Convert results to VM array of maps
	result := &vm.Array{
		Elements: make([]interface{}, len(rows)),
	}

	for i, row := range rows {
		vmMap := &vm.Map{
			Pairs: make(map[vm.HashKey]vm.MapPair),
		}

		for key, val := range row {
			keyObj := &vm.String{Value: key}
			hashKey := keyObj.HashKey()

			var value interface{}
			switch v := val.(type) {
			case nil:
				value = nil
			case string:
				value = &vm.String{Value: v}
			case int:
				value = float64(v)
			case int32:
				value = float64(v)
			case int64:
				value = float64(v)
			case float32:
				value = float64(v)
			case float64:
				value = v
			case bool:
				value = v
			default:
				value = &vm.String{Value: fmt.Sprintf("%v", v)}
			}

			vmMap.Pairs[hashKey] = vm.MapPair{
				Key:   keyObj,
				Value: value,
			}
		}

		result.Elements[i] = vmMap
	}

	return result, nil
}

// db_execute(conn_id, query, ...args) - Execute INSERT/UPDATE/DELETE
// Returns number of affected rows
func dbExecute(args ...interface{}) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("db_execute expects at least 2 arguments: conn_id, query, [args...]")
	}

	connID, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("db_execute: conn_id must be a string")
	}

	query, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("db_execute: query must be a string")
	}

	// Collect query arguments
	var queryArgs []interface{}
	if len(args) > 2 {
		queryArgs = args[2:]
	}

	// Execute query
	affected, err := dbManager.Execute(connID, query, queryArgs...)
	if err != nil {
		return nil, err
	}

	return float64(affected), nil
}

// db_query_one(conn_id, query, ...args) - Execute query expecting single row
// Returns a map or nil
func dbQueryOne(args ...interface{}) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("db_query_one expects at least 2 arguments: conn_id, query, [args...]")
	}

	connID, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("db_query_one: conn_id must be a string")
	}

	query, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("db_query_one: query must be a string")
	}

	// Collect query arguments
	var queryArgs []interface{}
	if len(args) > 2 {
		queryArgs = args[2:]
	}

	// Execute query
	row, err := dbManager.QueryOne(connID, query, queryArgs...)
	if err != nil {
		if err.Error() == "no rows returned" {
			return nil, nil
		}
		return nil, err
	}

	// Convert to VM map
	vmMap := &vm.Map{
		Pairs: make(map[vm.HashKey]vm.MapPair),
	}

	for key, val := range row {
		keyObj := &vm.String{Value: key}
		hashKey := keyObj.HashKey()

		var value interface{}
		switch v := val.(type) {
		case nil:
			value = nil
		case string:
			value = &vm.String{Value: v}
		case int:
			value = float64(v)
		case int32:
			value = float64(v)
		case int64:
			value = float64(v)
		case float32:
			value = float64(v)
		case float64:
			value = v
		case bool:
			value = v
		default:
			value = &vm.String{Value: fmt.Sprintf("%v", v)}
		}

		vmMap.Pairs[hashKey] = vm.MapPair{
			Key:   keyObj,
			Value: value,
		}
	}

	return vmMap, nil
}

// db_transaction(conn_id, func) - Execute function in transaction
func dbTransaction(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("db_transaction expects 2 arguments: conn_id, function")
	}

	connID, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("db_transaction: conn_id must be a string")
	}

	fn, ok := args[1].(*vm.CompiledFunction)
	if !ok {
		return nil, fmt.Errorf("db_transaction: second argument must be a function")
	}

	// For now, return a placeholder
	// Full implementation would need VM context to execute the function
	return fmt.Sprintf("Transaction on %s with function %v", connID, fn), nil
}

// db_escape(str) - Escape string for SQL queries
func dbEscape(args ...interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("db_escape expects 1 argument: string")
	}

	str, ok := args[0].(string)
	if !ok {
		strObj, ok := args[0].(*vm.String)
		if !ok {
			return nil, fmt.Errorf("db_escape: argument must be a string")
		}
		str = strObj.Value
	}

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

	return &vm.String{Value: escaped}, nil
}

// db_prepare(query, params_map) - Prepare query with named parameters
func dbPrepare(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("db_prepare expects 2 arguments: query, params")
	}

	query, ok := args[0].(string)
	if !ok {
		queryObj, ok := args[0].(*vm.String)
		if !ok {
			return nil, fmt.Errorf("db_prepare: query must be a string")
		}
		query = queryObj.Value
	}

	// For now, just return the query
	// Full implementation would handle parameter substitution
	return &vm.String{Value: query}, nil
}