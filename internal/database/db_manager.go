package database

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"  // Pure Go SQLite driver
	_ "github.com/lib/pq"
	_ "github.com/go-sql-driver/mysql"
)

// DBManager manages database connections for Sentra
type DBManager struct {
	connections map[string]*DBConn
	mu          sync.RWMutex
}

// DBConn represents an active database connection
type DBConn struct {
	ID         string
	Type       string // sqlite, postgres, mysql
	DB         *sql.DB
	DSN        string
	Created    time.Time
	LastUsed   time.Time
}

// NewDBManager creates a new database manager
func NewDBManager() *DBManager {
	return &DBManager{
		connections: make(map[string]*DBConn),
	}
}

// Connect creates a new database connection
func (m *DBManager) Connect(id, dbType, dsn string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if connection already exists
	if _, exists := m.connections[id]; exists {
		return fmt.Errorf("connection '%s' already exists", id)
	}

	// Map to proper driver name
	var driverName string
	switch dbType {
	case "sqlite", "sqlite3":
		driverName = "sqlite"
	case "postgres", "postgresql":
		driverName = "postgres"
	case "mysql":
		driverName = "mysql"
	default:
		return fmt.Errorf("unsupported database type: %s", dbType)
	}

	// Open database connection
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	conn := &DBConn{
		ID:       id,
		Type:     dbType,
		DB:       db,
		DSN:      dsn,
		Created:  time.Now(),
		LastUsed: time.Now(),
	}

	m.connections[id] = conn
	return nil
}

// Execute runs a query that doesn't return rows (INSERT, UPDATE, DELETE)
func (m *DBManager) Execute(connID, query string, args ...interface{}) (int64, error) {
	conn, err := m.getConnection(connID)
	if err != nil {
		return 0, err
	}

	conn.LastUsed = time.Now()

	result, err := conn.DB.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("execution failed: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return affected, nil
}

// Query runs a query that returns rows
func (m *DBManager) Query(connID, query string, args ...interface{}) ([]map[string]interface{}, error) {
	conn, err := m.getConnection(connID)
	if err != nil {
		return nil, err
	}

	conn.LastUsed = time.Now()

	rows, err := conn.DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]interface{}

	// Create slice for scanning
	values := make([]interface{}, len(columns))
	valuePtrs := make([]interface{}, len(columns))
	for i := range columns {
		valuePtrs[i] = &values[i]
	}

	// Fetch rows
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		// Create map for this row
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			
			// Handle byte arrays as strings
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		results = append(results, row)
	}

	return results, rows.Err()
}

// QueryOne runs a query expecting a single row
func (m *DBManager) QueryOne(connID, query string, args ...interface{}) (map[string]interface{}, error) {
	results, err := m.Query(connID, query, args...)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no rows returned")
	}

	return results[0], nil
}

// Transaction runs a function within a database transaction
func (m *DBManager) Transaction(connID string, fn func(*sql.Tx) error) error {
	conn, err := m.getConnection(connID)
	if err != nil {
		return err
	}

	conn.LastUsed = time.Now()

	tx, err := conn.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("transaction failed: %v, rollback failed: %w", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Close closes a specific connection
func (m *DBManager) Close(connID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	conn, exists := m.connections[connID]
	if !exists {
		return fmt.Errorf("connection '%s' not found", connID)
	}

	if err := conn.DB.Close(); err != nil {
		return err
	}

	delete(m.connections, connID)
	return nil
}

// CloseAll closes all connections
func (m *DBManager) CloseAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, conn := range m.connections {
		if err := conn.DB.Close(); err != nil {
			// Log error but continue closing others
			fmt.Printf("Error closing connection %s: %v\n", id, err)
		}
	}

	m.connections = make(map[string]*DBConn)
	return nil
}

// ListConnections returns a list of active connections
func (m *DBManager) ListConnections() []map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var list []map[string]interface{}
	for _, conn := range m.connections {
		list = append(list, map[string]interface{}{
			"id":       conn.ID,
			"type":     conn.Type,
			"created":  conn.Created,
			"lastUsed": conn.LastUsed,
		})
	}

	return list
}

// getConnection retrieves a connection by ID
func (m *DBManager) getConnection(connID string) (*DBConn, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	conn, exists := m.connections[connID]
	if !exists {
		return nil, fmt.Errorf("connection '%s' not found", connID)
	}

	return conn, nil
}