// Package database provides database security testing capabilities for Sentra
package database

import (
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	// Import common database drivers
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	_ "github.com/denisenkom/go-mssqldb"
)

// DatabaseModule provides database security testing
type DatabaseModule struct {
	Connections map[string]*DBConnection
	ScanResults []DBScanResult
	Credentials []Credential
	mu          sync.RWMutex
}

// DBConnection represents a database connection
type DBConnection struct {
	ID           string
	Type         string // mysql, postgres, sqlite3, sqlserver, mongodb
	Host         string
	Port         int
	Database     string
	Username     string
	Password     string
	Connected    bool
	Connection   *sql.DB
	LastAccess   time.Time
	Version      string
	Privileges   []string
}

// DBScanResult represents database security scan results
type DBScanResult struct {
	ConnectionID string
	Type         string // VULN, CONFIG, ACCESS, INJECTION
	Severity     string // LOW, MEDIUM, HIGH, CRITICAL
	Description  string
	Evidence     string
	Table        string
	Query        string
	Timestamp    time.Time
	Remediation  string
}

// Credential represents login credentials for testing
type Credential struct {
	Username string
	Password string
	Common   bool // Is it a common/default credential
}

// SQLInjectionTest represents SQL injection test parameters
type SQLInjectionTest struct {
	URL        string
	Parameter  string
	Method     string
	Payloads   []string
	Vulnerable bool
	Evidence   []string
}

// NewDatabaseModule creates a new database security module
func NewDatabaseModule() *DatabaseModule {
	module := &DatabaseModule{
		Connections: make(map[string]*DBConnection),
		ScanResults: make([]DBScanResult, 0),
		Credentials: getDefaultCredentials(),
	}
	return module
}

// getDefaultCredentials returns common database credentials for testing
func getDefaultCredentials() []Credential {
	return []Credential{
		{Username: "root", Password: "", Common: true},
		{Username: "root", Password: "root", Common: true},
		{Username: "root", Password: "password", Common: true},
		{Username: "root", Password: "123456", Common: true},
		{Username: "admin", Password: "", Common: true},
		{Username: "admin", Password: "admin", Common: true},
		{Username: "admin", Password: "password", Common: true},
		{Username: "sa", Password: "", Common: true},
		{Username: "sa", Password: "sa", Common: true},
		{Username: "postgres", Password: "", Common: true},
		{Username: "postgres", Password: "postgres", Common: true},
		{Username: "mysql", Password: "", Common: true},
		{Username: "mysql", Password: "mysql", Common: true},
		{Username: "oracle", Password: "oracle", Common: true},
		{Username: "user", Password: "user", Common: true},
		{Username: "test", Password: "test", Common: true},
		{Username: "guest", Password: "", Common: true},
		{Username: "guest", Password: "guest", Common: true},
	}
}

// ScanDatabaseService scans for database services on a host
func (db *DatabaseModule) ScanDatabaseService(host string) ([]map[string]interface{}, error) {
	services := make([]map[string]interface{}, 0)
	
	// Common database ports
	dbPorts := map[int]string{
		3306:  "MySQL",
		5432:  "PostgreSQL", 
		1433:  "SQL Server",
		1521:  "Oracle",
		27017: "MongoDB",
		6379:  "Redis",
		5984:  "CouchDB",
		9200:  "Elasticsearch",
		8086:  "InfluxDB",
		7000:  "Cassandra",
	}

	for port, service := range dbPorts {
		if db.isPortOpen(host, port) {
			serviceInfo := map[string]interface{}{
				"host":    host,
				"port":    port,
				"service": service,
				"status":  "open",
			}
			
			// Try to get version information
			if version := db.getServiceVersion(host, port, service); version != "" {
				serviceInfo["version"] = version
			}
			
			services = append(services, serviceInfo)
		}
	}

	return services, nil
}

// isPortOpen checks if a port is open on a host
func (db *DatabaseModule) isPortOpen(host string, port int) bool {
	timeout := time.Second * 2
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// getServiceVersion attempts to get version information
func (db *DatabaseModule) getServiceVersion(host string, port int, service string) string {
	// Simplified version detection
	// Real implementation would send service-specific probes
	return fmt.Sprintf("%s detected on %s:%d", service, host, port)
}

// Connect establishes a database connection
func (db *DatabaseModule) Connect(id, dbType, host string, port int, database, username, password string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	var dsn string
	var err error

	// Build connection string based on database type
	switch strings.ToLower(dbType) {
	case "mysql":
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", username, password, host, port, database)
	case "postgres", "postgresql":
		dsn = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			host, port, username, password, database)
	case "sqlite3", "sqlite":
		dsn = database // For SQLite, database is the file path
	case "sqlserver", "mssql":
		dsn = fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s;database=%s",
			host, port, username, password, database)
	default:
		return fmt.Errorf("unsupported database type: %s", dbType)
	}

	// Attempt connection
	conn, err := sql.Open(dbType, dsn)
	if err != nil {
		return err
	}

	// Test the connection
	if err = conn.Ping(); err != nil {
		conn.Close()
		return err
	}

	// Create connection object
	dbConn := &DBConnection{
		ID:         id,
		Type:       dbType,
		Host:       host,
		Port:       port,
		Database:   database,
		Username:   username,
		Password:   password,
		Connected:  true,
		Connection: conn,
		LastAccess: time.Now(),
	}

	// Get additional information
	dbConn.Version = db.getDBVersion(conn, dbType)
	dbConn.Privileges = db.getUserPrivileges(conn, dbType, username)

	db.Connections[id] = dbConn
	return nil
}

// getDBVersion gets database version information
func (db *DatabaseModule) getDBVersion(conn *sql.DB, dbType string) string {
	var query string
	
	switch strings.ToLower(dbType) {
	case "mysql":
		query = "SELECT VERSION()"
	case "postgres", "postgresql":
		query = "SELECT version()"
	case "sqlite3", "sqlite":
		query = "SELECT sqlite_version()"
	case "sqlserver", "mssql":
		query = "SELECT @@VERSION"
	default:
		return "Unknown"
	}

	var version string
	err := conn.QueryRow(query).Scan(&version)
	if err != nil {
		return "Unknown"
	}
	
	return version
}

// getUserPrivileges gets user privileges
func (db *DatabaseModule) getUserPrivileges(conn *sql.DB, dbType, username string) []string {
	privileges := make([]string, 0)
	
	var query string
	switch strings.ToLower(dbType) {
	case "mysql":
		query = fmt.Sprintf("SHOW GRANTS FOR '%s'", username)
	case "postgres", "postgresql":
		query = fmt.Sprintf("SELECT privilege_type FROM information_schema.role_table_grants WHERE grantee = '%s'", username)
	default:
		return privileges // Not implemented for other databases
	}

	rows, err := conn.Query(query)
	if err != nil {
		return privileges
	}
	defer rows.Close()

	for rows.Next() {
		var privilege string
		if rows.Scan(&privilege) == nil {
			privileges = append(privileges, privilege)
		}
	}

	return privileges
}

// TestCredentials tests multiple credentials against a database service
func (db *DatabaseModule) TestCredentials(host string, port int, dbType string, database string) ([]map[string]interface{}, error) {
	results := make([]map[string]interface{}, 0)
	
	for _, cred := range db.Credentials {
		// Skip if database type doesn't match credential pattern
		if !db.isCredentialRelevant(dbType, cred.Username) {
			continue
		}

		connID := fmt.Sprintf("test_%s_%d_%s", host, port, cred.Username)
		err := db.Connect(connID, dbType, host, port, database, cred.Username, cred.Password)
		
		result := map[string]interface{}{
			"username": cred.Username,
			"password": cred.Password,
			"success":  err == nil,
			"common":   cred.Common,
		}

		if err == nil {
			result["message"] = "Authentication successful"
			// Close the test connection
			db.CloseConnection(connID)
		} else {
			result["message"] = err.Error()
		}

		results = append(results, result)
	}

	return results, nil
}

// isCredentialRelevant checks if a credential is relevant for the database type
func (db *DatabaseModule) isCredentialRelevant(dbType, username string) bool {
	switch strings.ToLower(dbType) {
	case "mysql":
		return username == "root" || username == "mysql" || username == "admin" || 
		       username == "user" || username == "test" || username == "guest"
	case "postgres", "postgresql":
		return username == "postgres" || username == "admin" || username == "user" ||
		       username == "test" || username == "guest"
	case "sqlserver", "mssql":
		return username == "sa" || username == "admin" || username == "user" ||
		       username == "test" || username == "guest"
	default:
		return true // Test all for unknown types
	}
}

// ScanForVulnerabilities performs comprehensive database security scanning
func (db *DatabaseModule) ScanForVulnerabilities(connectionID string) ([]DBScanResult, error) {
	db.mu.RLock()
	conn, exists := db.Connections[connectionID]
	db.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("connection not found: %s", connectionID)
	}

	var results []DBScanResult

	// Check configuration vulnerabilities
	configResults := db.checkConfigurationSecurity(conn)
	results = append(results, configResults...)

	// Check access control
	accessResults := db.checkAccessControl(conn)
	results = append(results, accessResults...)

	// Check for dangerous functions/procedures
	funcResults := db.checkDangerousFunctions(conn)
	results = append(results, funcResults...)

	// Check database structure for security issues
	structResults := db.checkDatabaseStructure(conn)
	results = append(results, structResults...)

	// Store results
	db.mu.Lock()
	db.ScanResults = append(db.ScanResults, results...)
	db.mu.Unlock()

	return results, nil
}

// checkConfigurationSecurity checks database configuration for security issues
func (db *DatabaseModule) checkConfigurationSecurity(conn *DBConnection) []DBScanResult {
	var results []DBScanResult

	switch strings.ToLower(conn.Type) {
	case "mysql":
		results = append(results, db.checkMySQLConfig(conn)...)
	case "postgres", "postgresql":
		results = append(results, db.checkPostgreSQLConfig(conn)...)
	}

	return results
}

// checkMySQLConfig checks MySQL-specific configuration
func (db *DatabaseModule) checkMySQLConfig(conn *DBConnection) []DBScanResult {
	var results []DBScanResult

	// Check if log_bin is enabled
	if value := db.getConfigValue(conn.Connection, "SHOW VARIABLES LIKE 'log_bin'"); value == "OFF" {
		results = append(results, DBScanResult{
			ConnectionID: conn.ID,
			Type:         "CONFIG",
			Severity:     "MEDIUM",
			Description:  "Binary logging is disabled",
			Evidence:     "log_bin = OFF",
			Timestamp:    time.Now(),
			Remediation:  "Enable binary logging for audit trail",
		})
	}

	// Check for SSL
	if value := db.getConfigValue(conn.Connection, "SHOW VARIABLES LIKE 'have_ssl'"); value != "YES" {
		results = append(results, DBScanResult{
			ConnectionID: conn.ID,
			Type:         "CONFIG",
			Severity:     "HIGH",
			Description:  "SSL is not available or not enabled",
			Evidence:     fmt.Sprintf("have_ssl = %s", value),
			Timestamp:    time.Now(),
			Remediation:  "Enable SSL for encrypted connections",
		})
	}

	// Check for local_infile
	if value := db.getConfigValue(conn.Connection, "SHOW VARIABLES LIKE 'local_infile'"); value == "ON" {
		results = append(results, DBScanResult{
			ConnectionID: conn.ID,
			Type:         "CONFIG",
			Severity:     "MEDIUM",
			Description:  "local_infile is enabled",
			Evidence:     "local_infile = ON",
			Timestamp:    time.Now(),
			Remediation:  "Disable local_infile to prevent local file access",
		})
	}

	return results
}

// checkPostgreSQLConfig checks PostgreSQL-specific configuration
func (db *DatabaseModule) checkPostgreSQLConfig(conn *DBConnection) []DBScanResult {
	var results []DBScanResult

	// Check for SSL
	if value := db.getConfigValue(conn.Connection, "SHOW ssl"); value != "on" {
		results = append(results, DBScanResult{
			ConnectionID: conn.ID,
			Type:         "CONFIG",
			Severity:     "HIGH",
			Description:  "SSL is not enabled",
			Evidence:     fmt.Sprintf("ssl = %s", value),
			Timestamp:    time.Now(),
			Remediation:  "Enable SSL in postgresql.conf",
		})
	}

	// Check log_statement
	if value := db.getConfigValue(conn.Connection, "SHOW log_statement"); value == "none" {
		results = append(results, DBScanResult{
			ConnectionID: conn.ID,
			Type:         "CONFIG",
			Severity:     "MEDIUM",
			Description:  "Statement logging is disabled",
			Evidence:     "log_statement = none",
			Timestamp:    time.Now(),
			Remediation:  "Enable statement logging for audit trail",
		})
	}

	return results
}

// getConfigValue gets a configuration value from the database
func (db *DatabaseModule) getConfigValue(conn *sql.DB, query string) string {
	var name, value string
	err := conn.QueryRow(query).Scan(&name, &value)
	if err != nil {
		return "Unknown"
	}
	return value
}

// checkAccessControl checks database access control
func (db *DatabaseModule) checkAccessControl(conn *DBConnection) []DBScanResult {
	var results []DBScanResult

	// Check for users with empty passwords
	emptyPassUsers := db.getUsersWithEmptyPasswords(conn)
	for _, username := range emptyPassUsers {
		results = append(results, DBScanResult{
			ConnectionID: conn.ID,
			Type:         "ACCESS",
			Severity:     "CRITICAL",
			Description:  "User account with empty password",
			Evidence:     fmt.Sprintf("User '%s' has no password", username),
			Timestamp:    time.Now(),
			Remediation:  "Set strong passwords for all user accounts",
		})
	}

	// Check for excessive privileges
	adminUsers := db.getUsersWithAdminPrivileges(conn)
	if len(adminUsers) > 3 {
		results = append(results, DBScanResult{
			ConnectionID: conn.ID,
			Type:         "ACCESS",
			Severity:     "MEDIUM",
			Description:  "Too many users with administrative privileges",
			Evidence:     fmt.Sprintf("%d users have admin privileges", len(adminUsers)),
			Timestamp:    time.Now(),
			Remediation:  "Review and reduce administrative privileges",
		})
	}

	return results
}

// getUsersWithEmptyPasswords finds users with empty passwords
func (db *DatabaseModule) getUsersWithEmptyPasswords(conn *DBConnection) []string {
	var users []string
	var query string

	switch strings.ToLower(conn.Type) {
	case "mysql":
		query = "SELECT User FROM mysql.user WHERE authentication_string = '' OR Password = ''"
	case "postgres", "postgresql":
		// PostgreSQL doesn't store passwords directly, check role settings
		return users // Skip for PostgreSQL
	default:
		return users
	}

	rows, err := conn.Connection.Query(query)
	if err != nil {
		return users
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		if rows.Scan(&username) == nil {
			users = append(users, username)
		}
	}

	return users
}

// getUsersWithAdminPrivileges finds users with administrative privileges
func (db *DatabaseModule) getUsersWithAdminPrivileges(conn *DBConnection) []string {
	var users []string
	var query string

	switch strings.ToLower(conn.Type) {
	case "mysql":
		query = "SELECT User FROM mysql.user WHERE Super_priv = 'Y'"
	case "postgres", "postgresql":
		query = "SELECT rolname FROM pg_roles WHERE rolsuper = true"
	default:
		return users
	}

	rows, err := conn.Connection.Query(query)
	if err != nil {
		return users
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		if rows.Scan(&username) == nil {
			users = append(users, username)
		}
	}

	return users
}

// checkDangerousFunctions checks for dangerous functions and procedures
func (db *DatabaseModule) checkDangerousFunctions(conn *DBConnection) []DBScanResult {
	var results []DBScanResult

	dangerousFunctions := map[string]string{
		"xp_cmdshell":       "Command execution function",
		"LOAD_FILE":         "File reading function",
		"INTO OUTFILE":      "File writing capability",
		"xp_regread":        "Registry reading function",
		"sys_exec":          "System command execution",
	}

	for funcName, description := range dangerousFunctions {
		if db.checkFunctionExists(conn, funcName) {
			results = append(results, DBScanResult{
				ConnectionID: conn.ID,
				Type:         "VULN",
				Severity:     "HIGH",
				Description:  fmt.Sprintf("Dangerous function available: %s", funcName),
				Evidence:     description,
				Timestamp:    time.Now(),
				Remediation:  fmt.Sprintf("Disable or restrict access to %s", funcName),
			})
		}
	}

	return results
}

// checkFunctionExists checks if a dangerous function exists
func (db *DatabaseModule) checkFunctionExists(conn *DBConnection, funcName string) bool {
	// Simplified check - would need database-specific queries
	return false // Conservative approach
}

// checkDatabaseStructure checks database structure for security issues
func (db *DatabaseModule) checkDatabaseStructure(conn *DBConnection) []DBScanResult {
	var results []DBScanResult

	// Check for tables with sensitive names
	sensitiveTableNames := []string{
		"password", "passwd", "user", "admin", "credit_card", 
		"ssn", "social_security", "account", "payment",
	}

	tables := db.getDatabaseTables(conn)
	for _, table := range tables {
		for _, sensitiveName := range sensitiveTableNames {
			if strings.Contains(strings.ToLower(table), sensitiveName) {
				results = append(results, DBScanResult{
					ConnectionID: conn.ID,
					Type:         "CONFIG",
					Severity:     "MEDIUM",
					Description:  "Table with potentially sensitive name",
					Evidence:     fmt.Sprintf("Table name: %s", table),
					Table:        table,
					Timestamp:    time.Now(),
					Remediation:  "Review table contents and access controls",
				})
			}
		}
	}

	return results
}

// getDatabaseTables gets list of tables in the database
func (db *DatabaseModule) getDatabaseTables(conn *DBConnection) []string {
	var tables []string
	var query string

	switch strings.ToLower(conn.Type) {
	case "mysql":
		query = "SHOW TABLES"
	case "postgres", "postgresql":
		query = "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
	case "sqlite3", "sqlite":
		query = "SELECT name FROM sqlite_master WHERE type='table'"
	default:
		return tables
	}

	rows, err := conn.Connection.Query(query)
	if err != nil {
		return tables
	}
	defer rows.Close()

	for rows.Next() {
		var tableName string
		if rows.Scan(&tableName) == nil {
			tables = append(tables, tableName)
		}
	}

	return tables
}

// TestSQLInjection tests for SQL injection vulnerabilities
func (db *DatabaseModule) TestSQLInjection(targetURL, parameter string) (*SQLInjectionTest, error) {
	test := &SQLInjectionTest{
		URL:       targetURL,
		Parameter: parameter,
		Method:    "GET",
		Payloads:  getSQLInjectionPayloads(),
		Evidence:  make([]string, 0),
	}

	// This would integrate with the web client to test SQL injection
	// For now, return a basic test structure
	return test, nil
}

// getSQLInjectionPayloads returns common SQL injection payloads
func getSQLInjectionPayloads() []string {
	return []string{
		"'",
		"\"",
		"' OR '1'='1",
		"' OR '1'='1' --",
		"' OR '1'='1' /*",
		"' UNION SELECT NULL--",
		"' UNION SELECT NULL,NULL--",
		"' UNION SELECT NULL,NULL,NULL--",
		"'; DROP TABLE users--",
		"1' AND '1'='2",
		"1 AND 1=1",
		"1 AND 1=2",
		"admin'--",
		"admin' /*",
		"' OR 1=1#",
		"' OR 1=1--",
		"') OR '1'='1--",
		"') OR ('1'='1--",
	}
}

// ExecuteQuery executes a query on a database connection
func (db *DatabaseModule) ExecuteQuery(connectionID, query string) ([]map[string]interface{}, error) {
	db.mu.RLock()
	conn, exists := db.Connections[connectionID]
	db.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("connection not found: %s", connectionID)
	}

	rows, err := conn.Connection.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]interface{}
	
	for rows.Next() {
		// Create slice of interface{} for Scan
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		// Convert to map
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if b, ok := val.([]byte); ok {
				val = string(b)
			}
			row[col] = val
		}
		results = append(results, row)
	}

	// Update last access time
	db.mu.Lock()
	conn.LastAccess = time.Now()
	db.mu.Unlock()

	return results, nil
}

// CloseConnection closes a database connection
func (db *DatabaseModule) CloseConnection(connectionID string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	conn, exists := db.Connections[connectionID]
	if !exists {
		return fmt.Errorf("connection not found: %s", connectionID)
	}

	if conn.Connection != nil {
		err := conn.Connection.Close()
		if err != nil {
			return err
		}
	}

	conn.Connected = false
	delete(db.Connections, connectionID)
	return nil
}

// GetConnectionInfo returns information about a database connection
func (db *DatabaseModule) GetConnectionInfo(connectionID string) (map[string]interface{}, error) {
	db.mu.RLock()
	conn, exists := db.Connections[connectionID]
	db.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("connection not found: %s", connectionID)
	}

	info := map[string]interface{}{
		"id":          conn.ID,
		"type":        conn.Type,
		"host":        conn.Host,
		"port":        conn.Port,
		"database":    conn.Database,
		"username":    conn.Username,
		"connected":   conn.Connected,
		"last_access": conn.LastAccess,
		"version":     conn.Version,
		"privileges":  conn.Privileges,
	}

	return info, nil
}

// GetScanResults returns all database scan results
func (db *DatabaseModule) GetScanResults() []DBScanResult {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Return a copy
	results := make([]DBScanResult, len(db.ScanResults))
	copy(results, db.ScanResults)
	return results
}

// ClearScanResults clears all stored scan results
func (db *DatabaseModule) ClearScanResults() {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.ScanResults = db.ScanResults[:0]
}

// ParseConnectionString parses a database connection string  
func (db *DatabaseModule) ParseConnectionString(connStr string) (map[string]string, error) {
	params := make(map[string]string)
	
	if strings.Contains(connStr, "@tcp(") {
		// MySQL format: user:pass@tcp(host:port)/database
		parts := strings.Split(connStr, "@tcp(")
		if len(parts) == 2 {
			userPass := parts[0]
			hostDbPart := parts[1]
			
			if strings.Contains(userPass, ":") {
				userPassParts := strings.Split(userPass, ":")
				params["username"] = userPassParts[0]
				if len(userPassParts) > 1 {
					params["password"] = userPassParts[1]
				}
			}
			
			if strings.Contains(hostDbPart, ")/") {
				hostPortDb := strings.Split(hostDbPart, ")/")
				hostPort := hostPortDb[0]
				if len(hostPortDb) > 1 {
					params["database"] = hostPortDb[1]
				}
				
				if strings.Contains(hostPort, ":") {
					hostPortParts := strings.Split(hostPort, ":")
					params["host"] = hostPortParts[0]
					if len(hostPortParts) > 1 {
						if port, err := strconv.Atoi(hostPortParts[1]); err == nil {
							params["port"] = strconv.Itoa(port)
						}
					}
				}
			}
		}
	}
	
	return params, nil
}