package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	_ "github.com/microsoft/go-mssqldb"
	_ "github.com/microsoft/go-mssqldb/azuread"
)

// Safety tiers for SQL operations
type opTier int

const (
	tierRead      opTier = iota // SELECT, WITH, sp_help — no confirmation needed
	tierWrite                   // INSERT, UPDATE, DELETE, MERGE — requires confirm=true
	tierDangerous               // DROP, TRUNCATE, ALTER, GRANT, xp_ — requires confirm=true + non-prod
)

// Combined regex patterns for classification — single match per tier instead of 6+13 individual matches.
var writeRe = regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|MERGE|EXEC|EXECUTE)\b`)
var dangerousRe = regexp.MustCompile(`(?i)(\b(DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE|DENY|OPENROWSET|OPENDATASOURCE|sp_configure|SHUTDOWN)\b|\bBULK\s+INSERT\b|\bxp_)`)

// Production connections are determined by:
//  1. "prod": true in the config file (AZURE_SQL_CONFIG_FILE)
//  2. environment: "prod" or "production" in the config file
//  3. AZURE_SQL_PROD_CONNECTIONS env var (comma-separated, overrides all)
var prodConnections map[string]bool

// stripSQLNoise removes comments and string literals to prevent false positives
// in query classification. Order matters: block comments first, then line comments,
// then string literals (which may span lines with escaped quotes like ”).
var blockCommentRe = regexp.MustCompile(`/\*[\s\S]*?\*/`)
var lineCommentRe = regexp.MustCompile(`--[^\n]*`)
var stringLiteralRe = regexp.MustCompile(`N?'[^']*(?:''[^']*)*'`)

func stripSQLNoise(query string) string {
	q := blockCommentRe.ReplaceAllString(query, " ")
	q = lineCommentRe.ReplaceAllString(q, " ")
	q = stringLiteralRe.ReplaceAllString(q, " ")
	return q
}

// ODBC escape sequences can invoke stored procedures without EXEC keyword.
// {call sp_executesql(N'DROP TABLE X')} would bypass keyword detection.
var odbcCallRe = regexp.MustCompile(`(?i)\{\s*call\b`)

// Batch separators: semicolons followed by write keywords indicate multi-statement attacks.
var batchSepWriteRe = regexp.MustCompile(`(?i);\s*(INSERT|UPDATE|DELETE|MERGE|EXEC|EXECUTE|DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE|DENY)\b`)

func classifyQuery(query string) opTier {
	q := stripSQLNoise(strings.TrimSpace(query))

	// Block ODBC escape sequences that bypass keyword detection
	if odbcCallRe.MatchString(q) {
		return tierWrite
	}

	// Catch multi-statement injection: SELECT 1; DELETE FROM Users
	if batchSepWriteRe.MatchString(q) {
		return tierDangerous
	}

	// Single combined regex per tier (was 13+6 individual matches)
	if dangerousRe.MatchString(q) {
		return tierDangerous
	}
	if writeRe.MatchString(q) {
		return tierWrite
	}
	return tierRead
}

func isProd(connName string) bool {
	return prodConnections[connName]
}

// ── Connection registry ──
// Supports three configuration sources (merged in order, later overrides earlier):
//   1. AZURE_SQL_CONFIG_FILE — JSON file with full connection definitions
//   2. AZURE_SQL_CONNECTIONS — legacy env var (name=server/db;... format, Azure AD auth)
//   3. Runtime add_connection tool — add connections without restart

type authMode string

const (
	authAzureAD authMode = "azuread" // Azure AD DefaultAzureCredential (default)
	authSQL     authMode = "sql"     // SQL Server authentication (user/password)
	authConnStr authMode = "connstr" // Raw connection string passthrough
)

type connInfo struct {
	server      string
	database    string
	connStr     string   // built from other fields
	auth        authMode // azuread, sql, connstr
	environment string   // dev, qa, beta, test, preprod, prod
	description string
	appName     string
}

// configFileEntry is the JSON schema for AZURE_SQL_CONFIG_FILE
type configFileEntry struct {
	Name        string `json:"name"`
	Server      string `json:"server"`
	Database    string `json:"database"`
	Auth        string `json:"auth,omitempty"`              // "azuread" (default), "sql", "connstr"
	User        string `json:"user,omitempty"`              // for auth=sql
	Password    string `json:"password,omitempty"`          // for auth=sql
	ConnStr     string `json:"connection_string,omitempty"` // for auth=connstr
	Environment string `json:"environment,omitempty"`       // dev, qa, beta, test, preprod, prod
	Description string `json:"description,omitempty"`
	AppName     string `json:"app_name,omitempty"`
	Prod        bool   `json:"prod,omitempty"` // shorthand for marking as production
}

type configFile struct {
	Connections []configFileEntry `json:"connections"`
	Defaults    struct {
		Auth    string `json:"auth,omitempty"`
		AppName string `json:"app_name,omitempty"`
	} `json:"defaults,omitempty"`
}

var (
	connRegistry   map[string]connInfo
	connRegistryMu sync.RWMutex // protects connRegistry for runtime additions
)

func buildConnStr(server, database string, auth authMode, user, password, appName string) string {
	app := "azure-sql-mcp"
	if appName != "" {
		app = appName
	}

	switch auth {
	case authSQL:
		return fmt.Sprintf("server=%s;database=%s;user id=%s;password=%s;encrypt=true;TrustServerCertificate=false;app name=%s",
			server, database, user, password, app)
	case authConnStr:
		return "" // handled separately
	default: // authAzureAD
		return fmt.Sprintf("server=%s;database=%s;fedauth=ActiveDirectoryDefault;encrypt=true;TrustServerCertificate=false;app name=%s",
			server, database, app)
	}
}

func initConnRegistry() {
	connRegistry = map[string]connInfo{}
	prodConnections = map[string]bool{}

	defaultAuth := authAzureAD
	defaultAppName := "azure-sql-mcp"

	// Source 1: JSON config file
	if configPath := os.Getenv("AZURE_SQL_CONFIG_FILE"); configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			log.Printf("Warning: could not read config file %s: %v", configPath, err)
		} else {
			var cfg configFile
			if err := json.Unmarshal(data, &cfg); err != nil {
				log.Printf("Warning: could not parse config file %s: %v", configPath, err)
			} else {
				if cfg.Defaults.Auth != "" {
					defaultAuth = authMode(cfg.Defaults.Auth)
				}
				if cfg.Defaults.AppName != "" {
					defaultAppName = cfg.Defaults.AppName
				}
				for _, entry := range cfg.Connections {
					if entry.Name == "" || (entry.Server == "" && entry.ConnStr == "") {
						continue
					}
					auth := defaultAuth
					if entry.Auth != "" {
						auth = authMode(entry.Auth)
					}
					appName := defaultAppName
					if entry.AppName != "" {
						appName = entry.AppName
					}

					ci := connInfo{
						server:      entry.Server,
						database:    entry.Database,
						auth:        auth,
						environment: entry.Environment,
						description: entry.Description,
						appName:     appName,
					}

					if auth == authConnStr && entry.ConnStr != "" {
						ci.connStr = entry.ConnStr
					} else {
						ci.connStr = buildConnStr(entry.Server, entry.Database, auth, entry.User, entry.Password, appName)
					}

					connRegistry[entry.Name] = ci
					if entry.Prod {
						prodConnections[entry.Name] = true
					}
				}
				log.Printf("Config file: loaded %d connections from %s", len(cfg.Connections), configPath)
			}
		}
	}

	// Source 2: Legacy env var (backwards-compatible)
	if raw := os.Getenv("AZURE_SQL_CONNECTIONS"); raw != "" {
		envCount := 0
		for _, entry := range strings.Split(raw, ";") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			parts := strings.SplitN(entry, "=", 2)
			if len(parts) != 2 {
				continue
			}
			name := strings.TrimSpace(parts[0])
			serverDB := strings.TrimSpace(parts[1])
			serverParts := strings.SplitN(serverDB, "/", 2)
			if len(serverParts) != 2 {
				continue
			}
			// Don't override config file entries
			if _, exists := connRegistry[name]; exists {
				continue
			}
			connRegistry[name] = connInfo{
				server:   serverParts[0],
				database: serverParts[1],
				auth:     authAzureAD,
				connStr:  buildConnStr(serverParts[0], serverParts[1], authAzureAD, "", "", defaultAppName),
				appName:  defaultAppName,
			}
			envCount++
		}
		if envCount > 0 {
			log.Printf("Env var: loaded %d connections from AZURE_SQL_CONNECTIONS", envCount)
		}
	}

	// AZURE_SQL_PROD_CONNECTIONS: if set, replaces the default prod list entirely (comma-separated).
	// Config file entries with prod:true are additive regardless.
	if custom := os.Getenv("AZURE_SQL_PROD_CONNECTIONS"); custom != "" {
		prodConnections = map[string]bool{} // reset defaults
		for _, name := range strings.Split(custom, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				prodConnections[name] = true
			}
		}
	}
	// Also mark connections with environment=prod or prod:true flag as production
	for name, ci := range connRegistry {
		if strings.EqualFold(ci.environment, "prod") || strings.EqualFold(ci.environment, "production") {
			prodConnections[name] = true
		}
	}
	log.Printf("Production connections: %d", len(prodConnections))
}

// ── Connection pool cache ──
// Caches *sql.DB instances to avoid re-acquiring Azure AD tokens on every call.
// Tracks last successful use to skip unnecessary pings on rapid sequential calls.
var (
	dbPool     = map[string]*sql.DB{}
	dbPoolMu   sync.Mutex
	dbLastUsed = map[string]time.Time{} // last successful query time per connection
)

const pingSkipThreshold = 30 * time.Second // skip ping if used within this window

func getDB(connName string) (*sql.DB, error) {
	connRegistryMu.RLock()
	ci, ok := connRegistry[connName]
	connRegistryMu.RUnlock()
	if !ok {
		connRegistryMu.RLock()
		available := make([]string, 0, len(connRegistry))
		for k := range connRegistry {
			available = append(available, k)
		}
		connRegistryMu.RUnlock()
		sort.Strings(available)
		return nil, fmt.Errorf("unknown connection '%s'. Available: %s", connName, strings.Join(available, ", "))
	}

	dbPoolMu.Lock()
	db, cached := dbPool[connName]
	lastUsed := dbLastUsed[connName]
	if cached {
		// Skip ping if connection was successfully used recently
		if time.Since(lastUsed) < pingSkipThreshold {
			dbPoolMu.Unlock()
			return db, nil
		}
		dbPoolMu.Unlock()
		// Ping outside lock to verify stale connections
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := db.PingContext(ctx)
		cancel()
		if err == nil {
			dbPoolMu.Lock()
			dbLastUsed[connName] = time.Now()
			dbPoolMu.Unlock()
			return db, nil
		}
		// Stale — take lock to replace
		dbPoolMu.Lock()
		if dbPool[connName] == db {
			delete(dbPool, connName)
			db.Close()
		}
		// Fall through to create new connection while still holding lock
	}
	// Lock is held here (either from initial lock or stale path)

	// Check if another goroutine already created a new connection while we waited
	if existing, ok := dbPool[connName]; ok {
		dbPoolMu.Unlock()
		return existing, nil
	}

	// Use "azuresql" driver for Azure AD auth, "mssql" for SQL auth / raw connection strings
	driver := "azuresql"
	if ci.auth == authSQL || ci.auth == authConnStr {
		driver = "mssql"
	}
	newDB, err := sql.Open(driver, ci.connStr)
	if err != nil {
		dbPoolMu.Unlock()
		log.Printf("Connection open failed for '%s': %v", connName, err)
		return nil, fmt.Errorf("failed to open connection to '%s': %s", connName, sanitizeDBError(err))
	}
	newDB.SetConnMaxLifetime(10 * time.Minute)
	newDB.SetMaxOpenConns(5)
	newDB.SetMaxIdleConns(2)
	newDB.SetConnMaxIdleTime(5 * time.Minute)

	dbPool[connName] = newDB
	dbLastUsed[connName] = time.Now()
	dbPoolMu.Unlock()

	return newDB, nil
}

// bracketStripper is reused across calls (avoid allocation per call).
var bracketStripper = strings.NewReplacer("[", "", "]", "")

// parseSchemaTable splits "schema.table" or returns ("dbo", table).
// Strips SQL Server bracket quoting: [dbo].[Orders] → dbo, Orders
func parseSchemaTable(input string) (string, string) {
	clean := bracketStripper.Replace(strings.TrimSpace(input))
	if parts := strings.SplitN(clean, ".", 2); len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "dbo", clean
}

// ── Argument helpers ──
// Reduce boilerplate in handlers for extracting typed arguments.

func getStringArg(request mcp.CallToolRequest, key string) string {
	v, _ := request.GetArguments()[key].(string)
	return v
}

func getBoolArg(request mcp.CallToolRequest, key string) bool {
	v, _ := request.GetArguments()[key].(bool)
	return v
}

// requireArgs validates required string arguments and returns an error result if any are empty.
// Calls GetArguments() once and reuses the map.
func requireArgs(request mcp.CallToolRequest, keys ...string) (map[string]string, *mcp.CallToolResult) {
	args := request.GetArguments()
	vals := make(map[string]string, len(keys))
	for _, k := range keys {
		v, _ := args[k].(string)
		if v == "" {
			var missing []string
			for _, kk := range keys {
				vv, _ := args[kk].(string)
				if vv == "" {
					missing = append(missing, "'"+kk+"'")
				}
			}
			return nil, mcp.NewToolResultError(fmt.Sprintf("Required parameter(s) missing: %s", strings.Join(missing, ", ")))
		}
		vals[k] = v
	}
	return vals, nil
}

// auditLog logs every tool invocation for security audit trail.
func auditLog(tool, connName, detail string) {
	prod := ""
	if isProd(connName) {
		prod = " [PROD]"
	}
	log.Printf("AUDIT tool=%s conn=%s%s %s", tool, connName, prod, detail)
}

// getDBForTable is a convenience that validates connection + table args,
// gets the DB pool entry, and parses schema.table. Used by most schema handlers.
func getDBForTable(request mcp.CallToolRequest) (*sql.DB, string, string, *mcp.CallToolResult) {
	args, errResult := requireArgs(request, "connection", "table")
	if errResult != nil {
		return nil, "", "", errResult
	}
	db, err := getDB(args["connection"])
	if err != nil {
		return nil, "", "", mcp.NewToolResultError(err.Error())
	}
	schema, table := parseSchemaTable(args["table"])
	return db, schema, table, nil
}

// formatUniqueIdentifier converts a 16-byte SQL Server uniqueidentifier to
// standard GUID string format. SQL Server uses mixed-endian byte ordering:
// first 3 groups are little-endian, last 2 groups are big-endian.
func formatUniqueIdentifier(b []byte) string {
	if len(b) != 16 {
		return hex.EncodeToString(b)
	}
	// SQL Server mixed-endian: swap bytes in first 3 groups, then hex encode
	swapped := [16]byte{
		b[3], b[2], b[1], b[0], // group 1: little-endian → big-endian
		b[5], b[4], // group 2
		b[7], b[6], // group 3
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], // groups 4-5: already big-endian
	}
	h := hex.EncodeToString(swapped[:])
	// Insert dashes: 8-4-4-4-12
	return strings.ToUpper(h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32])
}

// sanitizeDBError strips connection string fragments from database errors
// to prevent leaking server FQDNs, database names, or auth details to MCP callers.
func sanitizeDBError(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "server=") || strings.Contains(msg, "database=") || strings.Contains(msg, "fedauth=") {
		log.Printf("Connection error (sanitized): %v", err)
		return "Database connection failed. Check Azure AD login and firewall rules."
	}
	return msg
}

// scanRows generically scans query results into []map[string]any.
// Returns results, column names, row count, and error.
func scanRows(rows *sql.Rows, maxRows int) ([]map[string]any, []string, int, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, nil, 0, err
	}

	// Get column types to detect uniqueidentifier
	colTypes, ctErr := rows.ColumnTypes()
	if ctErr != nil {
		log.Printf("Warning: could not get column types: %v", ctErr)
		colTypes = nil
	}

	// Pre-allocate scan targets outside the loop to reduce per-row allocations
	values := make([]any, len(columns))
	valuePtrs := make([]any, len(columns))
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	var results []map[string]any
	count := 0
	for rows.Next() {
		if count >= maxRows {
			break
		}
		// Reset scan targets (reuse slices allocated before loop)
		for i := range values {
			values[i] = nil
		}
		if err := rows.Scan(valuePtrs...); err != nil {
			return results, columns, count, err
		}
		row := make(map[string]any, len(columns))
		for i, col := range columns {
			switch v := values[i].(type) {
			case []byte:
				// 16-byte uniqueidentifier → format as GUID
				if len(v) == 16 && colTypes != nil && i < len(colTypes) &&
					strings.EqualFold(colTypes[i].DatabaseTypeName(), "UNIQUEIDENTIFIER") {
					row[col] = formatUniqueIdentifier(v)
				} else {
					row[col] = string(v)
				}
			case time.Time:
				row[col] = v.Format(time.RFC3339)
			default:
				row[col] = v
			}
		}
		results = append(results, row)
		count++
	}
	if err := rows.Err(); err != nil {
		return results, columns, count, err
	}
	return results, columns, count, nil
}

const version = "1.2.0"

// MCP tool annotation helpers for semantic hints to AI agents
func boolPtr(b bool) *bool { return &b }

var (
	readOnlyAnnotation = mcp.ToolAnnotation{
		Title:         "Read-only database query",
		ReadOnlyHint:  boolPtr(true),
		OpenWorldHint: boolPtr(true),
	}
	writeAnnotation = mcp.ToolAnnotation{
		Title:           "Database write operation",
		DestructiveHint: boolPtr(true),
		OpenWorldHint:   boolPtr(true),
	}
	metadataAnnotation = mcp.ToolAnnotation{
		Title:          "Connection metadata",
		ReadOnlyHint:   boolPtr(true),
		IdempotentHint: boolPtr(true),
	}
	schemaAnnotation = mcp.ToolAnnotation{
		Title:          "Database schema discovery",
		ReadOnlyHint:   boolPtr(true),
		IdempotentHint: boolPtr(true),
		OpenWorldHint:  boolPtr(true),
	}
	perfAnnotation = mcp.ToolAnnotation{
		Title:         "Performance diagnostics",
		ReadOnlyHint:  boolPtr(true),
		OpenWorldHint: boolPtr(true),
	}
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[azure-sql-mcp] ")

	// --version flag for operational debugging
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("azure-sql-mcp %s\n", version)
		os.Exit(0)
	}

	initConnRegistry()

	s := server.NewMCPServer(
		"Azure SQL MCP Server",
		version,
		server.WithToolCapabilities(true),
		server.WithLogging(),
	)

	// ── Read tools ──
	s.AddTool(mcp.NewTool("query",
		mcp.WithDescription("Execute a read-only SQL query (SELECT, WITH, sp_help) against an Azure SQL database. Uses Azure AD (Entra ID) auth via DefaultAzureCredential. For write operations use 'execute'."),
		mcp.WithToolAnnotation(readOnlyAnnotation),
		mcp.WithString("connection", mcp.Description("Connection name (e.g., 'my-dev-db', 'my-qa-db', 'my-prod-db')"), mcp.Required()),
		mcp.WithString("sql", mcp.Description("SQL query (must be read-only)"), mcp.Required()),
	), queryHandler)

	// ── Write tools ──
	s.AddTool(mcp.NewTool("execute",
		mcp.WithToolAnnotation(writeAnnotation),
		mcp.WithDescription("Execute a SQL statement that modifies data (INSERT, UPDATE, DELETE, CREATE, ALTER, EXEC). Requires confirm=true. On production databases, dangerous DDL (DROP, TRUNCATE, ALTER) is blocked."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("sql", mcp.Description("SQL statement to execute"), mcp.Required()),
		mcp.WithBoolean("confirm", mcp.Description("Safety gate — must be true. Review SQL before confirming."), mcp.Required()),
	), executeHandler)

	// ── Connection management ──
	s.AddTool(mcp.NewTool("list_connections",
		mcp.WithToolAnnotation(metadataAnnotation),
		mcp.WithDescription("List all configured Azure SQL database connections with server, database, and production status."),
	), listConnectionsHandler)

	s.AddTool(mcp.NewTool("test_connection",
		mcp.WithToolAnnotation(metadataAnnotation),
		mcp.WithDescription("Test connectivity to an Azure SQL database. Returns server version, database name, current user, and production status."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
	), testConnectionHandler)

	s.AddTool(mcp.NewTool("add_connection",
		mcp.WithToolAnnotation(metadataAnnotation),
		mcp.WithDescription("Add a new database connection at runtime (no restart needed). Supports Azure AD auth (default), SQL auth, or raw connection string. The connection persists for the lifetime of this MCP session."),
		mcp.WithString("name", mcp.Description("Connection name (e.g., 'my-dev-db')"), mcp.Required()),
		mcp.WithString("server", mcp.Description("Server FQDN (e.g., 'myserver.database.windows.net')")),
		mcp.WithString("database", mcp.Description("Database name")),
		mcp.WithString("auth", mcp.Description("Auth mode: 'azuread' (default), 'sql', or 'connstr'")),
		mcp.WithString("user", mcp.Description("Username (for auth=sql only)")),
		mcp.WithString("password", mcp.Description("Password (for auth=sql only)")),
		mcp.WithString("connection_string", mcp.Description("Raw connection string (for auth=connstr only)")),
		mcp.WithString("environment", mcp.Description("Environment tag: dev, qa, beta, test, preprod, prod")),
		mcp.WithString("description", mcp.Description("Human-readable description")),
		mcp.WithBoolean("prod", mcp.Description("Mark as production (enables safety gates)")),
	), addConnectionHandler)

	s.AddTool(mcp.NewTool("connection_info",
		mcp.WithToolAnnotation(metadataAnnotation),
		mcp.WithDescription("Get detailed metadata about a connection: server, database, auth mode, environment, production status, pool status, and description."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
	), connectionInfoHandler)

	// ── Schema discovery ──
	s.AddTool(mcp.NewTool("list_tables",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("List all tables in the database, grouped by schema."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("schema", mcp.Description("Filter by schema (optional, e.g., 'dbo')")),
	), listTablesHandler)

	s.AddTool(mcp.NewTool("describe_table",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("Get full schema of a table: columns, types, nullability, primary keys, defaults."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("table", mcp.Description("Table name (optionally schema-qualified, e.g., 'dbo.Orders')"), mcp.Required()),
	), describeTableHandler)

	s.AddTool(mcp.NewTool("describe_indexes",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("Get all indexes on a table: columns, uniqueness, type (clustered/nonclustered), included columns."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("table", mcp.Description("Table name (optionally schema-qualified)"), mcp.Required()),
	), describeIndexesHandler)

	s.AddTool(mcp.NewTool("describe_foreign_keys",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("Get all foreign key relationships for a table — both outgoing (this table references) and incoming (references this table)."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("table", mcp.Description("Table name (optionally schema-qualified)"), mcp.Required()),
	), describeForeignKeysHandler)

	s.AddTool(mcp.NewTool("search_columns",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("Search for columns by name pattern across all tables. Useful for finding where a field exists."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("pattern", mcp.Description("Column name pattern (SQL LIKE, e.g., '%CompanyId%')"), mcp.Required()),
	), searchColumnsHandler)

	s.AddTool(mcp.NewTool("table_row_counts",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("Get approximate row counts for all tables in a schema (fast, uses sys.partitions)."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("schema", mcp.Description("Schema name (default: 'dbo')")),
	), tableRowCountsHandler)

	// ── Views ──
	s.AddTool(mcp.NewTool("list_views",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("List all views in the database, optionally filtered by schema."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("schema", mcp.Description("Filter by schema (optional)")),
	), listViewsHandler)

	s.AddTool(mcp.NewTool("describe_view",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("Get the SQL definition of a view."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("name", mcp.Description("View name (optionally schema-qualified)"), mcp.Required()),
	), describeViewHandler)

	// ── Stored procedures ──
	s.AddTool(mcp.NewTool("list_stored_procs",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("List stored procedures, optionally filtered by schema or name pattern."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("schema", mcp.Description("Filter by schema (optional)")),
		mcp.WithString("pattern", mcp.Description("Name pattern (SQL LIKE, e.g., 'sp_SOM%')")),
	), listStoredProcsHandler)

	s.AddTool(mcp.NewTool("describe_sproc",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("Get stored procedure definition (source code) and parameters."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("name", mcp.Description("Proc name (optionally schema-qualified)"), mcp.Required()),
	), describeSprocHandler)

	// ── Functions ──
	s.AddTool(mcp.NewTool("list_functions",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("List user-defined functions (scalar, table-valued, inline), optionally filtered by schema."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("schema", mcp.Description("Filter by schema (optional)")),
	), listFunctionsHandler)

	s.AddTool(mcp.NewTool("describe_function",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("Get user-defined function definition and parameters."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("name", mcp.Description("Function name (optionally schema-qualified)"), mcp.Required()),
	), describeFunctionHandler)

	// ── Performance & diagnostics ──
	s.AddTool(mcp.NewTool("explain_query",
		mcp.WithToolAnnotation(perfAnnotation),
		mcp.WithDescription("Get the estimated execution plan for a SQL query (text format). Useful for performance analysis."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("sql", mcp.Description("SQL query to explain"), mcp.Required()),
	), explainQueryHandler)

	s.AddTool(mcp.NewTool("active_queries",
		mcp.WithToolAnnotation(perfAnnotation),
		mcp.WithDescription("Show currently executing queries on the database with their status, duration, wait type, and blocking info. Essential for debugging live performance issues."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
	), activeQueriesHandler)

	s.AddTool(mcp.NewTool("index_usage_stats",
		mcp.WithToolAnnotation(perfAnnotation),
		mcp.WithDescription("Get index usage statistics for a table: seeks, scans, lookups, updates. Identifies unused indexes and missing index recommendations."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("table", mcp.Description("Table name (optionally schema-qualified)"), mcp.Required()),
	), indexUsageStatsHandler)

	s.AddTool(mcp.NewTool("database_size",
		mcp.WithToolAnnotation(perfAnnotation),
		mcp.WithDescription("Get database size: total allocated, data files, log files, used and free space."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
	), databaseSizeHandler)

	s.AddTool(mcp.NewTool("search_objects",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("Search for any database object (table, view, procedure, function, trigger) by name pattern. The universal 'find anything' tool."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("pattern", mcp.Description("Object name pattern (SQL LIKE, e.g., '%Order%', '%VRS%')"), mcp.Required()),
	), searchObjectsHandler)

	s.AddTool(mcp.NewTool("describe_triggers",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("List all triggers on a table with their event type (INSERT/UPDATE/DELETE), timing (AFTER/INSTEAD OF), enabled status, and definition."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("table", mcp.Description("Table name (optionally schema-qualified)"), mcp.Required()),
	), describeTriggersHandler)

	s.AddTool(mcp.NewTool("missing_indexes",
		mcp.WithToolAnnotation(perfAnnotation),
		mcp.WithDescription("Get SQL Server's built-in missing index recommendations from DMVs. Shows potential improvement, impact, and the columns that should be indexed."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
	), missingIndexesHandler)

	s.AddTool(mcp.NewTool("top_queries_by_cpu",
		mcp.WithToolAnnotation(perfAnnotation),
		mcp.WithDescription("Get the top 20 most CPU-intensive queries from the plan cache. Shows total CPU time, execution count, and query text."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
	), topQueriesByCPUHandler)

	s.AddTool(mcp.NewTool("compare_tables",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("Compare the schema of a table across two database connections. Shows columns that are added, removed, or changed between environments (e.g., dev vs QA, QA vs prod)."),
		mcp.WithString("source", mcp.Description("Source connection name (e.g., 'my-dev-db')"), mcp.Required()),
		mcp.WithString("target", mcp.Description("Target connection name (e.g., 'my-qa-db')"), mcp.Required()),
		mcp.WithString("table", mcp.Description("Table name (optionally schema-qualified)"), mcp.Required()),
	), compareTablesHandler)

	// ── Advanced diagnostics ──
	s.AddTool(mcp.NewTool("wait_stats",
		mcp.WithToolAnnotation(perfAnnotation),
		mcp.WithDescription("Get server wait statistics — the #1 tool for Azure SQL performance triage. Shows top waits by total time, excluding benign system waits."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
	), waitStatsHandler)

	s.AddTool(mcp.NewTool("blocking_chains",
		mcp.WithToolAnnotation(perfAnnotation),
		mcp.WithDescription("Show the live blocking chain tree — who is blocking whom, with the head blocker at the top. Essential for deadlock and contention debugging."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
	), blockingChainsHandler)

	s.AddTool(mcp.NewTool("hangfire_dashboard",
		mcp.WithToolAnnotation(readOnlyAnnotation),
		mcp.WithDescription("Get Hangfire job processing status: queue depths, job states (last 24h), recent failures, and long-running jobs. Works on databases that have the HangFire schema."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
	), hangfireDashboardHandler)

	// ── Developer & compliance tools ──
	s.AddTool(mcp.NewTool("ef6_migration_status",
		mcp.WithToolAnnotation(schemaAnnotation),
		mcp.WithDescription("Show EF6 migration history from __MigrationHistory table. Lists applied migrations with timestamps, useful for comparing what's deployed across environments."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("context", mcp.Description("Context key filter (optional, e.g., 'LSP' to match LSP context)")),
	), ef6MigrationStatusHandler)

	s.AddTool(mcp.NewTool("table_statistics_health",
		mcp.WithToolAnnotation(perfAnnotation),
		mcp.WithDescription("Show stale/modified statistics across all tables. Identifies tables where statistics are outdated (high modification count relative to row count), which causes query plan regressions."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
	), tableStatisticsHealthHandler)

	s.AddTool(mcp.NewTool("long_running_queries",
		mcp.WithToolAnnotation(perfAnnotation),
		mcp.WithDescription("Show queries running longer than a threshold (default 10 seconds) with CPU time, reads, writes, and the current SQL text. Use for identifying runaway queries in production."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
		mcp.WithString("threshold_seconds", mcp.Description("Minimum duration in seconds (default: 10)")),
	), longRunningQueriesHandler)

	s.AddTool(mcp.NewTool("permission_audit",
		mcp.WithToolAnnotation(readOnlyAnnotation),
		mcp.WithDescription("List all database principals with their role memberships and object-level permissions. Essential for FDA 21 CFR Part 11 compliance audits and access control reviews."),
		mcp.WithString("connection", mcp.Description("Connection name"), mcp.Required()),
	), permissionAuditHandler)

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// ── Handlers ──

func queryHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, errResult := requireArgs(request, "connection", "sql")
	if errResult != nil {
		return errResult, nil
	}
	connName, sqlQuery := args["connection"], args["sql"]
	auditLog("query", connName, fmt.Sprintf("len=%d", len(sqlQuery)))
	if classifyQuery(sqlQuery) != tierRead {
		return mcp.NewToolResultError("This tool is for read-only queries (SELECT, WITH, sp_help). Use 'execute' for write operations."), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, sqlQuery)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	results, columns, rowCount, err := scanRows(rows, 500)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Scan error: %v", err)), nil
	}

	truncated := ""
	if rowCount >= 500 {
		truncated = "\n\n(Truncated at 500 rows. Use TOP or WHERE to narrow results.)"
	}

	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("JSON marshal error: %v", err)), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Returned %d rows, %d columns.%s\n\n%s", rowCount, len(columns), truncated, string(output))), nil
}

func executeHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, errResult := requireArgs(request, "connection", "sql")
	if errResult != nil {
		return errResult, nil
	}
	connName, sqlStmt := args["connection"], args["sql"]
	confirm := getBoolArg(request, "confirm")
	tier := classifyQuery(sqlStmt)
	auditLog("execute", connName, fmt.Sprintf("tier=%d confirm=%v len=%d", tier, confirm, len(sqlStmt)))

	if !confirm {
		return mcp.NewToolResultError("Safety gate: set confirm=true after reviewing the SQL."), nil
	}

	if tier == tierDangerous && isProd(connName) {
		return mcp.NewToolResultError(fmt.Sprintf("BLOCKED: Dangerous DDL on production database '%s'. Not allowed via this tool.", connName)), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	execCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	prodNote := ""
	if isProd(connName) {
		prodNote = fmt.Sprintf(" [PRODUCTION: %s]", connName)
	}

	// EXEC/EXECUTE may return result sets — use QueryContext to capture them.
	// Strip noise first so "-- comment\nEXEC sp_foo" is detected correctly.
	stripped := strings.TrimSpace(stripSQLNoise(sqlStmt))
	upperStripped := strings.ToUpper(stripped)
	isExec := strings.HasPrefix(upperStripped, "EXEC ") || strings.HasPrefix(upperStripped, "EXECUTE ") || upperStripped == "EXEC" || upperStripped == "EXECUTE"
	if isExec {
		rows, err := db.QueryContext(execCtx, sqlStmt)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Execution error: %v", err)), nil
		}
		defer rows.Close()

		results, _, rowCount, scanErr := scanRows(rows, 500)
		if scanErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Scan error: %v", scanErr)), nil
		}
		if rowCount > 0 {
			output, err := json.MarshalIndent(results, "", "  ")
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("JSON marshal error: %v", err)), nil
			}
			truncated := ""
			if rowCount >= 500 {
				truncated = "\n\n(Truncated at 500 rows.)"
			}
			return mcp.NewToolResultText(fmt.Sprintf("Executed. Returned %d rows.%s%s\n\n%s", rowCount, truncated, prodNote, string(output))), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Executed successfully.%s", prodNote)), nil
	}

	result, err := db.ExecContext(execCtx, sqlStmt)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Execution error: %v", err)), nil
	}

	rowsAffected, _ := result.RowsAffected()
	return mcp.NewToolResultText(fmt.Sprintf("OK. Rows affected: %d%s", rowsAffected, prodNote)), nil
}

func listConnectionsHandler(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connRegistryMu.RLock()
	if len(connRegistry) == 0 {
		connRegistryMu.RUnlock()
		return mcp.NewToolResultText("No connections configured. Set AZURE_SQL_CONNECTIONS or AZURE_SQL_CONFIG_FILE env var."), nil
	}

	names := make([]string, 0, len(connRegistry))
	for k := range connRegistry {
		names = append(names, k)
	}
	connRegistryMu.RUnlock()
	sort.Strings(names)

	dbPoolMu.Lock()
	poolSnapshot := make(map[string]bool, len(dbPool))
	for k := range dbPool {
		poolSnapshot[k] = true
	}
	dbPoolMu.Unlock()

	// Group by environment if available, otherwise flat list
	envGroups := map[string][]string{}
	var ungrouped []string
	connRegistryMu.RLock()
	for _, name := range names {
		ci := connRegistry[name]
		if ci.environment != "" {
			envGroups[ci.environment] = append(envGroups[ci.environment], name)
		} else {
			ungrouped = append(ungrouped, name)
		}
	}
	connRegistryMu.RUnlock()

	var lines []string
	formatConn := func(name string) string {
		connRegistryMu.RLock()
		ci := connRegistry[name]
		connRegistryMu.RUnlock()
		flags := ""
		if isProd(name) {
			flags += " [PROD]"
		}
		if poolSnapshot[name] {
			flags += " [CONNECTED]"
		}
		auth := string(ci.auth)
		if auth == "" {
			auth = "azuread"
		}
		desc := ""
		if ci.description != "" {
			desc = " — " + ci.description
		}
		return fmt.Sprintf("  %-30s %s/%s (%s)%s%s", name, ci.server, ci.database, auth, flags, desc)
	}

	if len(envGroups) > 0 {
		// Sort environment names with a sensible order
		envOrder := []string{"dev", "sqa", "qa", "beta", "delta", "test", "preprod", "prod", "production"}
		seen := map[string]bool{}
		for _, env := range envOrder {
			if conns, ok := envGroups[env]; ok {
				lines = append(lines, fmt.Sprintf("\n[%s]", strings.ToUpper(env)))
				for _, name := range conns {
					lines = append(lines, formatConn(name))
				}
				seen[env] = true
			}
		}
		// Any environments not in the predefined order
		for env, conns := range envGroups {
			if !seen[env] {
				lines = append(lines, fmt.Sprintf("\n[%s]", strings.ToUpper(env)))
				for _, name := range conns {
					lines = append(lines, formatConn(name))
				}
			}
		}
	}
	if len(ungrouped) > 0 {
		if len(envGroups) > 0 {
			lines = append(lines, "\n[UNGROUPED]")
		}
		for _, name := range ungrouped {
			lines = append(lines, formatConn(name))
		}
	}

	return mcp.NewToolResultText(fmt.Sprintf("Configured connections (%d):\n%s", len(names), strings.Join(lines, "\n"))), nil
}

func testConnectionHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connName, _ := request.GetArguments()["connection"].(string)
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}
	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var serverVersion, dbName, currentUser string
	var serverName sql.NullString
	err = db.QueryRowContext(queryCtx, "SELECT @@VERSION, DB_NAME(), SUSER_SNAME(), ISNULL(CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)), @@SERVERNAME)").Scan(&serverVersion, &dbName, &currentUser, &serverName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Connection failed: %v", err)), nil
	}

	prod := ""
	if isProd(connName) {
		prod = " [PRODUCTION]"
	}
	sn := "(unknown)"
	if serverName.Valid {
		sn = serverName.String
	}
	return mcp.NewToolResultText(fmt.Sprintf("Connected!%s\nServer: %s\nDatabase: %s\nUser: %s\nVersion: %s",
		prod, sn, dbName, currentUser, strings.Split(serverVersion, "\n")[0])), nil
}

func addConnectionHandler(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := getStringArg(request, "name")
	server := getStringArg(request, "server")
	database := getStringArg(request, "database")
	if name == "" {
		return mcp.NewToolResultError("'name' parameter is required"), nil
	}

	auth := authMode(getStringArg(request, "auth"))
	if auth == "" {
		auth = authAzureAD
	}
	if auth != authAzureAD && auth != authSQL && auth != authConnStr {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid auth mode '%s'. Use 'azuread', 'sql', or 'connstr'.", auth)), nil
	}

	user := getStringArg(request, "user")
	password := getStringArg(request, "password")
	rawConnStr := getStringArg(request, "connection_string")
	env := getStringArg(request, "environment")
	desc := getStringArg(request, "description")
	prod := getBoolArg(request, "prod")

	// Validate based on auth mode
	switch auth {
	case authAzureAD:
		if server == "" || database == "" {
			return mcp.NewToolResultError("'server' and 'database' are required for Azure AD auth."), nil
		}
	case authSQL:
		if server == "" || database == "" || user == "" || password == "" {
			return mcp.NewToolResultError("'server', 'database', 'user', and 'password' are required for SQL auth."), nil
		}
	case authConnStr:
		if rawConnStr == "" {
			return mcp.NewToolResultError("'connection_string' is required for connstr auth mode."), nil
		}
	}

	ci := connInfo{
		server:      server,
		database:    database,
		auth:        auth,
		environment: env,
		description: desc,
		appName:     "azure-sql-mcp",
	}
	if auth == authConnStr {
		ci.connStr = rawConnStr
	} else {
		ci.connStr = buildConnStr(server, database, auth, user, password, "azure-sql-mcp")
	}

	connRegistryMu.Lock()
	if _, exists := connRegistry[name]; exists {
		connRegistryMu.Unlock()
		return mcp.NewToolResultError(fmt.Sprintf("Connection '%s' already exists. Remove it first or use a different name.", name)), nil
	}
	connRegistry[name] = ci
	if prod || strings.EqualFold(env, "prod") || strings.EqualFold(env, "production") {
		prodConnections[name] = true
	}
	connRegistryMu.Unlock()

	auditLog("add_connection", name, fmt.Sprintf("server=%s db=%s auth=%s env=%s prod=%v", server, database, auth, env, prod))

	prodFlag := ""
	if isProd(name) {
		prodFlag = " [PROD]"
	}
	return mcp.NewToolResultText(fmt.Sprintf("Connection '%s' added successfully.%s\nServer: %s\nDatabase: %s\nAuth: %s\nEnvironment: %s",
		name, prodFlag, server, database, auth, env)), nil
}

func connectionInfoHandler(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := getStringArg(request, "connection")
	if name == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}

	connRegistryMu.RLock()
	ci, ok := connRegistry[name]
	connRegistryMu.RUnlock()
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("Unknown connection '%s'", name)), nil
	}

	dbPoolMu.Lock()
	_, connected := dbPool[name]
	dbPoolMu.Unlock()

	auth := string(ci.auth)
	if auth == "" {
		auth = "azuread"
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("Connection: %s", name))
	lines = append(lines, fmt.Sprintf("Server:     %s", ci.server))
	lines = append(lines, fmt.Sprintf("Database:   %s", ci.database))
	lines = append(lines, fmt.Sprintf("Auth:       %s", auth))
	if ci.environment != "" {
		lines = append(lines, fmt.Sprintf("Environment: %s", ci.environment))
	}
	if ci.description != "" {
		lines = append(lines, fmt.Sprintf("Description: %s", ci.description))
	}
	if ci.appName != "" {
		lines = append(lines, fmt.Sprintf("App Name:   %s", ci.appName))
	}
	lines = append(lines, fmt.Sprintf("Production: %v", isProd(name)))
	lines = append(lines, fmt.Sprintf("Connected:  %v", connected))

	return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
}

func listTablesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	connName, _ := args["connection"].(string)
	schemaFilter, _ := args["schema"].(string)
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE
		FROM INFORMATION_SCHEMA.TABLES
		WHERE (@p1 = '' OR TABLE_SCHEMA = @p1)
		ORDER BY TABLE_SCHEMA, TABLE_NAME`, schemaFilter)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	currentSchema := ""
	count := 0
	for rows.Next() {
		var schema, name, tableType string
		if err := rows.Scan(&schema, &name, &tableType); err != nil {
			continue
		}
		if schema != currentSchema {
			if currentSchema != "" {
				lines = append(lines, "")
			}
			lines = append(lines, fmt.Sprintf("[%s]", schema))
			currentSchema = schema
		}
		tt := "TABLE"
		if strings.Contains(tableType, "VIEW") {
			tt = "VIEW"
		}
		lines = append(lines, fmt.Sprintf("  %s (%s)", name, tt))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Found %d tables/views:\n\n%s", count, strings.Join(lines, "\n"))), nil
}

func describeTableHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	db, schema, tableName, errResult := getDBForTable(request)
	if errResult != nil {
		return errResult, nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT c.COLUMN_NAME, c.DATA_TYPE, c.CHARACTER_MAXIMUM_LENGTH, c.IS_NULLABLE,
			CASE WHEN pk.COLUMN_NAME IS NOT NULL THEN 'YES' ELSE 'NO' END AS IS_PRIMARY_KEY,
			c.COLUMN_DEFAULT
		FROM INFORMATION_SCHEMA.COLUMNS c
		LEFT JOIN (
			SELECT ku.TABLE_SCHEMA, ku.TABLE_NAME, ku.COLUMN_NAME
			FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
			JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE ku ON tc.CONSTRAINT_NAME = ku.CONSTRAINT_NAME
			WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
		) pk ON c.TABLE_SCHEMA = pk.TABLE_SCHEMA AND c.TABLE_NAME = pk.TABLE_NAME AND c.COLUMN_NAME = pk.COLUMN_NAME
		WHERE c.TABLE_SCHEMA = @p1 AND c.TABLE_NAME = @p2
		ORDER BY c.ORDINAL_POSITION`, schema, tableName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	lines = append(lines, fmt.Sprintf("Table: %s.%s\n", schema, tableName))
	lines = append(lines, fmt.Sprintf("%-30s %-15s %-6s %-4s %-4s %s", "Column", "Type", "MaxLen", "Null", "PK", "Default"))
	lines = append(lines, strings.Repeat("-", 90))

	count := 0
	for rows.Next() {
		var colName, dataType, isNullable, isPK string
		var maxLen, colDefault sql.NullString
		if err := rows.Scan(&colName, &dataType, &maxLen, &isNullable, &isPK, &colDefault); err != nil {
			continue
		}
		ml, def := "", ""
		if maxLen.Valid {
			ml = maxLen.String
		}
		if colDefault.Valid {
			def = colDefault.String
		}
		lines = append(lines, fmt.Sprintf("%-30s %-15s %-6s %-4s %-4s %s", colName, dataType, ml, isNullable, isPK, def))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("Table '%s.%s' not found or has no columns.", schema, tableName)), nil
	}
	return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
}

func describeIndexesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	db, schema, tableName, errResult := getDBForTable(request)
	if errResult != nil {
		return errResult, nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT i.name, i.type_desc, i.is_unique, i.is_primary_key,
			STRING_AGG(c.name, ', ') WITHIN GROUP (ORDER BY ic.key_ordinal) AS columns,
			STRING_AGG(CASE WHEN ic.is_included_column = 1 THEN c.name END, ', ') AS included_columns
		FROM sys.indexes i
		JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
		JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
		JOIN sys.tables t ON i.object_id = t.object_id
		JOIN sys.schemas s ON t.schema_id = s.schema_id
		WHERE s.name = @p1 AND t.name = @p2
		GROUP BY i.name, i.type_desc, i.is_unique, i.is_primary_key
		ORDER BY i.is_primary_key DESC, i.name`, schema, tableName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	lines = append(lines, fmt.Sprintf("Indexes on %s.%s:\n", schema, tableName))
	count := 0
	for rows.Next() {
		var idxName, idxType string
		var isUnique, isPK bool
		var cols string
		var inclCols sql.NullString
		if err := rows.Scan(&idxName, &idxType, &isUnique, &isPK, &cols, &inclCols); err != nil {
			continue
		}
		flags := ""
		if isPK {
			flags = " [PK]"
		} else if isUnique {
			flags = " [UNIQUE]"
		}
		line := fmt.Sprintf("  %s (%s)%s\n    Columns: %s", idxName, idxType, flags, cols)
		if inclCols.Valid && inclCols.String != "" {
			line += fmt.Sprintf("\n    Included: %s", inclCols.String)
		}
		lines = append(lines, line)
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No indexes found on %s.%s", schema, tableName)), nil
	}
	return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
}

func describeForeignKeysHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	db, schema, tableName, errResult := getDBForTable(request)
	if errResult != nil {
		return errResult, nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT fk.name, ps.name, pt.name, pc.name, rs.name, rt.name, rc.name,
			fk.delete_referential_action_desc, fk.update_referential_action_desc
		FROM sys.foreign_keys fk
		JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
		JOIN sys.tables pt ON fkc.parent_object_id = pt.object_id
		JOIN sys.schemas ps ON pt.schema_id = ps.schema_id
		JOIN sys.columns pc ON fkc.parent_object_id = pc.object_id AND fkc.parent_column_id = pc.column_id
		JOIN sys.tables rt ON fkc.referenced_object_id = rt.object_id
		JOIN sys.schemas rs ON rt.schema_id = rs.schema_id
		JOIN sys.columns rc ON fkc.referenced_object_id = rc.object_id AND fkc.referenced_column_id = rc.column_id
		WHERE (ps.name = @p1 AND pt.name = @p2) OR (rs.name = @p1 AND rt.name = @p2)
		ORDER BY fk.name, fkc.constraint_column_id`, schema, tableName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	lines = append(lines, fmt.Sprintf("Foreign keys involving %s.%s:\n", schema, tableName))
	count := 0
	for rows.Next() {
		var fkName, pSchema, pTable, pCol, rSchema, rTable, rCol, onDel, onUpd string
		if err := rows.Scan(&fkName, &pSchema, &pTable, &pCol, &rSchema, &rTable, &rCol, &onDel, &onUpd); err != nil {
			continue
		}
		dir := "OUT"
		if rSchema == schema && rTable == tableName {
			dir = "IN"
		}
		lines = append(lines, fmt.Sprintf("  %s [%s] %s.%s.%s -> %s.%s.%s  (DEL: %s, UPD: %s)",
			fkName, dir, pSchema, pTable, pCol, rSchema, rTable, rCol, onDel, onUpd))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No foreign keys found for %s.%s", schema, tableName)), nil
	}
	return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
}

func searchColumnsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	connName, _ := args["connection"].(string)
	pattern, _ := args["pattern"].(string)
	if connName == "" || pattern == "" {
		return mcp.NewToolResultError("Both 'connection' and 'pattern' parameters are required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE
		FROM INFORMATION_SCHEMA.COLUMNS
		WHERE COLUMN_NAME LIKE @p1
		ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION`, pattern)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	lines = append(lines, fmt.Sprintf("%-15s %-30s %-25s %-12s %-6s %-4s", "Schema", "Table", "Column", "Type", "Len", "Null"))
	lines = append(lines, strings.Repeat("-", 95))
	count := 0
	for rows.Next() {
		var s, t, c, dt, nullable string
		var ml sql.NullString
		if err := rows.Scan(&s, &t, &c, &dt, &ml, &nullable); err != nil {
			continue
		}
		l := ""
		if ml.Valid {
			l = ml.String
		}
		lines = append(lines, fmt.Sprintf("%-15s %-30s %-25s %-12s %-6s %-4s", s, t, c, dt, l, nullable))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No columns matching '%s'", pattern)), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Found %d columns:\n\n%s", count, strings.Join(lines, "\n"))), nil
}

func tableRowCountsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	connName, _ := args["connection"].(string)
	schemaFilter, _ := args["schema"].(string)
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}
	if schemaFilter == "" {
		schemaFilter = "dbo"
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT s.name, t.name, SUM(p.rows)
		FROM sys.tables t
		JOIN sys.schemas s ON t.schema_id = s.schema_id
		JOIN sys.partitions p ON t.object_id = p.object_id AND p.index_id IN (0, 1)
		WHERE s.name = @p1
		GROUP BY s.name, t.name
		ORDER BY SUM(p.rows) DESC`, schemaFilter)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	lines = append(lines, fmt.Sprintf("%-40s %15s", "Table", "Rows (approx)"))
	lines = append(lines, strings.Repeat("-", 56))
	total, count := int64(0), 0
	for rows.Next() {
		var sn, tn string
		var rc int64
		if err := rows.Scan(&sn, &tn, &rc); err != nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("%-40s %15d", sn+"."+tn, rc))
		total += rc
		count++
	}
	lines = append(lines, strings.Repeat("-", 56))
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	lines = append(lines, fmt.Sprintf("%-40s %15d", fmt.Sprintf("TOTAL (%d tables)", count), total))
	return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
}

func listViewsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	connName, _ := args["connection"].(string)
	schemaFilter, _ := args["schema"].(string)
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT s.name, v.name, v.modify_date
		FROM sys.views v JOIN sys.schemas s ON v.schema_id = s.schema_id
		WHERE (@p1 = '' OR s.name = @p1) ORDER BY s.name, v.name`, schemaFilter)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	count, curSchema := 0, ""
	for rows.Next() {
		var sn, vn string
		var md time.Time
		if err := rows.Scan(&sn, &vn, &md); err != nil {
			continue
		}
		if sn != curSchema {
			if curSchema != "" {
				lines = append(lines, "")
			}
			lines = append(lines, fmt.Sprintf("[%s]", sn))
			curSchema = sn
		}
		lines = append(lines, fmt.Sprintf("  %s (modified: %s)", vn, md.Format("2006-01-02")))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText("No views found."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Found %d views:\n\n%s", count, strings.Join(lines, "\n"))), nil
}

func describeViewHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	connName, _ := args["connection"].(string)
	name, _ := args["name"].(string)
	if connName == "" || name == "" {
		return mcp.NewToolResultError("Both 'connection' and 'name' parameters are required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	schema, viewName := parseSchemaTable(name)
	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	fullName := schema + "." + viewName
	var def sql.NullString
	err = db.QueryRowContext(queryCtx, "SELECT OBJECT_DEFINITION(OBJECT_ID(@p1))", fullName).Scan(&def)
	if err != nil || !def.Valid {
		return mcp.NewToolResultError(fmt.Sprintf("Could not retrieve definition for view %s", fullName)), nil
	}
	d := def.String
	if len(d) > 50000 {
		d = d[:50000] + "\n\n[TRUNCATED]"
	}
	return mcp.NewToolResultText(fmt.Sprintf("View: %s\n\n%s", fullName, d)), nil
}

func listStoredProcsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	connName, _ := args["connection"].(string)
	schemaFilter, _ := args["schema"].(string)
	pattern, _ := args["pattern"].(string)
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT s.name, p.name, p.modify_date
		FROM sys.procedures p JOIN sys.schemas s ON p.schema_id = s.schema_id
		WHERE (@p1 = '' OR s.name = @p1) AND (@p2 = '' OR p.name LIKE @p2)
		ORDER BY s.name, p.name`, schemaFilter, pattern)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	count, curSchema := 0, ""
	for rows.Next() {
		var sn, pn string
		var md time.Time
		if err := rows.Scan(&sn, &pn, &md); err != nil {
			continue
		}
		if sn != curSchema {
			if curSchema != "" {
				lines = append(lines, "")
			}
			lines = append(lines, fmt.Sprintf("[%s]", sn))
			curSchema = sn
		}
		lines = append(lines, fmt.Sprintf("  %s (modified: %s)", pn, md.Format("2006-01-02")))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText("No stored procedures found."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Found %d stored procedures:\n\n%s", count, strings.Join(lines, "\n"))), nil
}

func describeSprocHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	connName, _ := args["connection"].(string)
	name, _ := args["name"].(string)
	if connName == "" || name == "" {
		return mcp.NewToolResultError("Both 'connection' and 'name' parameters are required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	schema, procName := parseSchemaTable(name)
	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Parameters
	paramRows, err := db.QueryContext(queryCtx, `
		SELECT p.name, TYPE_NAME(p.user_type_id), p.max_length, p.is_output
		FROM sys.parameters p
		JOIN sys.procedures pr ON p.object_id = pr.object_id
		JOIN sys.schemas s ON pr.schema_id = s.schema_id
		WHERE s.name = @p1 AND pr.name = @p2
		ORDER BY p.parameter_id`, schema, procName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer paramRows.Close()

	var paramLines []string
	for paramRows.Next() {
		var pn, tn string
		var ml int
		var isOut bool
		if err := paramRows.Scan(&pn, &tn, &ml, &isOut); err != nil {
			continue
		}
		dir := "IN"
		if isOut {
			dir = "OUT"
		}
		paramLines = append(paramLines, fmt.Sprintf("  %s %s(%d) [%s]", pn, tn, ml, dir))
	}
	if err := paramRows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error reading parameters: %v", err)), nil
	}

	// Definition
	fullName := schema + "." + procName
	var def sql.NullString
	err = db.QueryRowContext(queryCtx, "SELECT OBJECT_DEFINITION(OBJECT_ID(@p1))", fullName).Scan(&def)
	if err != nil || !def.Valid {
		return mcp.NewToolResultError(fmt.Sprintf("Could not retrieve definition for %s", fullName)), nil
	}
	d := def.String
	if len(d) > 50000 {
		d = d[:50000] + "\n\n[TRUNCATED]"
	}

	params := "(none)"
	if len(paramLines) > 0 {
		params = strings.Join(paramLines, "\n")
	}
	return mcp.NewToolResultText(fmt.Sprintf("Stored Procedure: %s\n\nParameters:\n%s\n\nDefinition:\n%s", fullName, params, d)), nil
}

func listFunctionsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	connName, _ := args["connection"].(string)
	schemaFilter, _ := args["schema"].(string)
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT s.name, o.name, o.type_desc, o.modify_date
		FROM sys.objects o JOIN sys.schemas s ON o.schema_id = s.schema_id
		WHERE o.type IN ('FN','IF','TF') AND (@p1 = '' OR s.name = @p1)
		ORDER BY s.name, o.name`, schemaFilter)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	count, curSchema := 0, ""
	for rows.Next() {
		var sn, fn, td string
		var md time.Time
		if err := rows.Scan(&sn, &fn, &td, &md); err != nil {
			continue
		}
		if sn != curSchema {
			if curSchema != "" {
				lines = append(lines, "")
			}
			lines = append(lines, fmt.Sprintf("[%s]", sn))
			curSchema = sn
		}
		lines = append(lines, fmt.Sprintf("  %s (%s, modified: %s)", fn, td, md.Format("2006-01-02")))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText("No user-defined functions found."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Found %d functions:\n\n%s", count, strings.Join(lines, "\n"))), nil
}

func describeFunctionHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	connName, _ := args["connection"].(string)
	name, _ := args["name"].(string)
	if connName == "" || name == "" {
		return mcp.NewToolResultError("Both 'connection' and 'name' parameters are required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	schema, funcName := parseSchemaTable(name)
	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	fullName := schema + "." + funcName
	var def sql.NullString
	err = db.QueryRowContext(queryCtx, "SELECT OBJECT_DEFINITION(OBJECT_ID(@p1))", fullName).Scan(&def)
	if err != nil || !def.Valid {
		return mcp.NewToolResultError(fmt.Sprintf("Could not retrieve definition for function %s", fullName)), nil
	}
	d := def.String
	if len(d) > 50000 {
		d = d[:50000] + "\n\n[TRUNCATED]"
	}
	return mcp.NewToolResultText(fmt.Sprintf("Function: %s\n\n%s", fullName, d)), nil
}

func explainQueryHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	connName, _ := args["connection"].(string)
	sqlQuery, _ := args["sql"].(string)
	if connName == "" || sqlQuery == "" {
		return mcp.NewToolResultError("Both 'connection' and 'sql' parameters are required"), nil
	}
	if classifyQuery(sqlQuery) != tierRead {
		return mcp.NewToolResultError("Can only explain read-only queries (SELECT, WITH). Use the query tool to verify your SQL first."), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Use a dedicated connection so SET SHOWPLAN is session-scoped correctly
	conn, err := db.Conn(queryCtx)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get connection: %v", err)), nil
	}
	defer conn.Close()

	// SHOWPLAN_ALL returns multiple result sets with operator details, estimated rows, IO/CPU cost.
	// Falls back to SHOWPLAN_TEXT if SHOWPLAN_ALL is not available.
	showplanCmd := "SET SHOWPLAN_ALL ON"
	showplanOff := "SET SHOWPLAN_ALL OFF"
	if _, err := conn.ExecContext(queryCtx, showplanCmd); err != nil {
		// Fallback to SHOWPLAN_TEXT
		showplanCmd = "SET SHOWPLAN_TEXT ON"
		showplanOff = "SET SHOWPLAN_TEXT OFF"
		if _, err := conn.ExecContext(queryCtx, showplanCmd); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to enable SHOWPLAN: %v", err)), nil
		}
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		conn.ExecContext(cleanupCtx, showplanOff)
	}()

	rows, err := conn.QueryContext(queryCtx, sqlQuery)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	// SHOWPLAN_ALL returns multiple columns; collect all result sets
	var planLines []string
	cols, _ := rows.Columns()
	if len(cols) > 1 {
		// SHOWPLAN_ALL: format as table with StmtText, EstimateRows, EstimateIO, EstimateCPU, TotalSubtreeCost
		planLines = append(planLines, fmt.Sprintf("%-80s %12s %10s %10s %12s", "Operator", "Est.Rows", "Est.IO", "Est.CPU", "SubtreeCost"))
		planLines = append(planLines, strings.Repeat("-", 130))
		for rows.Next() {
			scanVals := make([]any, len(cols))
			scanPtrs := make([]any, len(cols))
			for i := range scanVals {
				scanPtrs[i] = &scanVals[i]
			}
			if err := rows.Scan(scanPtrs...); err != nil {
				continue
			}
			// Extract key columns by name
			colMap := make(map[string]any)
			for i, c := range cols {
				colMap[c] = scanVals[i]
			}
			stmtText := fmt.Sprintf("%v", colMap["StmtText"])
			estRows := ""
			if v, ok := colMap["EstimateRows"]; ok && v != nil {
				estRows = fmt.Sprintf("%.0f", v)
			}
			estIO := ""
			if v, ok := colMap["EstimateIO"]; ok && v != nil {
				estIO = fmt.Sprintf("%.4f", v)
			}
			estCPU := ""
			if v, ok := colMap["EstimateCPU"]; ok && v != nil {
				estCPU = fmt.Sprintf("%.4f", v)
			}
			subtreeCost := ""
			if v, ok := colMap["TotalSubtreeCost"]; ok && v != nil {
				subtreeCost = fmt.Sprintf("%.4f", v)
			}
			// Truncate long operator text
			if len(stmtText) > 80 {
				stmtText = stmtText[:77] + "..."
			}
			planLines = append(planLines, fmt.Sprintf("%-80s %12s %10s %10s %12s", stmtText, estRows, estIO, estCPU, subtreeCost))
		}
	} else {
		// SHOWPLAN_TEXT fallback: single column
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				continue
			}
			planLines = append(planLines, line)
		}
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if len(planLines) == 0 {
		return mcp.NewToolResultText("No execution plan returned."), nil
	}
	return mcp.NewToolResultText("Estimated Execution Plan:\n\n" + strings.Join(planLines, "\n")), nil
}

func activeQueriesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connName, _ := request.GetArguments()["connection"].(string)
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT
			r.session_id,
			r.status,
			r.command,
			DATEDIFF(SECOND, r.start_time, GETDATE()) AS duration_sec,
			r.wait_type,
			r.blocking_session_id,
			r.open_transaction_count,
			DB_NAME(r.database_id) AS database_name,
			SUBSTRING(t.text, (r.statement_start_offset/2)+1,
				CASE WHEN r.statement_end_offset = -1 THEN LEN(t.text)
				ELSE (r.statement_end_offset - r.statement_start_offset)/2 END) AS current_statement,
			s.login_name,
			s.host_name,
			s.program_name
		FROM sys.dm_exec_requests r
		JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
		CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
		WHERE r.session_id != @@SPID AND s.is_user_process = 1
		ORDER BY r.start_time`)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	count := 0
	for rows.Next() {
		var sessionID, durationSec, blockingID, openTxn int
		var status, command, dbName, loginName string
		var waitType, currentStmt, hostName, programName sql.NullString
		if err := rows.Scan(&sessionID, &status, &command, &durationSec, &waitType, &blockingID, &openTxn, &dbName, &currentStmt, &loginName, &hostName, &programName); err != nil {
			continue
		}
		wt := ""
		if waitType.Valid && waitType.String != "" {
			wt = fmt.Sprintf(" wait=%s", waitType.String)
		}
		blocking := ""
		if blockingID > 0 {
			blocking = fmt.Sprintf(" BLOCKED_BY=%d", blockingID)
		}
		stmt := "(unavailable)"
		if currentStmt.Valid {
			stmt = strings.TrimSpace(currentStmt.String)
			if len(stmt) > 200 {
				stmt = stmt[:200] + "..."
			}
		}
		host := ""
		if hostName.Valid {
			host = hostName.String
		}
		lines = append(lines, fmt.Sprintf("  [%d] %s %ds %s@%s%s%s\n    %s\n",
			sessionID, status, durationSec, loginName, host, wt, blocking, stmt))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText("No active user queries."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Active queries (%d):\n\n%s", count, strings.Join(lines, "\n"))), nil
}

func indexUsageStatsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	db, schema, tableName, errResult := getDBForTable(request)
	if errResult != nil {
		return errResult, nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT i.name, i.type_desc,
			ISNULL(us.user_seeks, 0), ISNULL(us.user_scans, 0),
			ISNULL(us.user_lookups, 0), ISNULL(us.user_updates, 0),
			ISNULL(us.last_user_seek, '1900-01-01'), ISNULL(us.last_user_scan, '1900-01-01')
		FROM sys.indexes i
		JOIN sys.tables t ON i.object_id = t.object_id
		JOIN sys.schemas s ON t.schema_id = s.schema_id
		LEFT JOIN sys.dm_db_index_usage_stats us ON i.object_id = us.object_id AND i.index_id = us.index_id AND us.database_id = DB_ID()
		WHERE s.name = @p1 AND t.name = @p2 AND i.name IS NOT NULL
		ORDER BY ISNULL(us.user_seeks,0) + ISNULL(us.user_scans,0) DESC`, schema, tableName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	lines = append(lines, fmt.Sprintf("Index usage stats for %s.%s:\n", schema, tableName))
	lines = append(lines, fmt.Sprintf("%-35s %-14s %8s %8s %8s %8s %s", "Index", "Type", "Seeks", "Scans", "Lookups", "Updates", "Last Used"))
	lines = append(lines, strings.Repeat("-", 110))
	count := 0
	for rows.Next() {
		var idxName, idxType string
		var seeks, scans, lookups, updates int64
		var lastSeek, lastScan time.Time
		if err := rows.Scan(&idxName, &idxType, &seeks, &scans, &lookups, &updates, &lastSeek, &lastScan); err != nil {
			continue
		}
		lastUsed := lastSeek
		if lastScan.After(lastUsed) {
			lastUsed = lastScan
		}
		lu := "never"
		if lastUsed.Year() > 1900 {
			lu = lastUsed.Format("2006-01-02")
		}
		warning := ""
		if seeks == 0 && scans == 0 && lookups == 0 && updates > 0 {
			warning = " [UNUSED - write overhead only]"
		}
		lines = append(lines, fmt.Sprintf("%-35s %-14s %8d %8d %8d %8d %s%s",
			idxName, idxType, seeks, scans, lookups, updates, lu, warning))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No index stats for %s.%s", schema, tableName)), nil
	}
	return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
}

func databaseSizeHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connName, _ := request.GetArguments()["connection"].(string)
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var dbNameResult string
	var totalMB, dataMB, logMB, usedMB int64
	err = db.QueryRowContext(queryCtx, `
		SELECT DB_NAME(),
			SUM(size) * 8 / 1024,
			SUM(CASE WHEN type = 0 THEN size ELSE 0 END) * 8 / 1024,
			SUM(CASE WHEN type = 1 THEN size ELSE 0 END) * 8 / 1024,
			SUM(FILEPROPERTY(name, 'SpaceUsed')) * 8 / 1024
		FROM sys.database_files`).Scan(&dbNameResult, &totalMB, &dataMB, &logMB, &usedMB)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Database: %s\n\nTotal: %d MB\nData: %d MB\nLog: %d MB\nUsed: %d MB\nFree: %d MB",
		dbNameResult, totalMB, dataMB, logMB, usedMB, totalMB-usedMB)), nil
}

func searchObjectsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	connName, _ := args["connection"].(string)
	pattern, _ := args["pattern"].(string)
	if connName == "" || pattern == "" {
		return mcp.NewToolResultError("Both 'connection' and 'pattern' parameters are required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT s.name AS schema_name, o.name AS object_name,
			CASE o.type
				WHEN 'U'  THEN 'TABLE'
				WHEN 'V'  THEN 'VIEW'
				WHEN 'P'  THEN 'PROCEDURE'
				WHEN 'FN' THEN 'SCALAR FUNCTION'
				WHEN 'IF' THEN 'INLINE TABLE FUNCTION'
				WHEN 'TF' THEN 'TABLE FUNCTION'
				WHEN 'TR' THEN 'TRIGGER'
				WHEN 'SN' THEN 'SYNONYM'
				ELSE RTRIM(o.type)
			END AS object_type,
			o.modify_date
		FROM sys.objects o
		JOIN sys.schemas s ON o.schema_id = s.schema_id
		WHERE o.name LIKE @p1 AND o.is_ms_shipped = 0
		ORDER BY
			CASE o.type WHEN 'U' THEN 1 WHEN 'V' THEN 2 WHEN 'P' THEN 3 ELSE 4 END,
			s.name, o.name`, pattern)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	lines = append(lines, fmt.Sprintf("%-15s %-40s %-22s %s", "Schema", "Name", "Type", "Modified"))
	lines = append(lines, strings.Repeat("-", 90))
	count := 0
	for rows.Next() {
		var sn, on, ot string
		var md time.Time
		if err := rows.Scan(&sn, &on, &ot, &md); err != nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("%-15s %-40s %-22s %s", sn, on, ot, md.Format("2006-01-02")))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No objects matching '%s'", pattern)), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Found %d objects matching '%s':\n\n%s", count, pattern, strings.Join(lines, "\n"))), nil
}

func describeTriggersHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	db, schema, tableName, errResult := getDBForTable(request)
	if errResult != nil {
		return errResult, nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT tr.name,
			CASE WHEN te.type_desc = 'INSERT' THEN 1 ELSE 0 END AS is_insert,
			CASE WHEN te.type_desc = 'UPDATE' THEN 1 ELSE 0 END AS is_update,
			CASE WHEN te.type_desc = 'DELETE' THEN 1 ELSE 0 END AS is_delete,
			CASE WHEN tr.is_instead_of_trigger = 1 THEN 'INSTEAD OF' ELSE 'AFTER' END AS timing,
			CASE WHEN tr.is_disabled = 1 THEN 'DISABLED' ELSE 'ENABLED' END AS status,
			tr.modify_date,
			OBJECT_DEFINITION(tr.object_id) AS definition
		FROM sys.triggers tr
		JOIN sys.trigger_events te ON tr.object_id = te.object_id
		JOIN sys.tables t ON tr.parent_id = t.object_id
		JOIN sys.schemas s ON t.schema_id = s.schema_id
		WHERE s.name = @p1 AND t.name = @p2
		ORDER BY tr.name, te.type_desc`, schema, tableName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	type triggerInfo struct {
		name       string
		events     []string
		timing     string
		status     string
		modified   time.Time
		definition string
	}
	triggers := map[string]*triggerInfo{}
	var order []string

	for rows.Next() {
		var name, timing, status string
		var isIns, isUpd, isDel int
		var md time.Time
		var def sql.NullString
		if err := rows.Scan(&name, &isIns, &isUpd, &isDel, &timing, &status, &md, &def); err != nil {
			continue
		}
		ti, exists := triggers[name]
		if !exists {
			d := ""
			if def.Valid {
				d = def.String
				if len(d) > 5000 {
					d = d[:5000] + "\n...[TRUNCATED]"
				}
			}
			ti = &triggerInfo{name: name, timing: timing, status: status, modified: md, definition: d}
			triggers[name] = ti
			order = append(order, name)
		}
		if isIns == 1 {
			ti.events = append(ti.events, "INSERT")
		}
		if isUpd == 1 {
			ti.events = append(ti.events, "UPDATE")
		}
		if isDel == 1 {
			ti.events = append(ti.events, "DELETE")
		}
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}

	if len(triggers) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No triggers on %s.%s", schema, tableName)), nil
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("Triggers on %s.%s:\n", schema, tableName))
	for _, name := range order {
		ti := triggers[name]
		events := strings.Join(ti.events, ", ")
		lines = append(lines, fmt.Sprintf("  %s [%s] %s %s (modified: %s)\n\n%s\n",
			ti.name, ti.status, ti.timing, events, ti.modified.Format("2006-01-02"), ti.definition))
	}
	return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
}

func missingIndexesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connName, _ := request.GetArguments()["connection"].(string)
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT TOP 30
			OBJECT_SCHEMA_NAME(mid.object_id) AS schema_name,
			OBJECT_NAME(mid.object_id) AS table_name,
			ROUND(migs.avg_total_user_cost * migs.avg_user_impact * (migs.user_seeks + migs.user_scans), 0) AS improvement_measure,
			migs.user_seeks,
			migs.user_scans,
			mid.equality_columns,
			mid.inequality_columns,
			mid.included_columns
		FROM sys.dm_db_missing_index_groups mig
		JOIN sys.dm_db_missing_index_group_stats migs ON mig.index_group_handle = migs.group_handle
		JOIN sys.dm_db_missing_index_details mid ON mig.index_handle = mid.index_handle
		WHERE mid.database_id = DB_ID()
		ORDER BY improvement_measure DESC`)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error (may require VIEW SERVER STATE permission): %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	lines = append(lines, fmt.Sprintf("%-15s %-30s %12s %8s %8s", "Schema", "Table", "Impact", "Seeks", "Scans"))
	lines = append(lines, strings.Repeat("-", 80))
	count := 0
	for rows.Next() {
		var sn, tn string
		var impact float64
		var seeks, scans int64
		var eqCols, ineqCols, inclCols sql.NullString
		if err := rows.Scan(&sn, &tn, &impact, &seeks, &scans, &eqCols, &ineqCols, &inclCols); err != nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("%-15s %-30s %12.0f %8d %8d", sn, tn, impact, seeks, scans))
		if eqCols.Valid && eqCols.String != "" {
			lines = append(lines, fmt.Sprintf("    Equality:   %s", eqCols.String))
		}
		if ineqCols.Valid && ineqCols.String != "" {
			lines = append(lines, fmt.Sprintf("    Inequality: %s", ineqCols.String))
		}
		if inclCols.Valid && inclCols.String != "" {
			lines = append(lines, fmt.Sprintf("    Include:    %s", inclCols.String))
		}
		lines = append(lines, "")
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText("No missing index recommendations."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Top %d missing index recommendations:\n\n%s", count, strings.Join(lines, "\n"))), nil
}

func topQueriesByCPUHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connName, _ := request.GetArguments()["connection"].(string)
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}

	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT TOP 20
			qs.total_worker_time / 1000 AS total_cpu_ms,
			qs.execution_count,
			qs.total_worker_time / NULLIF(qs.execution_count, 0) / 1000 AS avg_cpu_ms,
			qs.total_elapsed_time / NULLIF(qs.execution_count, 0) / 1000 AS avg_elapsed_ms,
			qs.total_logical_reads / NULLIF(qs.execution_count, 0) AS avg_logical_reads,
			SUBSTRING(t.text, (qs.statement_start_offset/2)+1,
				CASE WHEN qs.statement_end_offset = -1 THEN LEN(t.text)
				ELSE (qs.statement_end_offset - qs.statement_start_offset)/2 END) AS query_text,
			qs.creation_time AS plan_created
		FROM sys.dm_exec_query_stats qs
		CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) t
		WHERE t.dbid = DB_ID() OR t.dbid IS NULL
		ORDER BY qs.total_worker_time DESC`)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error (may require VIEW SERVER STATE permission): %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	count := 0
	for rows.Next() {
		var totalCPU, execCount int64
		var avgCPU, avgElapsed, avgReads sql.NullInt64
		var queryText sql.NullString
		var planCreated time.Time
		if err := rows.Scan(&totalCPU, &execCount, &avgCPU, &avgElapsed, &avgReads, &queryText, &planCreated); err != nil {
			continue
		}
		count++
		qt := "(unavailable)"
		if queryText.Valid {
			qt = strings.TrimSpace(queryText.String)
			if len(qt) > 300 {
				qt = qt[:300] + "..."
			}
		}
		ac, ae, ar := int64(0), int64(0), int64(0)
		if avgCPU.Valid {
			ac = avgCPU.Int64
		}
		if avgElapsed.Valid {
			ae = avgElapsed.Int64
		}
		if avgReads.Valid {
			ar = avgReads.Int64
		}
		lines = append(lines, fmt.Sprintf("#%d  Total CPU: %dms | Executions: %d | Avg CPU: %dms | Avg Elapsed: %dms | Avg Reads: %d | Plan: %s\n    %s\n",
			count, totalCPU, execCount, ac, ae, ar, planCreated.Format("2006-01-02 15:04"), qt))
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText("No query stats available."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Top %d queries by CPU:\n\n%s", count, strings.Join(lines, "\n"))), nil
}

func compareTablesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()
	srcConn, _ := args["source"].(string)
	tgtConn, _ := args["target"].(string)
	table, _ := args["table"].(string)
	if srcConn == "" || tgtConn == "" || table == "" {
		return mcp.NewToolResultError("'source', 'target', and 'table' parameters are all required"), nil
	}

	schema, tableName := parseSchemaTable(table)
	colQuery := `
		SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, NUMERIC_PRECISION,
			IS_NULLABLE, COLUMN_DEFAULT
		FROM INFORMATION_SCHEMA.COLUMNS
		WHERE TABLE_SCHEMA = @p1 AND TABLE_NAME = @p2
		ORDER BY ORDINAL_POSITION`

	type colDef struct {
		dataType  string
		maxLen    string
		precision string
		nullable  string
		dflt      string
	}

	fetchCols := func(connName string) (map[string]colDef, []string, error) {
		db, err := getDB(connName)
		if err != nil {
			return nil, nil, err
		}
		queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		rows, err := db.QueryContext(queryCtx, colQuery, schema, tableName)
		if err != nil {
			return nil, nil, err
		}
		defer rows.Close()

		cols := map[string]colDef{}
		var order []string
		for rows.Next() {
			var name, dt, nullable string
			var ml, prec, def sql.NullString
			if err := rows.Scan(&name, &dt, &ml, &prec, &nullable, &def); err != nil {
				continue
			}
			m, p, d := "", "", ""
			if ml.Valid {
				m = ml.String
			}
			if prec.Valid {
				p = prec.String
			}
			if def.Valid {
				d = def.String
			}
			cols[name] = colDef{dataType: dt, maxLen: m, precision: p, nullable: nullable, dflt: d}
			order = append(order, name)
		}
		if err := rows.Err(); err != nil {
			return cols, order, err
		}
		return cols, order, nil
	}

	srcCols, srcOrder, err := fetchCols(srcConn)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Source error: %v", err)), nil
	}
	tgtCols, _, err := fetchCols(tgtConn)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Target error: %v", err)), nil
	}

	if len(srcCols) == 0 && len(tgtCols) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("Table %s.%s not found in either connection.", schema, tableName)), nil
	}

	var added, removed, changed, identical int
	var lines []string
	lines = append(lines, fmt.Sprintf("Comparing %s.%s: %s vs %s\n", schema, tableName, srcConn, tgtConn))

	// Columns in source
	for _, name := range srcOrder {
		sc := srcCols[name]
		tc, exists := tgtCols[name]
		if !exists {
			lines = append(lines, fmt.Sprintf("  + %-30s %s  (only in %s)", name, sc.dataType, srcConn))
			added++
		} else {
			diffs := []string{}
			if sc.dataType != tc.dataType {
				diffs = append(diffs, fmt.Sprintf("type: %s -> %s", sc.dataType, tc.dataType))
			}
			if sc.maxLen != tc.maxLen {
				diffs = append(diffs, fmt.Sprintf("maxlen: %s -> %s", sc.maxLen, tc.maxLen))
			}
			if sc.nullable != tc.nullable {
				diffs = append(diffs, fmt.Sprintf("nullable: %s -> %s", sc.nullable, tc.nullable))
			}
			if sc.dflt != tc.dflt {
				diffs = append(diffs, fmt.Sprintf("default: %s -> %s", sc.dflt, tc.dflt))
			}
			if len(diffs) > 0 {
				lines = append(lines, fmt.Sprintf("  ~ %-30s %s", name, strings.Join(diffs, " | ")))
				changed++
			} else {
				identical++
			}
		}
	}

	// Columns only in target
	for name, tc := range tgtCols {
		if _, exists := srcCols[name]; !exists {
			lines = append(lines, fmt.Sprintf("  - %-30s %s  (only in %s)", name, tc.dataType, tgtConn))
			removed++
		}
	}

	summary := fmt.Sprintf("\nSummary: %d identical, %d changed, %d only in %s, %d only in %s",
		identical, changed, added, srcConn, removed, tgtConn)
	if changed == 0 && added == 0 && removed == 0 {
		summary = "\nSchemas are identical."
	}
	lines = append(lines, summary)

	return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
}

func waitStatsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connName := getStringArg(request, "connection")
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}
	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT TOP 25
			wait_type,
			waiting_tasks_count,
			wait_time_ms,
			max_wait_time_ms,
			signal_wait_time_ms,
			wait_time_ms - signal_wait_time_ms AS resource_wait_ms,
			CAST(100.0 * wait_time_ms / NULLIF(SUM(wait_time_ms) OVER(), 0) AS DECIMAL(5,2)) AS pct_total
		FROM sys.dm_db_wait_stats
		WHERE wait_type NOT IN (
			'SLEEP_TASK','BROKER_IO_FLUSH','SQLTRACE_BUFFER_FLUSH',
			'CLR_AUTO_EVENT','CLR_MANUAL_EVENT','LAZYWRITER_SLEEP',
			'RESOURCE_QUEUE','CHECKPOINT_QUEUE','BROKER_EVENTHANDLER',
			'BROKER_RECEIVE_WAITFOR','BROKER_TASK_STOP','BROKER_TO_FLUSH',
			'BROKER_TRANSMITTER','DIRTY_PAGE_POLL','DISPATCHER_QUEUE_SEMAPHORE',
			'FT_IFTS_SCHEDULER_IDLE_WAIT','FT_IFTSHC_MUTEX',
			'LOGMGR_QUEUE','ONDEMAND_TASK_QUEUE','REQUEST_FOR_DEADLOCK_SEARCH',
			'SERVER_IDLE_CHECK','SLEEP_DBSTARTUP','SLEEP_DCOMSTARTUP',
			'SLEEP_MASTERDBREADY','SLEEP_MASTERMDREADY','SLEEP_MASTERUPGRADED',
			'SLEEP_MSDBSTARTUP','SLEEP_SYSTEMTASK','SLEEP_TEMPDBSTARTUP',
			'SNI_HTTP_ACCEPT','SP_SERVER_DIAGNOSTICS_SLEEP',
			'SQLTRACE_INCREMENTAL_FLUSH_SLEEP','TRACEWRITE',
			'WAIT_FOR_RESULTS','WAITFOR','XE_DISPATCHER_WAIT','XE_TIMER_EVENT',
			'QDS_PERSIST_TASK_MAIN_LOOP_SLEEP','QDS_ASYNC_QUEUE',
			'QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP',
			'QDS_SHUTDOWN_QUEUE','REDO_THREAD_PENDING_WORK',
			'HADR_WORK_QUEUE','PREEMPTIVE_XE_GETTARGETSTATE',
			'PWAIT_ALL_COMPONENTS_INITIALIZED','PREEMPTIVE_OS_AUTHENTICATIONOPS',
			'PREEMPTIVE_OS_AUTHORIZATIONOPS','HADR_FILESTREAM_IOMGR_IOCOMPLETION',
			'WAIT_XTP_OFFLINE_CKPT_NEW_LOG'
		)
		AND waiting_tasks_count > 0
		ORDER BY wait_time_ms DESC`)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	lines = append(lines, fmt.Sprintf("%-35s %10s %12s %12s %10s %6s", "Wait Type", "Count", "Total ms", "Resource ms", "Max ms", "Pct"))
	lines = append(lines, strings.Repeat("-", 90))
	count := 0
	for rows.Next() {
		var waitType string
		var taskCount, waitMs, maxWaitMs, signalMs, resourceMs int64
		var pct float64
		if err := rows.Scan(&waitType, &taskCount, &waitMs, &maxWaitMs, &signalMs, &resourceMs, &pct); err != nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("%-35s %10d %12d %12d %10d %5.1f%%", waitType, taskCount, waitMs, resourceMs, maxWaitMs, pct))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText("No significant wait stats found."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Top %d wait types:\n\n%s", count, strings.Join(lines, "\n"))), nil
}

func blockingChainsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connName := getStringArg(request, "connection")
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}
	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT
			r.session_id,
			r.blocking_session_id,
			r.wait_type,
			r.wait_time / 1000 AS wait_sec,
			r.status,
			s.login_name,
			s.program_name,
			r.open_transaction_count,
			SUBSTRING(t.text, (r.statement_start_offset/2)+1,
				CASE WHEN r.statement_end_offset = -1 THEN LEN(t.text)
				ELSE (r.statement_end_offset - r.statement_start_offset)/2 END) AS current_sql
		FROM sys.dm_exec_requests r
		JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
		CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
		WHERE r.blocking_session_id > 0 AND s.is_user_process = 1
		ORDER BY r.blocking_session_id, r.session_id`)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	count := 0
	for rows.Next() {
		var sessionID, blockingID, waitSec, openTxn int
		var waitType, status, loginName sql.NullString
		var programName, currentSQL sql.NullString
		if err := rows.Scan(&sessionID, &blockingID, &waitType, &waitSec, &status, &loginName, &programName, &openTxn, &currentSQL); err != nil {
			continue
		}
		wt, st, ln, pn, cs := "", "", "", "", "(unavailable)"
		if waitType.Valid {
			wt = waitType.String
		}
		if status.Valid {
			st = status.String
		}
		if loginName.Valid {
			ln = loginName.String
		}
		if programName.Valid {
			pn = programName.String
		}
		if currentSQL.Valid {
			cs = strings.TrimSpace(currentSQL.String)
			if len(cs) > 200 {
				cs = cs[:200] + "..."
			}
		}
		lines = append(lines, fmt.Sprintf("  Session %d BLOCKED BY %d | %s %ds | %s %s@%s txn=%d\n    %s\n",
			sessionID, blockingID, wt, waitSec, st, ln, pn, openTxn, cs))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText("No blocking chains detected."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Blocking chains (%d blocked sessions):\n\n%s", count, strings.Join(lines, "\n"))), nil
}

func hangfireDashboardHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connName := getStringArg(request, "connection")
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}
	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Check if HangFire schema exists
	var schemaExists int
	err = db.QueryRowContext(queryCtx, "SELECT COUNT(*) FROM sys.schemas WHERE name = 'HangFire'").Scan(&schemaExists)
	if err != nil || schemaExists == 0 {
		return mcp.NewToolResultText("HangFire schema not found in this database."), nil
	}

	var lines []string
	lines = append(lines, "=== Hangfire Dashboard ===\n")

	// Job states (last 24h)
	stateRows, err := db.QueryContext(queryCtx, `
		SELECT StateName, COUNT(*) AS cnt
		FROM HangFire.Job
		WHERE CreatedAt > DATEADD(HOUR, -24, GETUTCDATE())
		GROUP BY StateName
		ORDER BY cnt DESC`)
	if err == nil {
		defer stateRows.Close()
		lines = append(lines, "Job States (last 24h):")
		for stateRows.Next() {
			var state string
			var cnt int64
			if err := stateRows.Scan(&state, &cnt); err == nil {
				lines = append(lines, fmt.Sprintf("  %-20s %d", state, cnt))
			}
		}
		if err := stateRows.Err(); err != nil {
			lines = append(lines, fmt.Sprintf("  (iteration error: %v)", err))
		}
		lines = append(lines, "")
	}

	// Recent failures
	failRows, err := db.QueryContext(queryCtx, `
		SELECT TOP 10
			j.Id,
			LEFT(j.InvocationData, 120) AS job_type,
			s.CreatedAt AS failed_at,
			LEFT(s.Reason, 150) AS reason
		FROM HangFire.Job j
		JOIN HangFire.State s ON j.StateId = s.Id
		WHERE j.StateName = 'Failed'
		ORDER BY s.CreatedAt DESC`)
	if err == nil {
		defer failRows.Close()
		lines = append(lines, "Recent Failures (last 10):")
		failCount := 0
		for failRows.Next() {
			var id int64
			var jobType, reason sql.NullString
			var failedAt time.Time
			if err := failRows.Scan(&id, &jobType, &failedAt, &reason); err == nil {
				jt, r := "", ""
				if jobType.Valid {
					jt = jobType.String
				}
				if reason.Valid {
					r = reason.String
				}
				lines = append(lines, fmt.Sprintf("  [%d] %s\n    Failed: %s\n    Reason: %s\n",
					id, jt, failedAt.Format("2006-01-02 15:04:05"), r))
				failCount++
			}
		}
		if err := failRows.Err(); err != nil {
			lines = append(lines, fmt.Sprintf("  (iteration error: %v)", err))
		}
		if failCount == 0 {
			lines = append(lines, "  (none)")
		}
		lines = append(lines, "")
	}

	// Server heartbeats (workers)
	serverRows, err := db.QueryContext(queryCtx, `
		SELECT Id, LEFT(Data, 200) AS data, LastHeartbeat
		FROM HangFire.Server
		ORDER BY LastHeartbeat DESC`)
	if err == nil {
		defer serverRows.Close()
		lines = append(lines, "Active Servers:")
		for serverRows.Next() {
			var id string
			var data sql.NullString
			var heartbeat time.Time
			if err := serverRows.Scan(&id, &data, &heartbeat); err == nil {
				ago := time.Since(heartbeat).Truncate(time.Second)
				lines = append(lines, fmt.Sprintf("  %s (heartbeat %s ago)", id, ago))
			}
		}
		if err := serverRows.Err(); err != nil {
			lines = append(lines, fmt.Sprintf("  (iteration error: %v)", err))
		}
	}

	return mcp.NewToolResultText(strings.Join(lines, "\n")), nil
}

func ef6MigrationStatusHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connName := getStringArg(request, "connection")
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}
	contextFilter := getStringArg(request, "context")
	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT MigrationId, ContextKey, ProductVersion,
			ROW_NUMBER() OVER (ORDER BY MigrationId) AS seq
		FROM dbo.__MigrationHistory
		WHERE (@p1 = '' OR ContextKey LIKE '%' + @p1 + '%')
		ORDER BY MigrationId DESC`, contextFilter)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v (table __MigrationHistory may not exist)", err)), nil
	}
	defer rows.Close()

	var lines []string
	lines = append(lines, fmt.Sprintf("%-4s %-60s %-12s", "#", "Migration", "EF Version"))
	lines = append(lines, strings.Repeat("-", 80))
	count := 0
	for rows.Next() {
		var migrationId, contextKey, productVersion string
		var seq int
		if err := rows.Scan(&migrationId, &contextKey, &productVersion, &seq); err != nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("%-4d %-60s %-12s", seq, migrationId, productVersion))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText("No migrations found."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Applied migrations (%d) on %s:\n\n%s", count, connName, strings.Join(lines, "\n"))), nil
}

func tableStatisticsHealthHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connName := getStringArg(request, "connection")
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}
	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT TOP 30
			OBJECT_SCHEMA_NAME(s.object_id) + '.' + OBJECT_NAME(s.object_id) AS table_name,
			s.name AS stat_name,
			CASE WHEN s.auto_created = 1 THEN 'auto' WHEN s.user_created = 1 THEN 'user' ELSE 'index' END AS stat_type,
			sp.last_updated,
			sp.rows,
			sp.rows_sampled,
			sp.modification_counter,
			CAST(100.0 * sp.modification_counter / NULLIF(sp.rows, 0) AS DECIMAL(5,2)) AS pct_modified
		FROM sys.stats s
		CROSS APPLY sys.dm_db_stats_properties(s.object_id, s.stats_id) sp
		WHERE sp.modification_counter > 0
			AND OBJECTPROPERTY(s.object_id, 'IsMSShipped') = 0
		ORDER BY sp.modification_counter DESC`)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	lines = append(lines, fmt.Sprintf("%-35s %-25s %-5s %10s %10s %8s %7s", "Table", "Statistic", "Type", "Rows", "Modified", "Pct", "Updated"))
	lines = append(lines, strings.Repeat("-", 110))
	count := 0
	for rows.Next() {
		var tableName, statName, statType string
		var lastUpdated sql.NullTime
		var rowCount, rowsSampled, modCount int64
		var pctModified sql.NullFloat64
		if err := rows.Scan(&tableName, &statName, &statType, &lastUpdated, &rowCount, &rowsSampled, &modCount, &pctModified); err != nil {
			continue
		}
		updated := "never"
		if lastUpdated.Valid {
			updated = lastUpdated.Time.Format("Jan 02")
		}
		pct := ""
		if pctModified.Valid {
			pct = fmt.Sprintf("%.1f%%", pctModified.Float64)
		}
		warning := ""
		if pctModified.Valid && pctModified.Float64 > 20 {
			warning = " [STALE]"
		}
		lines = append(lines, fmt.Sprintf("%-35s %-25s %-5s %10d %10d %8s %7s%s",
			tableName, statName, statType, rowCount, modCount, pct, updated, warning))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText("All statistics are up to date."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Statistics health (top %d modified):\n\n%s", count, strings.Join(lines, "\n"))), nil
}

func longRunningQueriesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connName := getStringArg(request, "connection")
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}
	threshold := getStringArg(request, "threshold_seconds")
	if threshold == "" {
		threshold = "10"
	}
	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT
			r.session_id,
			DATEDIFF(SECOND, r.start_time, GETDATE()) AS duration_sec,
			r.status,
			r.command,
			r.cpu_time,
			r.logical_reads,
			r.writes,
			r.wait_type,
			r.blocking_session_id,
			s.login_name,
			s.host_name,
			s.program_name,
			SUBSTRING(t.text, (r.statement_start_offset/2)+1,
				CASE WHEN r.statement_end_offset = -1 THEN LEN(t.text)
				ELSE (r.statement_end_offset - r.statement_start_offset)/2 END) AS current_sql
		FROM sys.dm_exec_requests r
		JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
		CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
		WHERE r.session_id != @@SPID
			AND s.is_user_process = 1
			AND DATEDIFF(SECOND, r.start_time, GETDATE()) > CAST(@p1 AS int)
		ORDER BY duration_sec DESC`, threshold)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	count := 0
	for rows.Next() {
		var sessionID, durationSec, cpuTime, logicalReads, writes, blockingID int
		var status, command, loginName string
		var waitType, hostName, programName, currentSQL sql.NullString
		if err := rows.Scan(&sessionID, &durationSec, &status, &command, &cpuTime, &logicalReads, &writes,
			&waitType, &blockingID, &loginName, &hostName, &programName, &currentSQL); err != nil {
			continue
		}
		wt := ""
		if waitType.Valid && waitType.String != "" {
			wt = " wait=" + waitType.String
		}
		blocking := ""
		if blockingID > 0 {
			blocking = fmt.Sprintf(" BLOCKED_BY=%d", blockingID)
		}
		host := ""
		if hostName.Valid {
			host = hostName.String
		}
		prog := ""
		if programName.Valid {
			prog = programName.String
		}
		stmt := "(unavailable)"
		if currentSQL.Valid {
			stmt = strings.TrimSpace(currentSQL.String)
			if len(stmt) > 300 {
				stmt = stmt[:300] + "..."
			}
		}
		lines = append(lines, fmt.Sprintf("  [%d] %ds | CPU: %dms | Reads: %d | Writes: %d | %s %s@%s (%s)%s%s\n    %s\n",
			sessionID, durationSec, cpuTime, logicalReads, writes, status, loginName, host, prog, wt, blocking, stmt))
		count++
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No queries running longer than %s seconds.", threshold)), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Long-running queries (>%ss): %d found\n\n%s", threshold, count, strings.Join(lines, "\n"))), nil
}

func permissionAuditHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	connName := getStringArg(request, "connection")
	if connName == "" {
		return mcp.NewToolResultError("'connection' parameter is required"), nil
	}
	db, err := getDB(connName)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT
			dp.name AS principal_name,
			dp.type_desc AS principal_type,
			ISNULL(r.name, '') AS role_name,
			ISNULL(p.permission_name, '') AS permission,
			ISNULL(p.state_desc, '') AS state,
			CASE WHEN p.major_id > 0
				THEN ISNULL(OBJECT_SCHEMA_NAME(p.major_id) + '.' + OBJECT_NAME(p.major_id), '')
				ELSE '' END AS object_name
		FROM sys.database_principals dp
		LEFT JOIN sys.database_role_members rm ON dp.principal_id = rm.member_principal_id
		LEFT JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
		LEFT JOIN sys.database_permissions p ON dp.principal_id = p.grantee_principal_id
		WHERE dp.type IN ('S','U','G','E','X')
			AND dp.name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys','public')
		ORDER BY dp.name, r.name, p.permission_name`)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query error: %v", err)), nil
	}
	defer rows.Close()

	var lines []string
	currentPrincipal := ""
	count := 0
	for rows.Next() {
		var principalName, principalType, roleName, permission, state, objectName string
		if err := rows.Scan(&principalName, &principalType, &roleName, &permission, &state, &objectName); err != nil {
			continue
		}
		if principalName != currentPrincipal {
			if currentPrincipal != "" {
				lines = append(lines, "")
			}
			lines = append(lines, fmt.Sprintf("  %s (%s)", principalName, principalType))
			currentPrincipal = principalName
			count++
		}
		if roleName != "" {
			lines = append(lines, fmt.Sprintf("    Role: %s", roleName))
		}
		if permission != "" {
			obj := ""
			if objectName != "" {
				obj = " ON " + objectName
			}
			lines = append(lines, fmt.Sprintf("    %s %s%s", state, permission, obj))
		}
	}
	if err := rows.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Iteration error: %v", err)), nil
	}
	if count == 0 {
		return mcp.NewToolResultText("No database principals found."), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Database principals (%d):\n\n%s", count, strings.Join(lines, "\n"))), nil
}
