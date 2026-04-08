# mcp-azure-sql

Enterprise-grade [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server for Azure SQL Database and SQL Server. Gives AI agents direct, safe access to your databases with Azure AD (Entra ID) authentication, tiered safety gates, and 34 tools for querying, schema discovery, performance diagnostics, and compliance auditing.

## Why

Existing SQL MCP servers don't support Azure AD token-based authentication. This one does — no passwords, no connection strings to manage. Just `az login` and go.

It also has a tiered safety model that prevents AI agents from accidentally running destructive operations on production databases, while still allowing full read/write access on development environments.

## Features

- **Azure AD (Entra ID) authentication** via `DefaultAzureCredential` — works with `az login`, managed identities, and service principals
- **SQL Server authentication** and **raw connection string** passthrough for legacy systems
- **34 tools** covering queries, schema discovery, performance diagnostics, compliance auditing, and Hangfire monitoring
- **Tiered safety gates**: read (no confirmation), write (requires `confirm=true`), dangerous DDL (blocked on production)
- **Production protection**: configurable per-connection via JSON config file or environment tags
- **Connection pooling** with Azure AD token caching and health-check ping skip for rapid sequential calls
- **Multi-agent support**: works with Claude Code, Codex CLI, Gemini CLI, Cursor, and any MCP-compatible client
- **JSON config file** with per-connection auth modes, environment tags, descriptions, and production flags
- **Audit logging** for all query and execute operations
- **SQL injection protection**: parameterized queries, ODBC escape detection, batch separator blocking, comment/string-literal stripping

## Quick Start

### Prerequisites

- Go 1.21+ (for building from source)
- Azure CLI (`az login`) for Azure AD authentication
- Network access to your Azure SQL databases (firewall rules)

### Install

```bash
go install github.com/ialbahub/mcp-azure-sql@latest
```

Or build from source:

```bash
git clone https://github.com/ialbahub/mcp-azure-sql.git
cd mcp-azure-sql
go build -o mcp-azure-sql .
```

### Configure

Create a JSON config file (e.g., `~/.config/azure-sql-mcp/connections.json`):

```json
{
  "defaults": {
    "auth": "azuread",
    "app_name": "azure-sql-mcp"
  },
  "connections": [
    {
      "name": "my-dev-db",
      "server": "myserver-dev.database.windows.net",
      "database": "myapp-dev",
      "environment": "dev",
      "description": "Development database"
    },
    {
      "name": "my-prod-db",
      "server": "myserver-prod.database.windows.net",
      "database": "myapp-prod",
      "environment": "prod",
      "prod": true,
      "description": "Production (safety gates enabled)"
    }
  ]
}
```

See [`example-config.json`](example-config.json) for all options including SQL auth and raw connection strings.

### Add to Your AI Agent

**Claude Code** (`~/.claude.json`):
```json
{
  "mcpServers": {
    "azure-sql": {
      "type": "stdio",
      "command": "/path/to/mcp-azure-sql",
      "env": {
        "AZURE_SQL_CONFIG_FILE": "/path/to/connections.json"
      }
    }
  }
}
```

**Codex CLI** (`~/.codex/config.toml`):
```toml
[mcp_servers.azure-sql]
command = "/path/to/mcp-azure-sql"
env_vars = ["AZURE_SQL_CONFIG_FILE"]
startup_timeout_sec = 30.0
tool_timeout_sec = 120.0
```

**Gemini CLI** (`~/.gemini/settings.json`):
```json
{
  "mcpServers": {
    "azure-sql": {
      "command": "/path/to/mcp-azure-sql",
      "env": { "AZURE_SQL_CONFIG_FILE": "/path/to/connections.json" }
    }
  }
}
```

**Cursor** (`~/.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "azure-sql": {
      "command": "/path/to/mcp-azure-sql",
      "env": { "AZURE_SQL_CONFIG_FILE": "/path/to/connections.json" }
    }
  }
}
```

## Tools (34)

### Connection Management
| Tool | Description |
|------|-------------|
| `list_connections` | List all configured connections with environment, auth mode, production status, and pool health |
| `test_connection` | Verify connectivity, show server version, database name, and authenticated user |
| `connection_info` | Detailed metadata for a single connection |
| `add_connection` | Add a connection at runtime (Azure AD, SQL auth, or raw connection string) |

### Query & Execute
| Tool | Description |
|------|-------------|
| `query` | Execute read-only SQL (SELECT, WITH, sp_help). Write operations are rejected. |
| `execute` | Execute write operations (INSERT, UPDATE, DELETE, EXEC). Requires `confirm=true`. Dangerous DDL blocked on production. |

### Schema Discovery
| Tool | Description |
|------|-------------|
| `list_tables` | List all tables and views, grouped by schema |
| `describe_table` | Full column schema: types, nullability, primary keys, defaults |
| `describe_indexes` | All indexes with columns, uniqueness, type, included columns |
| `describe_foreign_keys` | FK relationships (both incoming and outgoing) with cascade rules |
| `search_columns` | Find columns by name pattern across all tables |
| `table_row_counts` | Approximate row counts (fast, uses `sys.partitions`) |
| `search_objects` | Find any object (table, view, proc, function, trigger) by name |
| `describe_triggers` | Triggers with event types, timing, enabled status, and definitions |

### Views, Procedures & Functions
| Tool | Description |
|------|-------------|
| `list_views` / `describe_view` | List and inspect view definitions |
| `list_stored_procs` / `describe_sproc` | List and inspect stored procedure source code and parameters |
| `list_functions` / `describe_function` | List and inspect user-defined functions |

### Performance & Diagnostics
| Tool | Description |
|------|-------------|
| `explain_query` | Estimated execution plan with operator costs (SHOWPLAN_ALL) |
| `active_queries` | Currently executing queries with duration, wait type, blocking info |
| `long_running_queries` | Queries exceeding a time threshold with CPU, reads, writes |
| `top_queries_by_cpu` | Top 20 CPU-intensive queries from the plan cache |
| `wait_stats` | Server wait statistics for performance triage |
| `blocking_chains` | Live blocking chain tree for deadlock debugging |
| `index_usage_stats` | Index seeks/scans/lookups/updates with unused index detection |
| `missing_indexes` | SQL Server's built-in missing index recommendations |
| `table_statistics_health` | Stale statistics detection with modification counts |
| `database_size` | Database size breakdown (data, log, used, free) |

### Comparison & Compliance
| Tool | Description |
|------|-------------|
| `compare_tables` | Schema diff between two connections (dev vs QA, QA vs prod) |
| `ef6_migration_status` | Applied EF6 migrations from `__MigrationHistory` |
| `permission_audit` | Database principals, role memberships, and object permissions |

### Hangfire
| Tool | Description |
|------|-------------|
| `hangfire_dashboard` | Job states, recent failures, active servers (for databases with HangFire schema) |

## Configuration

### Config File (`AZURE_SQL_CONFIG_FILE`)

The recommended way to configure connections. JSON file with:

```json
{
  "defaults": {
    "auth": "azuread",
    "app_name": "my-app"
  },
  "connections": [
    {
      "name": "unique-name",
      "server": "server.database.windows.net",
      "database": "dbname",
      "auth": "azuread",
      "environment": "dev",
      "description": "Human-readable note",
      "prod": false
    }
  ]
}
```

**Auth modes:**
| Mode | Driver | Use Case |
|------|--------|----------|
| `azuread` (default) | Azure AD DefaultAzureCredential | Azure SQL with `az login`, managed identity, or service principal |
| `sql` | SQL Server auth | Legacy systems with username/password |
| `connstr` | Raw connection string | Any custom configuration |

**Environment tags:** `dev`, `sqa`, `qa`, `beta`, `delta`, `test`, `preprod`, `prod`. Used for grouping in `list_connections` output.

**Production marking:** Connections with `"prod": true` or `"environment": "prod"` get safety gates:
- `execute` tool blocks `DROP`, `TRUNCATE`, `ALTER`, `GRANT` on production
- `execute` tool allows `INSERT`, `UPDATE`, `DELETE` with `confirm=true`
- `query` tool is always read-only regardless of environment

### Legacy Environment Variable (`AZURE_SQL_CONNECTIONS`)

For simple setups without a config file:

```bash
export AZURE_SQL_CONNECTIONS="dev=myserver.database.windows.net/mydb;qa=qaserver.database.windows.net/qadb"
```

Format: `name=server.fqdn/database` separated by semicolons. All connections use Azure AD auth.

### Production Override (`AZURE_SQL_PROD_CONNECTIONS`)

Override which connections are treated as production (comma-separated):

```bash
export AZURE_SQL_PROD_CONNECTIONS="my-prod-db,my-staging-db"
```

## Safety Model

| Operation | `query` tool | `execute` tool (dev) | `execute` tool (prod) |
|-----------|-------------|---------------------|----------------------|
| SELECT, WITH | Allowed | N/A (use query) | N/A (use query) |
| INSERT, UPDATE, DELETE | Blocked | Requires `confirm=true` | Requires `confirm=true` |
| DROP, TRUNCATE, ALTER | Blocked | Requires `confirm=true` | **BLOCKED entirely** |
| EXEC stored proc | Blocked | Requires `confirm=true` | Requires `confirm=true` |
| ODBC `{call}` | Blocked | Requires `confirm=true` | Requires `confirm=true` |

The classifier:
- Strips SQL comments (`--`, `/* */`) and string literals (`'...'`) before checking keywords
- Uses word-boundary regex to avoid false positives (`DeletedItems` is not `DELETE`)
- Detects ODBC escape sequences (`{call sp_executesql(...)}`)
- Catches batch separator injection (`SELECT 1; DELETE FROM ...`)

## Architecture

- **Go** with `github.com/mark3labs/mcp-go` for MCP protocol
- **`github.com/microsoft/go-mssqldb/azuread`** for Azure AD token authentication
- **Connection pool** with `sync.Mutex`-protected cache, health-check ping skip (30s window), and automatic reconnection
- **Audit logging** on all query/execute operations with connection name and production status
- **Error sanitization** strips connection strings from error messages before returning to the AI agent
- **`UNIQUEIDENTIFIER` formatting** with SQL Server's mixed-endian byte ordering for proper GUID display

## Development

```bash
# Build
go build -o mcp-azure-sql .

# Run tests
go vet ./...
go build -race -o /dev/null .

# Test MCP protocol
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | \
  AZURE_SQL_CONFIG_FILE=example-config.json ./mcp-azure-sql

# Version
./mcp-azure-sql --version
```

## License

MIT License - Copyright (c) 2026 Albahub, LLC
