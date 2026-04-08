<p align="center">
  <h1 align="center">mcp-azure-sql</h1>
  <p align="center">
    <strong>Enterprise-grade MCP server for Azure SQL &amp; SQL Server</strong>
  </p>
  <p align="center">
    <a href="https://github.com/ialbahub/mcp-azure-sql/releases"><img src="https://img.shields.io/github/v/release/ialbahub/mcp-azure-sql?style=flat-square&color=00A67E" alt="Release"></a>
    <a href="https://github.com/ialbahub/mcp-azure-sql/blob/main/LICENSE"><img src="https://img.shields.io/github/license/ialbahub/mcp-azure-sql?style=flat-square" alt="License"></a>
    <a href="https://github.com/ialbahub/mcp-azure-sql"><img src="https://img.shields.io/badge/language-Go-00ADD8?style=flat-square&logo=go" alt="Go"></a>
    <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-2024--11--05-8B5CF6?style=flat-square" alt="MCP"></a>
    <img src="https://img.shields.io/badge/tools-34-blue?style=flat-square" alt="34 Tools">
  </p>
  <p align="center">
    Azure AD auth &bull; 34 tools &bull; Tiered safety gates &bull; Zero dependencies<br>
    Works with Claude Code &bull; Codex CLI &bull; Gemini CLI &bull; Cursor &bull; GitHub Copilot &bull; Windsurf &bull; Cline &bull; Continue
  </p>
</p>

---

## Overview

Give any AI agent direct, safe access to your Azure SQL databases. One binary, zero dependencies — just download and run.

```
AI Agent  ──MCP stdio──>  mcp-azure-sql  ──Azure AD──>  Azure SQL Database
                              │
                              ├── 34 tools (query, schema, perf, compliance)
                              ├── Tiered safety (read/write/dangerous)
                              ├── Production protection (DDL blocked)
                              └── Connection pooling + audit logging
```

## Why Go?

Most MCP servers are written in TypeScript or Python. This one is **Go** — and it matters:

| | **Go** | TypeScript / Python |
|:--|:--|:--|
| **Startup** | ~5ms | 500ms+ / 1s+ |
| **Binary** | Single 16MB file, zero deps | Runtime + packages required |
| **Memory** | ~15MB idle | 80MB+ / 50MB+ |
| **Concurrency** | Native goroutines | Event loop / GIL |
| **Distribution** | Download → run | `npm install` / `pip install` + runtime |
| **Azure AD** | Native driver (`go-mssqldb/azuread`) | Requires `@azure/identity` + `tedious` |
| **Safety** | Compile-time type checking | Runtime errors |

> **One binary. No dependencies. No runtime. Download and run.**

---

## Quick Start

### 1. Install

**Download binary** (no Go required):

```bash
# Linux / macOS / WSL
curl -fsSL https://raw.githubusercontent.com/ialbahub/mcp-azure-sql/main/install.sh | sh
```

<details>
<summary>Other install methods</summary>

**Manual download:**
```bash
# Linux amd64
curl -fsSL https://github.com/ialbahub/mcp-azure-sql/releases/latest/download/mcp-azure-sql_linux_amd64.tar.gz | tar xz
sudo mv mcp-azure-sql /usr/local/bin/

# macOS Apple Silicon
curl -fsSL https://github.com/ialbahub/mcp-azure-sql/releases/latest/download/mcp-azure-sql_darwin_arm64.tar.gz | tar xz
sudo mv mcp-azure-sql /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/ialbahub/mcp-azure-sql/releases/latest/download/mcp-azure-sql_windows_amd64.zip -OutFile mcp-azure-sql.zip
Expand-Archive mcp-azure-sql.zip; Move-Item mcp-azure-sql.exe $HOME\.local\bin\
```

**Go install:**
```bash
go install github.com/ialbahub/mcp-azure-sql@latest
```

**Build from source:**
```bash
git clone https://github.com/ialbahub/mcp-azure-sql.git && cd mcp-azure-sql
go build -o mcp-azure-sql .
```

</details>

### 2. Configure connections

Create `~/.config/azure-sql-mcp/connections.json`:

```json
{
  "defaults": { "auth": "azuread" },
  "connections": [
    {
      "name": "my-dev-db",
      "server": "myserver-dev.database.windows.net",
      "database": "myapp-dev",
      "environment": "dev"
    },
    {
      "name": "my-prod-db",
      "server": "myserver-prod.database.windows.net",
      "database": "myapp-prod",
      "environment": "prod",
      "prod": true
    }
  ]
}
```

### 3. Add to your AI agent

Pick your agent below, then restart it.

---

## Agent Configuration

<details>
<summary><strong>Claude Code</strong></summary>

Add to `~/.claude.json` under `mcpServers`:

```json
"azure-sql": {
  "type": "stdio",
  "command": "mcp-azure-sql",
  "env": { "AZURE_SQL_CONFIG_FILE": "~/.config/azure-sql-mcp/connections.json" }
}
```

Or via CLI: `claude mcp add --transport stdio --scope user azure-sql -- mcp-azure-sql`
</details>

<details>
<summary><strong>OpenAI Codex CLI</strong></summary>

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.azure-sql]
command = "mcp-azure-sql"
env_vars = ["AZURE_SQL_CONFIG_FILE"]
startup_timeout_sec = 30.0
tool_timeout_sec = 120.0
```

Set env: `export AZURE_SQL_CONFIG_FILE="$HOME/.config/azure-sql-mcp/connections.json"`
</details>

<details>
<summary><strong>Google Gemini CLI</strong></summary>

Add to `~/.gemini/settings.json` under `mcpServers`:

```json
"azure-sql": {
  "command": "mcp-azure-sql",
  "env": { "AZURE_SQL_CONFIG_FILE": "~/.config/azure-sql-mcp/connections.json" },
  "timeout": 120
}
```
</details>

<details>
<summary><strong>Cursor</strong></summary>

Add to `~/.cursor/mcp.json` under `mcpServers`:

```json
"azure-sql": {
  "command": "mcp-azure-sql",
  "env": { "AZURE_SQL_CONFIG_FILE": "~/.config/azure-sql-mcp/connections.json" }
}
```
</details>

<details>
<summary><strong>GitHub Copilot (VS Code)</strong></summary>

Add to VS Code `settings.json`:

```json
"mcp": {
  "servers": {
    "azure-sql": {
      "type": "stdio",
      "command": "mcp-azure-sql",
      "env": { "AZURE_SQL_CONFIG_FILE": "~/.config/azure-sql-mcp/connections.json" }
    }
  }
}
```
</details>

<details>
<summary><strong>Windsurf (Codeium)</strong></summary>

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{ "mcpServers": { "azure-sql": {
  "command": "mcp-azure-sql",
  "env": { "AZURE_SQL_CONFIG_FILE": "~/.config/azure-sql-mcp/connections.json" }
}}}
```
</details>

<details>
<summary><strong>Cline (VS Code)</strong></summary>

Edit `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`:

```json
{ "mcpServers": { "azure-sql": {
  "command": "mcp-azure-sql",
  "env": { "AZURE_SQL_CONFIG_FILE": "~/.config/azure-sql-mcp/connections.json" }
}}}
```
</details>

<details>
<summary><strong>Continue (VS Code / JetBrains)</strong></summary>

Add to `~/.continue/config.yaml`:

```yaml
mcpServers:
  - name: azure-sql
    command: mcp-azure-sql
    env:
      AZURE_SQL_CONFIG_FILE: ~/.config/azure-sql-mcp/connections.json
```
</details>

<details>
<summary><strong>Claude Desktop</strong></summary>

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{ "mcpServers": { "azure-sql": {
  "command": "mcp-azure-sql",
  "env": { "AZURE_SQL_CONFIG_FILE": "~/.config/azure-sql-mcp/connections.json" }
}}}
```
</details>

<details>
<summary><strong>Any MCP Client</strong></summary>

Standard **MCP over stdio** — JSON-RPC 2.0, protocol version `2024-11-05`. The binary reads from stdin and writes to stdout. Point any MCP-compatible client at the binary.
</details>

---

## Tools

### Connection Management
| Tool | Description | Annotation |
|------|-------------|------------|
| `list_connections` | List all connections with environment, auth, status | `readOnly` `idempotent` |
| `test_connection` | Verify connectivity, server version, auth user | `readOnly` `idempotent` |
| `connection_info` | Detailed metadata for a connection | `readOnly` `idempotent` |
| `add_connection` | Add a connection at runtime | `readOnly` `idempotent` |

### Query & Execute
| Tool | Description | Annotation |
|------|-------------|------------|
| `query` | Read-only SQL (SELECT, WITH, sp_help) | `readOnly` |
| `execute` | Write SQL with `confirm=true` gate. DDL blocked on prod. | `destructive` |

### Schema Discovery
| Tool | Description | Annotation |
|------|-------------|------------|
| `list_tables` | Tables and views grouped by schema | `readOnly` `idempotent` |
| `describe_table` | Columns, types, PKs, defaults | `readOnly` `idempotent` |
| `describe_indexes` | Indexes with columns, included, uniqueness | `readOnly` `idempotent` |
| `describe_foreign_keys` | FK relationships (in + out) | `readOnly` `idempotent` |
| `search_columns` | Find columns by name pattern | `readOnly` `idempotent` |
| `table_row_counts` | Fast approximate row counts | `readOnly` `idempotent` |
| `search_objects` | Find any object by name | `readOnly` `idempotent` |
| `describe_triggers` | Triggers with events and definitions | `readOnly` `idempotent` |

### Views, Procs & Functions
| Tool | Description | Annotation |
|------|-------------|------------|
| `list_views` / `describe_view` | View definitions | `readOnly` `idempotent` |
| `list_stored_procs` / `describe_sproc` | Proc source code + parameters | `readOnly` `idempotent` |
| `list_functions` / `describe_function` | UDF definitions | `readOnly` `idempotent` |

### Performance & Diagnostics
| Tool | Description | Annotation |
|------|-------------|------------|
| `explain_query` | Execution plan with operator costs | `readOnly` |
| `active_queries` | Running queries with wait types | `readOnly` |
| `long_running_queries` | Queries exceeding time threshold | `readOnly` |
| `top_queries_by_cpu` | Top 20 CPU consumers | `readOnly` |
| `wait_stats` | Database wait statistics | `readOnly` |
| `blocking_chains` | Live blocking tree | `readOnly` |
| `index_usage_stats` | Index usage + unused detection | `readOnly` |
| `missing_indexes` | SQL Server index recommendations | `readOnly` |
| `table_statistics_health` | Stale statistics detection | `readOnly` |
| `database_size` | Size breakdown (data/log/free) | `readOnly` |

### Comparison & Compliance
| Tool | Description | Annotation |
|------|-------------|------------|
| `compare_tables` | Schema diff across connections | `readOnly` `idempotent` |
| `ef6_migration_status` | EF6 migration history | `readOnly` `idempotent` |
| `permission_audit` | Principals, roles, permissions | `readOnly` |
| `hangfire_dashboard` | Job states, failures, servers | `readOnly` |

---

## Configuration Reference

### Auth Modes

| Mode | Description |
|------|-------------|
| `azuread` (default) | Azure AD `DefaultAzureCredential` — works with `az login`, managed identity, service principal |
| `sql` | SQL Server auth — add `user` and `password` fields |
| `connstr` | Raw connection string — add `connection_string` field |

### Environment Tags

`dev` `sqa` `qa` `beta` `delta` `test` `preprod` `prod`

Connections with `"prod": true` or `"environment": "prod"` get production safety gates.

### Safety Model

| Operation | `query` | `execute` (dev) | `execute` (prod) |
|-----------|---------|-----------------|------------------|
| SELECT | Allowed | — | — |
| INSERT / UPDATE / DELETE | Blocked | `confirm=true` | `confirm=true` |
| DROP / TRUNCATE / ALTER | Blocked | `confirm=true` | **BLOCKED** |
| EXEC / `{call}` | Blocked | `confirm=true` | `confirm=true` |

---

## Architecture

```
┌──────────────┐     stdio      ┌──────────────────┐    Azure AD    ┌─────────────┐
│  AI Agent    │ ──JSON-RPC──> │  mcp-azure-sql   │ ──────────>   │  Azure SQL  │
│  (any MCP    │ <──────────── │                  │ <──────────── │  Database   │
│   client)    │               │  34 tools        │               │             │
└──────────────┘               │  Safety gates    │               └─────────────┘
                               │  Connection pool │
                               │  Audit logging   │
                               └──────────────────┘
```

- **Go** + [`mcp-go`](https://github.com/mark3labs/mcp-go) — MCP protocol, JSON-RPC 2.0
- **[`go-mssqldb/azuread`](https://github.com/microsoft/go-mssqldb)** — Azure AD token auth
- **Tool annotations** — `ReadOnlyHint`, `DestructiveHint`, `IdempotentHint`, `OpenWorldHint`
- **MCP logging** — clients can set log levels via protocol
- **GUID formatting** — SQL Server mixed-endian byte ordering
- **Error sanitization** — connection strings never exposed to AI agents

## Development

```bash
go build -o mcp-azure-sql .
go vet ./...
go build -race -o /dev/null .
./mcp-azure-sql --version
```

### Release

```bash
git tag v1.2.0 && git push origin v1.2.0
# GitHub Actions builds binaries for 6 platforms via GoReleaser
```

---

<p align="center">
  <sub>Built by <a href="https://albahub.io">Albahub, LLC</a> &bull; MIT License</sub>
</p>
