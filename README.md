<h1 align="center">
  mcp-azure-sql
</h1>

<p align="center">
  <strong>Azure SQL + AI agents. 34 tools. One command.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/mcp-azure-sql"><img src="https://img.shields.io/npm/v/mcp-azure-sql?style=for-the-badge&color=CB3837&logo=npm&logoColor=white" alt="npm"></a>&nbsp;
  <a href="https://github.com/albahubio/mcp-azure-sql/releases"><img src="https://img.shields.io/github/v/release/albahubio/mcp-azure-sql?style=for-the-badge&color=00A67E&label=release" alt="Release"></a>&nbsp;
  <img src="https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">&nbsp;
  <img src="https://img.shields.io/badge/tools-34-3178C6?style=for-the-badge" alt="34 Tools">&nbsp;
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-2024--11--05-8B5CF6?style=for-the-badge" alt="MCP"></a>
</p>

<p align="center">
  Enterprise <a href="https://modelcontextprotocol.io">MCP</a> server for Azure SQL &amp; SQL Server.<br>
  Azure AD auth &bull; Tiered safety gates &bull; Zero dependencies &bull; Written in Go.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Anthropic-Claude-D97706?style=flat-square&logo=anthropic&logoColor=white" alt="">
  <img src="https://img.shields.io/badge/OpenAI-Codex-412991?style=flat-square&logo=openai&logoColor=white" alt="">
  <img src="https://img.shields.io/badge/Google-Gemini-4285F4?style=flat-square&logo=google&logoColor=white" alt="">
  <img src="https://img.shields.io/badge/GitHub-Copilot-000?style=flat-square&logo=github&logoColor=white" alt="">
  <img src="https://img.shields.io/badge/Cursor-00D1B2?style=flat-square" alt="">
  <img src="https://img.shields.io/badge/Windsurf-09B6A2?style=flat-square" alt="">
  <img src="https://img.shields.io/badge/Cline-007ACC?style=flat-square" alt="">
  <img src="https://img.shields.io/badge/Continue-FF6F00?style=flat-square" alt="">
</p>

---

## Quick Start

### &nbsp;&nbsp;1&nbsp;&nbsp; Add to your AI agent

> **CLI agents** &mdash; one command, done:

```bash
# Claude Code (Anthropic)
claude mcp add --transport stdio --scope user azure-sql -- npx -y mcp-azure-sql

# Codex CLI (OpenAI)
codex mcp add azure-sql -- npx -y mcp-azure-sql

# Gemini CLI (Google)
gemini mcp add -s user azure-sql npx -y mcp-azure-sql
```

> **IDE agents** &mdash; add this JSON block to your agent's config file:

```json
{
  "azure-sql": {
    "command": "npx",
    "args": ["-y", "mcp-azure-sql"],
    "env": {
      "AZURE_SQL_CONFIG_FILE": "~/.config/azure-sql-mcp/connections.json"
    }
  }
}
```

<details>
<summary>Where does this go? (click to expand)</summary>

| Agent | File | Key |
|:------|:-----|:----|
| ![Copilot](https://img.shields.io/badge/-GitHub_Copilot-000?style=flat-square&logo=github&logoColor=white) | VS Code `settings.json` | `"mcp" > "servers"` |
| ![Cursor](https://img.shields.io/badge/-Cursor-00D1B2?style=flat-square) | `~/.cursor/mcp.json` | `"mcpServers"` |
| ![Windsurf](https://img.shields.io/badge/-Windsurf-09B6A2?style=flat-square) | `~/.codeium/windsurf/mcp_config.json` | `"mcpServers"` |
| ![Cline](https://img.shields.io/badge/-Cline-007ACC?style=flat-square&logo=visualstudiocode&logoColor=white) | Cline Settings UI or `cline_mcp_settings.json` | `"mcpServers"` |
| ![Continue](https://img.shields.io/badge/-Continue-FF6F00?style=flat-square) | `~/.continue/config.yaml` | `mcpServers:` (YAML) |
| ![Claude](https://img.shields.io/badge/-Claude_Desktop-D97706?style=flat-square&logo=anthropic&logoColor=white) | `claude_desktop_config.json` | `"mcpServers"` |

</details>

### &nbsp;&nbsp;2&nbsp;&nbsp; Configure your databases

Create `~/.config/azure-sql-mcp/connections.json`:

```json
{
  "defaults": { "auth": "azuread" },
  "connections": [
    {
      "name": "dev",
      "server": "myserver.database.windows.net",
      "database": "myapp-dev",
      "environment": "dev"
    },
    {
      "name": "prod",
      "server": "myserver.database.windows.net",
      "database": "myapp-prod",
      "environment": "prod",
      "prod": true
    }
  ]
}
```

> See [`example-config.json`](example-config.json) for SQL auth, connection strings, and all options.

### &nbsp;&nbsp;3&nbsp;&nbsp; Sign in to Azure

```bash
az login
```

### &nbsp;&nbsp;&check;&nbsp;&nbsp; Done

Restart your AI agent. You now have 34 database tools.

---

## Tools

<table>
<tr>
<td width="200"><strong>Query &amp; Execute</strong></td>
<td><code>query</code> &bull; <code>execute</code></td>
</tr>
<tr>
<td><strong>Schema</strong></td>
<td><code>list_tables</code> &bull; <code>describe_table</code> &bull; <code>describe_indexes</code> &bull; <code>describe_foreign_keys</code> &bull; <code>search_columns</code> &bull; <code>table_row_counts</code> &bull; <code>search_objects</code> &bull; <code>describe_triggers</code></td>
</tr>
<tr>
<td><strong>Views / Procs / Functions</strong></td>
<td><code>list_views</code> &bull; <code>describe_view</code> &bull; <code>list_stored_procs</code> &bull; <code>describe_sproc</code> &bull; <code>list_functions</code> &bull; <code>describe_function</code></td>
</tr>
<tr>
<td><strong>Performance</strong></td>
<td><code>explain_query</code> &bull; <code>active_queries</code> &bull; <code>long_running_queries</code> &bull; <code>top_queries_by_cpu</code> &bull; <code>wait_stats</code> &bull; <code>blocking_chains</code> &bull; <code>index_usage_stats</code> &bull; <code>missing_indexes</code> &bull; <code>table_statistics_health</code> &bull; <code>database_size</code></td>
</tr>
<tr>
<td><strong>Connections</strong></td>
<td><code>list_connections</code> &bull; <code>test_connection</code> &bull; <code>connection_info</code> &bull; <code>add_connection</code></td>
</tr>
<tr>
<td><strong>Compliance</strong></td>
<td><code>compare_tables</code> &bull; <code>ef6_migration_status</code> &bull; <code>permission_audit</code> &bull; <code>hangfire_dashboard</code></td>
</tr>
</table>

---

## Safety

Your AI agent **cannot** accidentally destroy production.

| | `query` | `execute` on dev | `execute` on prod |
|:--|:--|:--|:--|
| **SELECT** | &check; | &mdash; | &mdash; |
| **INSERT / UPDATE / DELETE** | &cross; | `confirm=true` | `confirm=true` |
| **DROP / TRUNCATE / ALTER** | &cross; | `confirm=true` | **Blocked** |
| **EXEC / {call}** | &cross; | `confirm=true` | `confirm=true` |

Production = any connection with `"prod": true` or `"environment": "prod"`.

---

## Authentication

| Mode | When to use |
|:--|:--|
| **`azuread`** (default) | Azure SQL via `az login`, managed identity, or service principal |
| **`sql`** | Legacy SQL Server &mdash; add `"user"` and `"password"` to connection |
| **`connstr`** | Custom &mdash; add `"connection_string"` with full connection string |

---

## Why Go?

| | **Go** | TypeScript / Python |
|:--|:--|:--|
| Startup | ~5ms | 500ms+ |
| Binary | Single 16MB file | Runtime + packages |
| Memory | ~15MB | 80MB+ |
| Install | Download &rarr; run | `npm install` + Node.js |
| Azure AD | Native driver | `@azure/identity` shim |
| Concurrency | Goroutines | Event loop / GIL |

---

<details>
<summary><strong>Configuration reference</strong></summary>

### Config file

```json
{
  "defaults": { "auth": "azuread", "app_name": "my-app" },
  "connections": [{
    "name": "unique-name",
    "server": "server.database.windows.net",
    "database": "dbname",
    "auth": "azuread",
    "environment": "dev",
    "description": "Human-readable note",
    "prod": false
  }]
}
```

**Environment tags:** `dev` `sqa` `qa` `beta` `delta` `test` `preprod` `prod`

### Environment variables

```bash
# Legacy (no config file needed)
export AZURE_SQL_CONNECTIONS="dev=server.database.windows.net/mydb;qa=qaserver.database.windows.net/qadb"

# Override production list
export AZURE_SQL_PROD_CONNECTIONS="my-prod-db,my-staging-db"
```

</details>

<details>
<summary><strong>Architecture</strong></summary>

```
AI Agent  ──stdio/JSON-RPC──>  mcp-azure-sql  ──Azure AD──>  Azure SQL
                                    │
                                    ├── 34 tools with MCP annotations
                                    ├── Tiered safety (read/write/dangerous)
                                    ├── Connection pool (30s ping skip)
                                    ├── Audit logging
                                    └── Error sanitization
```

Built with [`mcp-go`](https://github.com/mark3labs/mcp-go) + [`go-mssqldb`](https://github.com/microsoft/go-mssqldb). MCP protocol `2024-11-05`. Tool annotations (`ReadOnlyHint`, `DestructiveHint`, `IdempotentHint`, `OpenWorldHint`) on all 34 tools. Logging capability enabled.

</details>

<details>
<summary><strong>Development &amp; releases</strong></summary>

```bash
go build -o mcp-azure-sql .
go vet ./...
./mcp-azure-sql --version
```

**Release:** `git tag v1.3.0 && git push origin v1.3.0` &rarr; GitHub Actions builds 6 platform binaries via GoReleaser &rarr; npm auto-publishes.

</details>

---

<p align="center">
  <a href="https://albahub.io"><strong>Albahub, LLC</strong></a> &bull; <a href="LICENSE">MIT License</a>
</p>
