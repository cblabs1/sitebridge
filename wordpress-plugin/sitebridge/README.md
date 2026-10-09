# SiteBridge WordPress Plugin 0.3.0

Browser approval support is now included. Install the plugin on each WordPress website, enable the desired capabilities under **Settings → SiteBridge**, and connect through the updated SiteBridge Hub. Your agent returns a temporary approval link; sign in as an administrator, review the connection, and approve. Manual API key creation still works.

The approval screen has no permission checkboxes. It uses the access already enabled in Settings → SiteBridge and offers Approve or Cancel. The login, approval and completion screens share the SiteBridge design.

Browser connections receive separate scoped keys. Revoke them under **Settings → SiteBridge → Connected AI clients and API keys**. Disabled global capabilities remain disabled and cannot be granted by an approval link. Start with read access only.

The matching hub configuration, private storage requirements, OAuth client support and deployment checks are documented in the hub README. Version 0.1 hubs cannot use this new browser flow.

---

# SiteBridge — a WPVibe-style AI connector you own

SiteBridge lets an AI agent (Claude Desktop, Claude Code, or any MCP client) manage a
WordPress site — read site info, manage content, update WooCommerce products, read
settings and the database, and (when you allow it) run guarded DB writes and edit code.

It has **two parts**, exactly like WPVibe:

```
  AI agent  ⇄  MCP server (Node, runs on your machine/server)  ⇄  WordPress plugin (REST API on the site)
                         mcp-server/                                     wordpress-plugin/sitebridge/
```

1. **The WordPress plugin** (`wordpress-plugin/sitebridge/`) installs on each site and
   adds secure REST endpoints under `/wp-json/sitebridge/v1`, protected by API keys you
   generate in the admin. Every capability is individually toggleable.
2. **The MCP server** (`mcp-server/`) is a small Node program that exposes those endpoints
   to an AI agent as tools. You point it at a site URL + API key.

This is a **starter foundation** — production-minded and safe by default, but intended as
the base you extend, not a finished commercial clone of WPVibe.

---

## Part 1 — Install the WordPress plugin

1. Zip the folder `wordpress-plugin/sitebridge/` (or use the provided `sitebridge-plugin.zip`).
2. In WP admin → **Plugins → Add New → Upload Plugin**, upload the zip and activate.
3. Go to **Settings → SiteBridge**.
4. Under **Capabilities**, enable only what you want the agent to do. Only *Site info* is on
   by default. Leave **DB write** and **Code editing** OFF unless you fully trust the agent.
5. Click **Generate new key**, give it a label, and **copy the key immediately** — it's shown
   only once and stored only as a SHA-256 hash.

Your API base will be: `https://YOURSITE.com/wp-json/sitebridge/v1`

### Quick manual test (optional)
```bash
curl https://YOURSITE.com/wp-json/sitebridge/v1/site \
  -H "Authorization: Bearer sbk_YOURKEY"
```
You should get JSON with your site name, versions, theme, and plugins.

---

## Part 2 — Run the MCP server

Requires **Node.js 18+**.

```bash
cd mcp-server
npm install
SITEBRIDGE_URL="https://YOURSITE.com" \
SITEBRIDGE_KEY="sbk_YOURKEY" \
node index.js
```

The server speaks MCP over stdio, so you normally don't run it by hand — you register it
with your AI client.

### Connect it to Claude Desktop
Edit `claude_desktop_config.json` (Settings → Developer → Edit Config) and add:

```json
{
  "mcpServers": {
    "sitebridge": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-server/index.js"],
      "env": {
        "SITEBRIDGE_URL": "https://YOURSITE.com",
        "SITEBRIDGE_KEY": "sbk_YOURKEY"
      }
    }
  }
}
```

Restart Claude Desktop. You'll see SiteBridge's tools available; ask it e.g.
*"Using sitebridge, what plugins are active on the site?"*

### Connect it to Claude Code
```bash
claude mcp add sitebridge -- node /absolute/path/to/mcp-server/index.js
```
(set the two env vars in your shell first, or add them to the command's environment).

---

## Tools exposed

| Tool | Capability needed | What it does |
|------|-------------------|--------------|
| `site_info` | Site info | Site name, versions, theme, WooCommerce, plugins |
| `list_content` / `get_content` | Site info | List / read posts, pages, any post type |
| `create_content` / `update_content` | Content mgmt | Create / edit posts & pages |
| `list_products` / `get_product` | Site info | Read WooCommerce products |
| `update_product` | WooCommerce | Update price, stock, status, descriptions |
| `get_option` | Settings read | Read a WP option (secrets blocked) |
| `db_query` | DB read | SELECT/SHOW/DESCRIBE/EXPLAIN only (auto-LIMIT) |
| `db_execute` | DB write ⚠ | Single UPDATE/INSERT/DELETE, WHERE required, `confirm:true` |
| `read_file` / `write_file` | Code edit ⚠ | Read/write text & code files inside `wp-content` (auto-backup) |

---

## Security model

- **Keys**: Bearer tokens, shown once, stored as SHA-256 hashes, compared in constant time.
  Revoke any key anytime from the settings screen.
- **Capabilities**: every group is a toggle; disabled = 403. Off by default except site info.
- **DB writes**: single statement only, no DDL (no DROP/ALTER/TRUNCATE), `WHERE` required on
  UPDATE/DELETE, `confirm:true` required. Still dangerous — enable deliberately.
- **Code edits**: confined to `wp-content` (path-traversal blocked), allow-listed extensions,
  a timestamped `.bak` backup is written before every change.
- **Audit log**: every call is recorded (action, status, detail, key label, IP) and shown
  under Settings → SiteBridge → Recent activity.
- **Transport**: always run the site over HTTPS so the Bearer key isn't sent in the clear.

## Ideas to extend next
- Per-key capability scoping (the storage already supports a `caps` array per key).
- Rate limiting / IP allow-listing on the permission callback.
- A one-click browser authorization flow (like WPVibe) instead of manual key copy.
- More tools: media upload, plugin/theme activation, cache purge, menus.

---

*SiteBridge is an independent starter connector. It is not affiliated with WPVibe; it just
follows the same plugin + MCP-server pattern so you can build and own your own version.*
