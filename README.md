# SiteBridge Hub — your online, multi-site MCP server (PHP)

This is the "WPVibe-style" piece: **one hosted endpoint that manages many WordPress sites.**
It's written in **PHP** so it runs on ordinary shared hosting (Hostinger Business / hPanel) —
no Node process, no VPS required. It speaks the Model Context Protocol over HTTPS and proxies
each call to the **SiteBridge plugin** on whichever site you name.

```
   AI client ──HTTPS + master token──▶  SiteBridge Hub (this, on Hostinger)  ──plugin key──▶  site A
                                                                              ──plugin key──▶  site B
                                                                              ──plugin key──▶  site C
```

Every tool takes a `site` argument (like WPVibe's `site_url`). A `list_sites` tool shows what's registered.

---

## Prerequisites

1. The **SiteBridge plugin** installed and activated on each WordPress site you want to manage,
   with the capabilities you want enabled and an API key generated (Settings → SiteBridge).
2. A place to host this folder with **HTTPS** — a subdomain on your Hostinger account is perfect,
   e.g. `mcp.yourdomain.com`.

> PHP shared hosting runs this fine because it's plain request/response PHP — there's no
> long-running process to keep alive.

---

## Deploy to Hostinger (hPanel)

1. In hPanel, create a subdomain, e.g. **`mcp.yourdomain.com`**, and note its document root
   (something like `domains/yourdomain.com/public_html/mcp` or a dedicated folder).
2. Upload the contents of this `sitebridge-hub/` folder into that document root
   (`index.php`, `.htaccess`, `config.sample.php`). Use hPanel **File Manager** or FTP.
3. In File Manager, **copy `config.sample.php` to `config.php`** and edit it:
   - Set `master_token` to a long random string. Generate one at
     <https://www.random.org/strings/> or, if you have SSH, `openssl rand -hex 32`.
   - Under `sites`, add each site: a short name → its `url` and the `sbk_…` plugin key from that site.
4. Make sure the subdomain has **SSL** (hPanel → SSL → install free Let's Encrypt if not already).

**Test it's live** — visit `https://mcp.yourdomain.com/` in a browser. You should see:
```json
{"ok":true,"service":"sitebridge-hub","transport":"mcp/http"}
```

**Test a real call** (replace the token):
```bash
curl -X POST https://mcp.yourdomain.com/ \
  -H "Authorization: Bearer YOUR_MASTER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_sites","arguments":{}}}'
```
You should get your list of registered sites back.

Your **MCP endpoint URL** is: `https://mcp.yourdomain.com/`

---

## Connect an AI client

### Claude Code (native remote MCP — simplest)
```bash
claude mcp add sitebridge --transport http https://mcp.yourdomain.com/ \
  --header "Authorization: Bearer YOUR_MASTER_TOKEN"
```
Then: *"Using sitebridge, list my sites"* → *"get site_info for rickrak"*.

### Claude Desktop (via the mcp-remote bridge)
Claude Desktop launches local (stdio) servers, so use the standard `mcp-remote` bridge to reach
your hosted hub. Edit `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "sitebridge": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote",
        "https://mcp.yourdomain.com/",
        "--header", "Authorization: Bearer YOUR_MASTER_TOKEN"
      ]
    }
  }
}
```
Restart Claude Desktop. (This needs Node/npx on the *desktop*, not on the server.)

### Any other MCP client
Point it at `https://mcp.yourdomain.com/` with header `Authorization: Bearer YOUR_MASTER_TOKEN`.

---

## Adding a new site later

1. Install + activate the SiteBridge plugin on the new site, enable capabilities, generate a key.
2. Add an entry under `sites` in `config.php`:
   ```php
   'newsite' => array( 'url' => 'https://newsite.com', 'key' => 'sbk_...' ),
   ```
That's it — no redeploy needed; the next call picks it up.

---

## Tools (each takes a `site` argument, except `list_sites`)

`list_sites`, `site_info`, `list_content`, `get_content`, `create_content`, `update_content`,
`list_products`, `get_product`, `update_product`, `get_option`, `db_query`, `db_execute` ⚠,
`read_file` ⚠, `write_file` ⚠.

The ⚠ tools only work if that capability is enabled in the site's SiteBridge plugin settings —
the hub can't override a site's own permissions.

---

## Security notes

- **One master token** guards the whole hub — treat it like a password; rotate it by changing
  `config.php`. Anyone with it can reach every registered site, so keep the endpoint HTTPS-only.
- **Two layers of control**: the hub's master token lets a client *in*; each site's plugin key +
  capability toggles decide what can actually be *done* there. A site stays safe even if it's
  registered, because its own DANGEROUS toggles are off unless you enabled them.
- `config.php` is blocked from the web by `.htaccess`. Confirm `https://mcp.yourdomain.com/config.php`
  returns 403, not your secrets.
- Consider a per-site key with only the capabilities that site needs, rather than reusing one key.

## Limitations & next steps

- This hub does single-response JSON-RPC (no server-initiated streaming) — perfect for tools,
  which is all SiteBridge needs.
- Natural upgrades: per-client tokens with site scoping, an activity log table, and a one-click
  browser auth flow for registering sites (like WPVibe's connect link).

*Independent software following the WPVibe pattern; not affiliated with WPVibe.*
