# SiteBridge WordPress Plugin 0.5.0

SiteBridge connects WordPress to your AI through a remote PHP MCP hub. Install this plugin on each website, configure access in **Settings → SiteBridge**, and let the AI generate a connection link.

## Connect

1. Install or replace SiteBridge using `sitebridge-plugin_0.5.0.zip` and activate it.
2. Enable SiteBridge and Site info in **Settings → SiteBridge**. Enable other capabilities as needed.
3. Add your SiteBridge hub URL as an OAuth MCP connector in your AI app.
4. Enter the website URL or ask the AI to use `connect_site`.
5. Open the generated link yourself. WordPress shows its built-in Application Password authorization screen; sign in as an administrator and click Approve.
6. WordPress returns to the hub and shows Connected. Initial connector setup automatically returns to the AI app; additional site connections can be checked with `connection_status`.

No manual key copying is needed. The AI prepares the connection; the user approves access. This requires hub 0.5.0 and WordPress Application Passwords over HTTPS. Updating the hub does not update plugins installed on other websites.

## Permissions

Native connections use the capabilities currently enabled in plugin settings on every request. Changing those settings updates access immediately. SiteBridge Application Passwords are restricted to the `sitebridge/v1` REST namespace while this plugin is active and cannot authenticate XML-RPC. Existing custom API keys retain their individual scopes and global settings checks.

| Capability | Tools |
| --- | --- |
| Site info | Site details, list/read posts, pages and products |
| Content management | Create and update posts/pages |
| WooCommerce | Update products |
| Settings read | Read allowed WordPress options |
| Database read | Guarded read-only queries |
| Database write | Guarded writes with explicit confirmation |
| Code editing | Allowed files inside wp-content, with backups |

Only Site info is enabled by default. Database writes and file editing remain advanced, opt-in capabilities.

## Manage connections

The current administrator's native connections appear under **Settings → SiteBridge → Connected AI clients and API keys**. Revoke them there or under **Users → Profile → Application Passwords**. Other administrators manage their own native passwords from their profiles. The hub's `disconnect_site` also revokes a reachable native credential.

Revoke SiteBridge Application Passwords before deactivating or removing the plugin: its additional endpoint restrictions require the plugin to remain active. WordPress stores password hashes; the hub stores the usable password encrypted. Never paste passwords or callback URLs into chat.

## Existing integrations

Existing custom-key connections continue to work. Manual keys remain available under the Advanced section for custom clients and the original local Node stdio MCP server. Send them to SiteBridge REST endpoints using `Authorization: Bearer sbk_...`.

The hub README documents Hostinger setup, OAuth compatibility, private SQLite storage and verification. SiteBridge is independent and is not affiliated with WPVibe.
