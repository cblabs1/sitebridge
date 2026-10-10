# SiteBridge WordPress Plugin 0.6.0

Version 0.6.0 adds WPVibe-style tools. Each one follows the capability switches in Settings → SiteBridge:

- **Plugin REST routes and abilities** (`rest_proxy`, off by default): call any REST route as the connected administrator, and discover or run WordPress Abilities. Writes also need content management. Users, application passwords and SiteBridge's own routes are blocked; plugin/theme changes need code editing and `/wp/v2/settings` writes need option writing.
- **Post meta** (read: site info; write: content management): SEO fields such as Yoast and Rank Math, page-builder data, ACF values. Caches for the post are purged after a write.
- **Media upload** (content management): from a public URL or base64 data.
- **Additional CSS** (read: site info; write: content management).
- **Option writes** (`options_write`, off by default): site URLs, roles, active plugins and secrets stay blocked.
- **Cache purge** (content management): WP Rocket, LiteSpeed, W3 Total Cache, WP Super Cache, SiteGround, Autoptimize, WP Fastest Cache, Elementor CSS and the object cache.

Version 0.5.4 fixed an HTTP 403 after approval on sites where another plugin initializes the current user before WordPress marks the request as REST. SiteBridge application passwords are now accepted for SiteBridge REST URLs at that early stage, while XML-RPC and every other context stay refused. Every 403 path now writes its reason to the SiteBridge activity log.

Version 0.5.3 fixes a reproducible authentication recursion when other plugins inspect the current user from capability or option filters. Administrator and enabled-plugin checks now run during REST dispatch, after WordPress finishes initializing the current user. Namespace restrictions, XML-RPC denial and individual capability gates remain enforced. Invalid forwarded credentials now return HTTP 401 instead of an unclassified HTTP 500. Install this plugin update on the affected WordPress site and start a fresh approval; updating the hub alone cannot fix code running on WordPress.

Version 0.5.1 adds authentication header compatibility for CGI/shared hosting: the hub sends a SiteBridge fallback header alongside standard Basic authentication, and the plugin validates it using WordPress's Application Password authentication on SiteBridge REST routes only. It also recognizes Application Passwords authenticated before the plugin's observation hook. Update both the hub and WordPress plugin, then request a fresh link after a failed 0.5.0 attempt. No permissions, hashes or authentication checks are bypassed.

SiteBridge connects WordPress to your AI through a remote PHP MCP hub. Install this plugin on each website, configure access in **Settings → SiteBridge**, and let the AI generate a connection link.

## Connect

1. Install or replace SiteBridge using `sitebridge-plugin_0.5.3.zip` and activate it.
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
