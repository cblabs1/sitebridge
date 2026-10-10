# SiteBridge Hub 0.5.1 — native WordPress approval

Version 0.5.1 adds authentication header compatibility for CGI/shared hosting: the hub sends a SiteBridge fallback header alongside standard Basic authentication, and the plugin validates it using WordPress's Application Password authentication on SiteBridge REST routes only. It also recognizes Application Passwords authenticated before the plugin's observation hook. Update both the hub and WordPress plugin, then request a fresh link after a failed 0.5.0 attempt. No permissions, hashes or authentication checks are bypassed.

A PHP remote MCP hub with OAuth sign-in and WordPress's native Application Password authorization. An AI requests a temporary connection URL; the user opens it in their own browser, signs in to WordPress, and clicks Approve. WordPress returns to the hub, which verifies the credential, stores it encrypted, and automatically returns to the AI client. Additional sites use the same approval journey and the agent checks `connection_status` afterward.

AI client → HTTPS PHP MCP hub → SiteBridge WordPress plugin → WordPress

## Upgrade to 0.5.0

**Both the hub and the installed WordPress plugin must be updated.** GitHub CI/CD updates the hub only. Upload `downloads/sitebridge-plugin_0.5.1.zip` using WordPress → Plugins → Add New → Upload Plugin, then replace the existing SiteBridge plugin. Existing settings and custom API keys remain. Start a fresh connection after updating.

The hub now sends users to WordPress's own `wp-admin/authorize-application.php` screen instead of SiteBridge's custom `admin-post.php` approval page. The native screen handles login, application name, nonce, Approve and Reject. Dark SiteBridge cards remain on the hub's URL-entry, completion and error screens. This improves use of standard WordPress infrastructure; it does not guarantee an individual host's firewall will allow every request.

No database reset or encryption-key change is needed. Existing custom-key connections still work. New native connections use plugin permissions dynamically on every request. Their credentials are restricted to the `sitebridge/v1` REST namespace while the plugin is active; other WordPress REST namespaces and XML-RPC are rejected for the SiteBridge application ID. Other applications, including WPVibe, are unaffected.

## Hostinger setup

1. Use PHP 8.3 or a supported newer version with **curl, openssl and pdo_sqlite** enabled.
2. Upload `index.php`, `connections.php`, `connection-ui.css`, and hidden `.htaccess` to the hub's domain root. Keep the existing private `config.php`.
3. Create a PHP-writable directory outside the public document root for SQLite, such as `/home/YOUR_USER/sitebridge-private`.
4. Generate a separate encryption secret with `openssl rand -hex 32`. Keep it stable and backed up privately.
5. Configure:

```php
<?php
return array(
    'public_url' => 'https://YOUR-HUB-DOMAIN',
    'encryption_key' => 'YOUR_64_CHARACTER_HEX_SECRET',
    'storage_path' => '/home/YOUR_USER/sitebridge-private/connections.sqlite',
    'master_token' => '',
    'sites' => array(),
    'timeout' => 30,
);
```

The public hub URL must be an HTTPS domain root. Keep configuration, SQLite, backups and credentials out of GitHub and public_html. Exclude the MCP and callback endpoints from caching, analytics and bot challenges. WordPress's standard success callback includes the generated Application Password in the HTTPS query string. The hub immediately redirects to a clean URL without rendering the password and sends `Cache-Control: no-store` and `Referrer-Policy: no-referrer`; configure hosting access logs to omit/redact callback query strings as well. Application Passwords are encrypted with AES-256-GCM at rest. Never share a callback URL, password or token in chat.

## Connect an AI client

Add the hub root URL as a remote MCP connector, selecting **OAuth**:

`https://lemonchiffon-pigeon-682675.hostingersite.com/`

1. Enter the final HTTPS WordPress home URL on the hub's connection page.
2. The hub checks SiteBridge 0.5.0 native authorization support and opens WordPress's Application Password authorization screen.
3. **The user signs in as a WordPress administrator and clicks Approve.** The AI must not approve its own access or ask the user to copy credentials.
4. WordPress returns to the hub. The hub binds the return to the initiating browser, verifies the credential against the original site, and displays Connected.
5. For initial OAuth setup, the page automatically returns to the registered AI client with a one-time PKCE code. A Return to your AI app link remains available if automatic navigation is disabled.
6. Ask the agent to call `list_sites` and `site_info`.

To add another site without reconnecting the AI connector, ask: **“Use connect_site to connect https://my-other-site.com.”** Open its `approval_url`, approve, and ask the agent to check `connection_status` using the returned `request_id`. Multiple sites can belong to the same AI authorization.

Each request expires after 10 minutes. OAuth authorization codes and browser results last 2 minutes. Cookie-bound state and atomic claims prevent callback replay. OAuth forms retain safe restart and repeat-submission support.

## WordPress permissions and revocation

Enable SiteBridge and Site info under **Settings → SiteBridge**. Enable additional capabilities only as needed. Native connections follow these settings on every request; permission changes take effect without another connection approval. Existing custom keys also retain their individual scopes.

The plugin lists the current administrator's SiteBridge Application Passwords alongside custom API keys. Revoke a native connection there or in **Users → Profile → Application Passwords**. `disconnect_site` attempts to revoke the authenticated native password and removes the hub record. It returns `wordpress_revoked: false` if revocation cannot be confirmed; in that case revoke the password directly in WordPress if it is still listed. Legacy custom-key disconnect removes only the hub reference; revoke its key in plugin settings too.

Keep SiteBridge active for its namespace restrictions to apply. Native passwords otherwise inherit the WordPress user's capabilities; revoke SiteBridge Application Passwords before deactivating or removing the plugin. WordPress stores their hashes, and the hub holds the encrypted usable credentials.

## Client isolation and compatibility

Each OAuth authorization gets an isolated workspace. Its tokens can reach only sites approved in that workspace. Different AI clients and fresh re-authorizations do not share sites automatically. This version has no shared account, email sign-in or account recovery.

Public OAuth clients require S256 PKCE. Dynamic registration and HTTPS Client ID Metadata Documents are supported. Confidential client authentication and server-initiated streaming are not implemented. The MCP transport uses single-response HTTP JSON.

WordPress must support HTTPS, Application Passwords and the SiteBridge 0.5.0 plugin. Destinations must resolve to public IPv4 addresses; requests pin DNS and do not follow redirects. Enter the canonical home URL including `www` or a subdirectory when applicable. The native authorization endpoint must be on that same WordPress installation.

Legacy manual bearer configurations still work with `master_token` and `sites`. A master token cannot access other OAuth workspaces. Leave it empty to disable manual access.

## Verification and troubleshooting

- Browser `GET /` shows the landing page; non-browser GET returns health JSON.
- `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` return metadata.
- Unauthenticated MCP POST returns HTTP 401 with discovery information.
- `/config.php`, `/config.sample.php`, databases and development folders must not be publicly served.
- The target's `/wp-json/sitebridge/v1/connect/info` reports native authorization availability.
- Complete real approval, verify `site_info`, revoke the native password, then confirm access fails.

A 404 on `connect/info` means the installed plugin needs updating. Unavailable authorization means HTTPS, WordPress Application Passwords, or SiteBridge/Site info is disabled. A browser mismatch means the approval was opened or returned in another browser. Start a fresh request in the same browser.

A ModSecurity rejection needs the host's specific rule ID; use a narrowly scoped exception if required. Native WordPress authorization avoids SiteBridge's former custom approval URL, but the host may independently restrict login, native authorization, or REST traffic. Do not disable the firewall globally.

## Development checks

```bash
php tests/hub-security.php
php tests/plugin-approval.php
php tests/plugin-native.php
php tests/plugin-native.php xmlrpc
php tests/plugin-forwarded.php
python3 tests/ui-checks.py
python3 tests/hub-protocol.py
```

The HTTP suite runs a local PHP server with test-only remote transport fixtures. It tests native callback verification, browser binding, rejection/replay, encrypted storage, Basic authentication, revocation, and OAuth completion without touching a real WordPress site. Plugin tests stub WordPress APIs. Real WordPress/browser and host testing remain deployment checks.

Native integration follows [WordPress's Application Passwords integration guide](https://make.wordpress.org/core/2020/11/05/application-passwords-integration-guide/). SiteBridge is independent and not affiliated with WPVibe.
