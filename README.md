# SiteBridge Hub 0.3.1 — browser-approved WordPress connections

A standalone PHP remote MCP hub with OAuth browser sign-in and administrator-approved WordPress connections. An AI can call `connect_site`, give the user an approval link, and verify completion using `connection_status`. No WordPress password or manually copied plugin API key is needed.

This is an initial implementation, not a claim of compatibility with every AI application or a security-audited hosted service. The AI client must support remote HTTP MCP with OAuth public clients and S256 PKCE. Live client/WordPress compatibility must be checked after deployment.

## Architecture

AI client → HTTPS MCP hub → SiteBridge plugin → WordPress

The hub remains PHP to run on ordinary PHP hosting. No Node daemon, VPS, background worker or new WordPress database is required. The hub uses a private SQLite database. PHP must have **curl, openssl and pdo_sqlite** enabled. Use PHP 8.3 or a supported newer version.

## Version 0.3.1 recovery fix

Expired, resubmitted or cookie-mismatched OAuth forms now offer a Restart connection action backed by a 30-minute, server-validated context. Restart creates a fresh browser-bound form without approving access, changing the registered redirect URI or disabling CSRF checks. The error message distinguishes an expired form from an unverifiable browser cookie. If the original AI client has also expired its OAuth attempt, start again from that client.

## Version 0.3 changes

The hub welcome screen, URL entry, WordPress login (only when entered from a SiteBridge connection), approval, success, cancellation and connection errors now share a responsive SiteBridge design. The WordPress settings page includes onboarding steps and connection management.

The approval screen has one Approve button and Cancel, with no permission checkboxes. New connections use the administrator's already-enabled settings. A server-side snapshot prevents settings enabled after opening the screen from broadening that approval; settings disabled before submission are removed from the grant. Existing connections and keys keep their scopes. Approval links opened before updating the plugin may require a fresh link.

This is a SiteBridge design inspired by the connection pattern, not a copy of WPVibe branding or an implementation of WPVibe email accounts.

## Hostinger upgrade

1. Back up the existing hub files and private `config.php`.
2. Upload `index.php`, `connections.php`, `connection-ui.css`, and `.htaccess` to the domain's document root. Include the hidden `.htaccess` file. Do not overwrite your private config blindly. `README.md` and `config.sample.php` are reference files; tests and plugin source do not need uploading.
3. Create a folder **outside public_html**, for example `/home/u123456789/sitebridge-private`. Use your actual hosting account path. Its PHP user must be able to write there. A location inside the website's document root is deliberately rejected.
4. Generate a **separate** encryption secret on your computer with `openssl rand -hex 32`. Keep it stable and back it up privately: changing or losing it makes existing stored WordPress keys unreadable.
5. Merge these settings into `config.php`:

```php
<?php
return array(
    'public_url' => 'https://lemonchiffon-pigeon-682675.hostingersite.com',
    'encryption_key' => 'YOUR_NEW_64_CHARACTER_HEX_SECRET',
    'storage_path' => '/home/YOUR_HOSTINGER_USER/sitebridge-private/connections.sqlite',
    'master_token' => '',
    'sites' => array(),
    'timeout' => 30,
);
```

`public_url` must be an HTTPS domain root; subdirectory installation is not supported by the OAuth routing in this version. Do not put the SQLite database in GitHub or public_html. Exclude this endpoint from page caching, bot challenges and HTML login protection; MCP and OAuth responses already send `Cache-Control: no-store`.

6. Install **SiteBridge plugin 0.3.0** on each WordPress website. The old 0.1 plugin cannot process approval links. In WordPress → Plugins → Add New → Upload Plugin, upload the new ZIP and choose to replace the existing version. Existing manual keys/settings remain.
7. In Settings → SiteBridge, enable only the capabilities you want to offer. Start with Site info. An approval cannot enable a capability that is disabled here. Leave database writes and code editing disabled unless explicitly needed.

## Connect an AI client

Add this as a remote MCP server URL, selecting **OAuth** where offered:

`https://lemonchiffon-pigeon-682675.hostingersite.com/`

1. The client discovers the hub's OAuth endpoints and opens the Connect WordPress page.
2. Enter the final HTTPS WordPress home URL. SiteBridge must already be installed.
3. Sign in to WordPress as an administrator if asked.
4. Review the AI app and website. Access follows the permissions already enabled in WordPress → Settings → SiteBridge; expand connection details to see the access summary and hub URL. Approve or cancel.
5. Click **Finish connecting to your AI app**. This finishes OAuth using a one-time code; the AI client manages its own access/refresh tokens.
6. Ask the agent to call `list_sites` and `site_info`.

The initial OAuth sign-in connects the first site. To add another site, ask: **“Use connect_site to connect https://my-other-site.com.”** Open the returned `approval_url`, approve in WordPress, then have the agent call `connection_status` with its `request_id`.

A connection request lasts 10 minutes. Credential exchange codes and OAuth authorization codes last 2 minutes. If a flow expires, request a fresh link. Never put API keys, master tokens or WordPress passwords in approval URLs or chat messages.

### Client workspaces and limitations

Each completed OAuth authorization gets an isolated workspace. Its access and refresh tokens can reach only sites approved in that workspace. Different AI clients/authorizations do **not** automatically share sites. Re-authorizing from scratch creates a new workspace and requires site approval again; this version does not provide a shared email account, account recovery or email-code sign-in like WPVibe.

The hub supports public OAuth clients with PKCE, dynamic client registration and HTTPS Client ID Metadata Documents. Confidential client authentication is not implemented. Clients requiring different registration/authentication mechanisms may need an adapter or further work. The MCP transport uses single-response JSON; server-initiated streaming is not implemented.

Only public HTTPS WordPress destinations with working IPv4 DNS are supported. The hub blocks private/reserved destinations, pins resolved addresses and does not follow redirects; supply the final canonical WordPress URL, including `www` or a path if applicable. The plugin expects that URL to match WordPress `home_url()`.

### Legacy manual mode

To retain the old private bearer setup, keep your own `master_token` and existing `sites` entries. That token can see those manual sites and any sites approved through it, but cannot see OAuth workspaces. Do not give the master token to customers. Leave it empty to disable manual access. Old configurations without the new settings still support manual tools, but browser connection tools require the new configuration.

## Verification

- `GET /` in a browser shows the welcome page. Requests without an HTML Accept header still return health JSON (neither verifies storage or WordPress connectivity).
- `GET /.well-known/oauth-authorization-server` returns the OAuth endpoint metadata.
- `GET /.well-known/oauth-protected-resource` returns resource metadata.
- An unauthenticated MCP POST returns HTTP 401 with a `WWW-Authenticate` discovery header.
- `GET /config.php` and `/config.sample.php` should return 403.
- Complete a real administrator approval, verify `site_info`, then revoke its key in WordPress and confirm subsequent calls fail.
- Test your intended AI clients; passing local protocol tests does not prove all-client compatibility.

If discovery gives 404, check `.htaccess` and rewrite support. For HTTP 500, inspect PHP error logs and extensions. A storage error means the private directory path, write permissions or encryption secret needs correction. A WordPress mismatch means the URL differs from its configured home URL. A failed approval should be retried with a fresh request; the plugin revokes the newly generated key if completion fails.

## Access controls

- WordPress administrator login, a nonce and an explicit POST are required for approval.
- Browser approval does not change global plugin settings; each connection key inherits the capabilities enabled when the approval screen opens, intersected with settings still enabled at submission. Empty-scope keys are never generated by this flow.
- WordPress keys are sent server-to-server over HTTPS using an expiring, one-time exchange code, and stored with AES-256-GCM encryption in the private hub database.
- OAuth uses hashed opaque access/refresh tokens, S256 PKCE, registered redirect URI matching, resource audience binding, refresh rotation with replay-family revocation, expiry, revocation and endpoint rate limits.
- The hub maintains isolation by workspace, including connection status and disconnect operations. There is no global customer directory exposed to clients.
- Revoke a connection's API key in WordPress → Settings → SiteBridge to stop site access immediately. `disconnect_site` removes the hub reference only; the WordPress key remains until revoked there.
- OAuth token revocation disables the relevant token family. It does not delete the WordPress API key or connection history.
- Backup the database and encryption key privately. This single-instance SQLite version is not a horizontally scaled hosted service. Do not place it on multiple instances with independent disks.

## Development checks

The repository's tests require PHP with curl, openssl and pdo_sqlite, plus Python 3. Run from the repository root:

```bash
php tests/hub-security.php
php tests/plugin-approval.php
python3 tests/ui-checks.py
python3 tests/hub-protocol.py
```

The HTTP suite starts a temporary local PHP server and uses fixture grants; it never connects a real WordPress site. The plugin suite stubs WordPress APIs. Real WordPress/browser testing and target-client testing remain deployment checks.

Independent software; not affiliated with WPVibe.
