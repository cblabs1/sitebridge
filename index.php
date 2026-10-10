<?php
/**
 * SiteBridge Hub — a multi-site MCP server implemented in PHP.
 *
 * Runs on ordinary PHP shared hosting (e.g. Hostinger Business/hPanel). It speaks the
 * Model Context Protocol over HTTP (JSON-RPC 2.0 via POST — the "Streamable HTTP"
 * transport, single-response mode), authenticates every request with a master token,
 * and proxies each tool call to the SiteBridge plugin running on the target WordPress site.
 *
 *   AI client  ──HTTPS + master token──▶  THIS hub  ──plugin key──▶  SiteBridge plugin on site
 *
 * Deploy: upload this folder to a subdomain docroot (e.g. mcp.yourdomain.com), copy
 * config.sample.php to config.php and fill it in. The MCP endpoint URL is the folder URL.
 *
 * @package SiteBridgeHub
 */

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

header( 'Content-Type: application/json' );
// Never cache MCP responses.
header( 'Cache-Control: no-store' );

$config_path = __DIR__ . '/config.php';
if ( ! file_exists( $config_path ) ) {
	http_response_code( 500 );
	echo json_encode( array( 'error' => 'Hub not configured: copy config.sample.php to config.php.' ) );
	exit;
}
$config = require $config_path;
require_once __DIR__ . '/connections.php';
set_exception_handler( function ( $error ) use ( $config ) {
    $status = $error instanceof RuntimeException && $error->getCode() >= 400 && $error->getCode() <= 599 ? $error->getCode() : 500;
    error_log( 'SiteBridge hub error: ' . get_class( $error ) );
    if ( in_array( $_GET['route'] ?? '', array( 'authorize', 'connect', 'connected' ), true ) && strpos( $_SERVER['HTTP_ACCEPT'] ?? '', 'text/html' ) !== false ) {
        http_response_code( $status );
        $message = $status === 500 ? 'We couldn’t finish this step. Please try again or contact your site administrator.' : $error->getMessage();
        sbh_html( 'Connection needs attention', '<div class="sb-outcome"><div class="sb-outcome-icon is-error" aria-hidden="true">!</div><p class="sb-eyebrow">Let’s try that again</p><h1 id="sb-title">Connection needs attention</h1><p class="sb-lead">' . htmlspecialchars( $message, ENT_QUOTES, 'UTF-8' ) . '</p>' . sbh_restart_action( $config ) . '<p class="sb-note">If restarting doesn’t help, return to your AI app and start a new connection.</p></div>' );
    }
    sbh_json( array( 'error' => $status === 500 ? 'Internal server error. Check server logs and configuration.' : $error->getMessage() ), $status );
} );
sbh_browser_routes( $config );

// Only POST carries JSON-RPC. A GET is handy as a health check.
$method_http = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ( 'GET' === $method_http && ( $_GET['route'] ?? '' ) !== 'mcp' && empty( $_SERVER['HTTP_AUTHORIZATION'] ) && strpos( $_SERVER['HTTP_ACCEPT'] ?? '', 'text/event-stream' ) === false ) {
    if ( strpos( $_SERVER['HTTP_ACCEPT'] ?? '', 'text/html' ) !== false && ! empty( $config['public_url'] ) ) { sbh_landing( $config ); }
	echo json_encode( array( 'ok' => true, 'service' => 'sitebridge-hub', 'transport' => 'mcp/http' ) );
	exit;
}

// ---------------------------------------------------------------------------
// Auth: master token via Authorization: Bearer <token>
// ---------------------------------------------------------------------------

function sbh_bearer() {
	$hdr = '';
	if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
		$hdr = $_SERVER['HTTP_AUTHORIZATION'];
	} elseif ( isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) {
		$hdr = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
	} elseif ( function_exists( 'getallheaders' ) ) {
		foreach ( getallheaders() as $k => $v ) {
			if ( strtolower( $k ) === 'authorization' ) {
				$hdr = $v;
				break;
			}
		}
	}
	if ( 0 === stripos( $hdr, 'bearer ' ) ) {
		return trim( substr( $hdr, 7 ) );
	}
	return trim( $hdr );
}

$raw  = sbh_body();
$msg  = json_decode( $raw, true );
$id   = is_array( $msg ) && isset( $msg['id'] ) ? $msg['id'] : null;

/**
 * Emit a JSON-RPC error and exit.
 */
function sbh_error( $id, $code, $message, $http = 200 ) {
	http_response_code( $http );
	echo json_encode(
		array(
			'jsonrpc' => '2.0',
			'id'      => $id,
			'error'   => array( 'code' => $code, 'message' => $message ),
		)
	);
	exit;
}

/**
 * Emit a JSON-RPC result and exit.
 */
function sbh_result( $id, $result ) {
	echo json_encode(
		array(
			'jsonrpc' => '2.0',
			'id'      => $id,
			'result'  => $result,
		)
	);
	exit;
}

// Constant-time token check.
$token = sbh_bearer();
$identity = sbh_identity( $config, $token );
if ( ! $identity ) {
    if ( ! empty( $config['public_url'] ) ) {
        header( 'WWW-Authenticate: Bearer resource_metadata="' . sbh_base( $config ) . '/.well-known/oauth-protected-resource", scope="sitebridge"' );
    }
	sbh_error( $id, -32001, 'Unauthorized: sign in to SiteBridge or provide a valid bearer token.', 401 );
}

if ( 'POST' !== $method_http ) {
	http_response_code( 405 );
	echo json_encode( array( 'error' => 'Method not allowed' ) );
	exit;
}

$config['_identity'] = $identity;
$manual_sites = $identity['owner'] === 'legacy-admin' ? ( $config['sites'] ?? array() ) : array();
$config['sites'] = ! empty( $config['public_url'] ) ? array_merge( $manual_sites, sbh_connections( $config, $identity['owner'] ) ) : $manual_sites;

if ( ! is_array( $msg ) || ! isset( $msg['method'] ) ) {
	sbh_error( $id, -32600, 'Invalid JSON-RPC request.', 400 );
}

$method = $msg['method'];
$params = isset( $msg['params'] ) && is_array( $msg['params'] ) ? $msg['params'] : array();

// Notifications (no id) — acknowledge with 202 and no body.
if ( null === $id && 0 === strpos( $method, 'notifications/' ) ) {
	http_response_code( 202 );
	exit;
}

// ---------------------------------------------------------------------------
// Proxy helper: call the SiteBridge plugin on a given site.
// ---------------------------------------------------------------------------

function sbh_call_site( $config, $site, $http_method, $path, $query = array(), $body = null ) {
	if ( ! isset( $config['sites'][ $site ] ) ) {
		return array( 'ok' => false, 'error' => "Unknown site '{$site}'. Use list_sites to see configured sites." );
	}
	$s   = $config['sites'][ $site ];
	$url = rtrim( $s['url'], '/' ) . '/wp-json/sitebridge/v1' . $path;
	if ( ! empty( $query ) ) {
		$url .= '?' . http_build_query( $query );
	}

	try {
        $data = sbh_http( $url, $http_method, $body === null ? null : json_encode( $body ), sbh_site_headers( $s ), (int) ( $config['timeout'] ?? 30 ) );
        return array( 'ok' => true, 'data' => $data );
    } catch ( Throwable $e ) { return array( 'ok' => false, 'error' => $e->getMessage() ); }
}

/**
 * Wrap a proxy outcome as an MCP tool result (text content).
 */
function sbh_tool_result( $payload, $is_error = false ) {
	return array(
		'content' => array(
			array(
				'type' => 'text',
				'text' => is_string( $payload ) ? $payload : json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ),
			),
		),
		'isError' => (bool) $is_error,
	);
}

// ---------------------------------------------------------------------------
// Tool catalogue (schemas advertised to the client).
// ---------------------------------------------------------------------------

function sbh_site_prop() {
	return array( 'type' => 'string', 'description' => 'Short site name from the hub registry (see list_sites).' );
}

function sbh_tools() {
	$site = sbh_site_prop();
	return array(
        array( 'name' => 'connect_site', 'description' => 'Connect a WordPress site. Returns a temporary approval URL. Give that URL to the user; the user must open it in their own browser and approve the native WordPress Application Password screen as an administrator. Do not open or approve it on the user’s behalf. Never request passwords or API keys. After approval call connection_status.',
            'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site_url' => array( 'type' => 'string', 'description' => 'Final public HTTPS WordPress home URL.' ) ), 'required' => array( 'site_url' ) ) ),
        array( 'name' => 'connection_status', 'description' => 'Check a connection request after the user opens its approval link. Returns pending, connected, denied, failed, or expired.',
            'inputSchema' => array( 'type' => 'object', 'properties' => array( 'request_id' => array( 'type' => 'string' ) ), 'required' => array( 'request_id' ) ) ),
        array( 'name' => 'disconnect_site', 'description' => 'Remove this hub connection and attempt to revoke its native WordPress application password. Check wordpress_revoked; if false, revoke in WordPress Users > Profile. Legacy custom keys must also be revoked in WordPress Settings > SiteBridge.',
            'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => sbh_site_prop() ), 'required' => array( 'site' ) ) ),
		array(
			'name'        => 'list_sites',
			'description' => 'List the WordPress sites this hub can manage (their short names and URLs).',
			'inputSchema' => array( 'type' => 'object', 'properties' => new stdClass() ),
		),
		array(
			'name'        => 'site_info',
			'description' => "Get a site's name, WP/PHP versions, active theme, WooCommerce status and plugins.",
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site ), 'required' => array( 'site' ) ),
		),
		array(
			'name'        => 'list_content',
			'description' => 'List posts/pages on a site. Params: site, type (default post), search, per_page.',
			'inputSchema' => array(
				'type'       => 'object',
				'properties' => array( 'site' => $site, 'type' => array( 'type' => 'string' ), 'search' => array( 'type' => 'string' ), 'per_page' => array( 'type' => 'number' ) ),
				'required'   => array( 'site' ),
			),
		),
		array(
			'name'        => 'get_content',
			'description' => 'Get one post/page by ID on a site.',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'id' => array( 'type' => 'number' ) ), 'required' => array( 'site', 'id' ) ),
		),
		array(
			'name'        => 'create_content',
			'description' => 'Create a post/page on a site. Fields: site, title, content, excerpt, status, type. Requires content_write on the site.',
			'inputSchema' => array(
				'type'       => 'object',
				'properties' => array( 'site' => $site, 'title' => array( 'type' => 'string' ), 'content' => array( 'type' => 'string' ), 'excerpt' => array( 'type' => 'string' ), 'status' => array( 'type' => 'string' ), 'type' => array( 'type' => 'string' ) ),
				'required'   => array( 'site' ),
			),
		),
		array(
			'name'        => 'update_content',
			'description' => 'Update a post/page by ID on a site. Fields: site, id, title, content, excerpt, status.',
			'inputSchema' => array(
				'type'       => 'object',
				'properties' => array( 'site' => $site, 'id' => array( 'type' => 'number' ), 'title' => array( 'type' => 'string' ), 'content' => array( 'type' => 'string' ), 'excerpt' => array( 'type' => 'string' ), 'status' => array( 'type' => 'string' ) ),
				'required'   => array( 'site', 'id' ),
			),
		),
		array(
			'name'        => 'list_products',
			'description' => 'List WooCommerce products on a site. Params: site, search, per_page.',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'search' => array( 'type' => 'string' ), 'per_page' => array( 'type' => 'number' ) ), 'required' => array( 'site' ) ),
		),
		array(
			'name'        => 'get_product',
			'description' => 'Get one WooCommerce product by ID on a site.',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'id' => array( 'type' => 'number' ) ), 'required' => array( 'site', 'id' ) ),
		),
		array(
			'name'        => 'update_product',
			'description' => 'Update a WooCommerce product. Fields: site, id, name, regular_price, sale_price, stock_quantity, stock_status, status, short_description, description. Requires woo_write.',
			'inputSchema' => array(
				'type'       => 'object',
				'properties' => array(
					'site'              => $site,
					'id'                => array( 'type' => 'number' ),
					'name'              => array( 'type' => 'string' ),
					'regular_price'     => array( 'type' => 'string' ),
					'sale_price'        => array( 'type' => 'string' ),
					'stock_quantity'    => array( 'type' => 'number' ),
					'stock_status'      => array( 'type' => 'string' ),
					'status'            => array( 'type' => 'string' ),
					'short_description' => array( 'type' => 'string' ),
					'description'       => array( 'type' => 'string' ),
				),
				'required'   => array( 'site', 'id' ),
			),
		),
		array(
			'name'        => 'get_option',
			'description' => 'Read a WordPress option by name on a site (secrets blocked). Requires options_read.',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'name' => array( 'type' => 'string' ) ), 'required' => array( 'site', 'name' ) ),
		),
		array(
			'name'        => 'db_query',
			'description' => 'Run a READ-ONLY SQL query on a site (SELECT/SHOW/DESCRIBE/EXPLAIN only). Requires db_read.',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'sql' => array( 'type' => 'string' ) ), 'required' => array( 'site', 'sql' ) ),
		),
		array(
			'name'        => 'db_execute',
			'description' => 'DANGEROUS. Single UPDATE/INSERT/DELETE on a site (WHERE required; no DDL; confirm:true). Requires db_write.',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'sql' => array( 'type' => 'string' ), 'confirm' => array( 'type' => 'boolean' ) ), 'required' => array( 'site', 'sql', 'confirm' ) ),
		),
		array(
			'name'        => 'read_file',
			'description' => 'Read a text/code file inside wp-content on a site. Params: site, path. Requires code_edit.',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'path' => array( 'type' => 'string' ) ), 'required' => array( 'site', 'path' ) ),
		),
		array(
			'name'        => 'write_file',
			'description' => 'DANGEROUS. Write a text/code file inside wp-content on a site (auto-backup). Params: site, path, content. Requires code_edit.',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'path' => array( 'type' => 'string' ), 'content' => array( 'type' => 'string' ) ), 'required' => array( 'site', 'path', 'content' ) ),
		),
		array(
			'name'        => 'rest_api',
			'description' => 'Call any WordPress REST route on a site as the connected administrator: core (/wp/v2/...), Yoast, WooCommerce, forms, page builders and other plugins. GET / lists namespaces. Requires rest_proxy; writes also need content_write. Users, application passwords and SiteBridge routes are blocked; plugin/theme changes need code_edit and /wp/v2/settings writes need options_write.',
			'inputSchema' => array(
				'type'       => 'object',
				'properties' => array( 'site' => $site, 'method' => array( 'type' => 'string', 'enum' => array( 'GET', 'POST', 'PUT', 'PATCH', 'DELETE' ) ), 'route' => array( 'type' => 'string', 'description' => 'Route after /wp-json, e.g. /wp/v2/pages/12' ), 'query' => array( 'type' => 'object' ), 'body' => array( 'type' => 'object' ) ),
				'required'   => array( 'site', 'route' ),
			),
		),
		array(
			'name'        => 'discover_abilities',
			'description' => 'List WordPress Abilities (WordPress 6.9+) that plugins expose on a site, with input schemas. Optional search. Requires rest_proxy.',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'search' => array( 'type' => 'string' ) ), 'required' => array( 'site' ) ),
		),
		array(
			'name'        => 'run_ability',
			'description' => "Run a WordPress Ability by name with input matching its schema. The ability's own permission checks apply. Requires rest_proxy.",
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'name' => array( 'type' => 'string' ), 'input' => new stdClass() ), 'required' => array( 'site', 'name' ) ),
		),
		array(
			'name'        => 'get_post_meta',
			'description' => 'Read custom fields of a post/page: SEO fields (e.g. _yoast_wpseo_title, _yoast_wpseo_metadesc, rank_math_*), page-builder data and ACF values. Without key, lists all keys (large values summarized).',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'id' => array( 'type' => 'number' ), 'key' => array( 'type' => 'string' ) ), 'required' => array( 'site', 'id' ) ),
		),
		array(
			'name'        => 'update_post_meta',
			'description' => 'Set custom fields on a post/page through WordPress (hooks run, caches purged). meta is an object of key → value; null deletes a key. Requires content_write.',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'id' => array( 'type' => 'number' ), 'meta' => array( 'type' => 'object' ) ), 'required' => array( 'site', 'id', 'meta' ) ),
		),
		array(
			'name'        => 'upload_media',
			'description' => 'Add a file to the Media Library from a public URL (preferred) or base64 data (under ~700 KB). Optional filename, title, alt, caption and post_id to attach to. Requires content_write.',
			'inputSchema' => array(
				'type'       => 'object',
				'properties' => array( 'site' => $site, 'url' => array( 'type' => 'string' ), 'data' => array( 'type' => 'string' ), 'filename' => array( 'type' => 'string' ), 'title' => array( 'type' => 'string' ), 'alt' => array( 'type' => 'string' ), 'caption' => array( 'type' => 'string' ), 'post_id' => array( 'type' => 'number' ) ),
				'required'   => array( 'site' ),
			),
		),
		array(
			'name'        => 'get_custom_css',
			'description' => "Read the active theme's Customizer Additional CSS on a site.",
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site ), 'required' => array( 'site' ) ),
		),
		array(
			'name'        => 'update_custom_css',
			'description' => "Replace the active theme's Additional CSS (send the complete stylesheet; read it first). Caches are purged. Requires content_write.",
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'css' => array( 'type' => 'string' ) ), 'required' => array( 'site', 'css' ) ),
		),
		array(
			'name'        => 'update_option',
			'description' => 'DANGEROUS. Change a WordPress option (e.g. blogname, a plugin setting). Site URLs, roles, active plugins and secrets are blocked. Returns the previous value. Requires options_write.',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'name' => array( 'type' => 'string' ), 'value' => new stdClass() ), 'required' => array( 'site', 'name', 'value' ) ),
		),
		array(
			'name'        => 'purge_cache',
			'description' => 'Purge page caches (WP Rocket, LiteSpeed, W3TC, WP Super Cache, SiteGround, Autoptimize, WP Fastest Cache, Elementor CSS) and the object cache. Pass post_id to purge one page. Requires content_write.',
			'inputSchema' => array( 'type' => 'object', 'properties' => array( 'site' => $site, 'post_id' => array( 'type' => 'number' ) ), 'required' => array( 'site' ) ),
		),
	);
}

// ---------------------------------------------------------------------------
// Dispatch a tools/call to the right plugin endpoint.
// ---------------------------------------------------------------------------

function sbh_dispatch_tool( $config, $name, $args ) {
	$site = isset( $args['site'] ) ? preg_replace( '/[^a-zA-Z0-9_\-]/', '', $args['site'] ) : '';

	switch ( $name ) {
        case 'connect_site':
            sbh_rate( sbh_db( $config ), 'connect', 30 );
            return sbh_tool_result( sbh_pending( $config, $config['_identity']['owner'], $args['site_url'] ?? '', $config['_identity']['client_name'] ) );
        case 'connection_status':
            $row = sbh_get( sbh_db( $config ), 'pending', $args['request_id'] ?? '' );
            if ( ! $row || ! hash_equals( $row['owner'], $config['_identity']['owner'] ) ) { return sbh_tool_result( array( 'status' => 'expired' ) ); }
            return sbh_tool_result( array( 'status' => $row['status'], 'site' => $row['site'] ?? null ) );
        case 'disconnect_site':
            $db = sbh_db( $config );
            $row = sbh_get( $db, 'connection', $site );
            if ( ! $row || ! hash_equals( $row['owner'], $config['_identity']['owner'] ) ) { return sbh_tool_result( 'Unknown site connection.', true ); }
            $out = array( 'disconnected' => true );
            if ( ( $row['auth_type'] ?? '' ) === 'application_password' ) {
                $result = sbh_call_site( $config, $site, 'POST', '/connect/revoke' );
                $out['wordpress_revoked'] = $result['ok'] && ! empty( $result['data']['revoked'] );
                if ( ! $out['wordpress_revoked'] ) { $out['message'] = 'The hub connection was removed, but WordPress revocation could not be confirmed. Revoke the SiteBridge Application Password in WordPress Users > Profile if it is still listed.'; }
            }
            sbh_delete( $db, 'connection', $site );
            return sbh_tool_result( $out );
		case 'list_sites':
			$out = array();
			foreach ( $config['sites'] as $key => $s ) {
				$out[] = array( 'site' => $key, 'url' => $s['url'] );
			}
			return sbh_tool_result( array( 'sites' => $out ) );

		case 'site_info':
			$r = sbh_call_site( $config, $site, 'GET', '/site' );
			break;

		case 'list_content':
			$q = array_filter(
				array(
					'type'     => isset( $args['type'] ) ? $args['type'] : null,
					'search'   => isset( $args['search'] ) ? $args['search'] : null,
					'per_page' => isset( $args['per_page'] ) ? $args['per_page'] : null,
				),
				function ( $v ) {
					return null !== $v && '' !== $v;
				}
			);
			$r = sbh_call_site( $config, $site, 'GET', '/content', $q );
			break;

		case 'get_content':
			$r = sbh_call_site( $config, $site, 'GET', '/content/' . (int) $args['id'] );
			break;

		case 'create_content':
			$body = array_intersect_key( $args, array_flip( array( 'title', 'content', 'excerpt', 'status', 'type' ) ) );
			$r    = sbh_call_site( $config, $site, 'POST', '/content', array(), $body );
			break;

		case 'update_content':
			$body = array_intersect_key( $args, array_flip( array( 'title', 'content', 'excerpt', 'status' ) ) );
			$r    = sbh_call_site( $config, $site, 'PUT', '/content/' . (int) $args['id'], array(), $body );
			break;

		case 'list_products':
			$q = array_filter(
				array(
					'search'   => isset( $args['search'] ) ? $args['search'] : null,
					'per_page' => isset( $args['per_page'] ) ? $args['per_page'] : null,
				),
				function ( $v ) {
					return null !== $v && '' !== $v;
				}
			);
			$r = sbh_call_site( $config, $site, 'GET', '/products', $q );
			break;

		case 'get_product':
			$r = sbh_call_site( $config, $site, 'GET', '/products/' . (int) $args['id'] );
			break;

		case 'update_product':
			$body = array_intersect_key( $args, array_flip( array( 'name', 'regular_price', 'sale_price', 'stock_quantity', 'stock_status', 'status', 'short_description', 'description' ) ) );
			$r    = sbh_call_site( $config, $site, 'PUT', '/products/' . (int) $args['id'], array(), $body );
			break;

		case 'get_option':
			$r = sbh_call_site( $config, $site, 'GET', '/option/' . rawurlencode( $args['name'] ) );
			break;

		case 'db_query':
			$r = sbh_call_site( $config, $site, 'POST', '/db/query', array(), array( 'sql' => $args['sql'] ) );
			break;

		case 'db_execute':
			$r = sbh_call_site( $config, $site, 'POST', '/db/execute', array(), array( 'sql' => $args['sql'], 'confirm' => ! empty( $args['confirm'] ) ) );
			break;

		case 'read_file':
			$r = sbh_call_site( $config, $site, 'GET', '/file', array( 'path' => $args['path'] ) );
			break;

		case 'write_file':
			$r = sbh_call_site( $config, $site, 'PUT', '/file', array( 'path' => $args['path'] ), array( 'content' => $args['content'] ) );
			break;

		case 'rest_api':
			$body = array( 'method' => strtoupper( $args['method'] ?? 'GET' ), 'route' => (string) ( $args['route'] ?? '' ) );
			foreach ( array( 'query', 'body' ) as $k ) {
				if ( isset( $args[ $k ] ) && is_array( $args[ $k ] ) ) { $body[ $k ] = $args[ $k ]; }
			}
			$r = sbh_call_site( $config, $site, 'POST', '/rest', array(), $body );
			break;

		case 'discover_abilities':
			$r = sbh_call_site( $config, $site, 'GET', '/abilities', array_filter( array( 'search' => $args['search'] ?? null ) ) );
			break;

		case 'run_ability':
			$r = sbh_call_site( $config, $site, 'POST', '/abilities/run', array(), array( 'name' => (string) ( $args['name'] ?? '' ), 'input' => $args['input'] ?? null ) );
			break;

		case 'get_post_meta':
			$r = sbh_call_site( $config, $site, 'GET', '/meta/' . (int) $args['id'], array_filter( array( 'key' => $args['key'] ?? null ) ) );
			break;

		case 'update_post_meta':
			$r = sbh_call_site( $config, $site, 'PUT', '/meta/' . (int) $args['id'], array(), array( 'meta' => $args['meta'] ?? null ) );
			break;

		case 'upload_media':
			$body = array_intersect_key( $args, array_flip( array( 'url', 'data', 'filename', 'title', 'alt', 'caption', 'post_id' ) ) );
			$r    = sbh_call_site( $config, $site, 'POST', '/media', array(), $body );
			break;

		case 'get_custom_css':
			$r = sbh_call_site( $config, $site, 'GET', '/css' );
			break;

		case 'update_custom_css':
			$r = sbh_call_site( $config, $site, 'PUT', '/css', array(), array( 'css' => (string) ( $args['css'] ?? '' ) ) );
			break;

		case 'update_option':
			$r = sbh_call_site( $config, $site, 'PUT', '/option-write/' . rawurlencode( (string) ( $args['name'] ?? '' ) ), array(), array( 'value' => $args['value'] ?? null ) );
			break;

		case 'purge_cache':
			$r = sbh_call_site( $config, $site, 'POST', '/cache/purge', array(), array_filter( array( 'post_id' => isset( $args['post_id'] ) ? (int) $args['post_id'] : null ) ) );
			break;

		default:
			return sbh_tool_result( "Unknown tool: {$name}", true );
	}

	if ( empty( $r['ok'] ) ) {
		return sbh_tool_result( isset( $r['error'] ) ? $r['error'] : 'Request failed', true );
	}
	return sbh_tool_result( $r['data'] );
}

// ---------------------------------------------------------------------------
// JSON-RPC router
// ---------------------------------------------------------------------------

switch ( $method ) {

	case 'initialize':
		$requested_ver = $params['protocolVersion'] ?? '';
		$client_ver = in_array( $requested_ver, array( '2025-03-26', '2025-06-18', '2025-11-25' ), true ) ? $requested_ver : '2025-11-25';
		sbh_result(
			$id,
			array(
				'protocolVersion' => $client_ver,
				'capabilities'    => array( 'tools' => new stdClass() ),
				'serverInfo'      => array( 'name' => 'sitebridge-hub', 'version' => '0.6.1' ),
			)
		);
		break;

	case 'ping':
		sbh_result( $id, new stdClass() );
		break;

	case 'tools/list':
		sbh_result( $id, array( 'tools' => sbh_tools() ) );
		break;

	case 'tools/call':
		$name = isset( $params['name'] ) ? $params['name'] : '';
		$args = isset( $params['arguments'] ) && is_array( $params['arguments'] ) ? $params['arguments'] : array();
		try {
            $result = sbh_dispatch_tool( $config, $name, $args );
        } catch ( Throwable $e ) {
            $result = sbh_tool_result( $e instanceof RuntimeException ? $e->getMessage() : 'Invalid tool arguments or internal error.', true );
        }
        sbh_result( $id, $result );
		break;

	default:
		sbh_error( $id, -32601, "Method not found: {$method}" );
}
