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

// Only POST carries JSON-RPC. A GET is handy as a health check.
$method_http = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ( 'GET' === $method_http ) {
	echo json_encode( array( 'ok' => true, 'service' => 'sitebridge-hub', 'transport' => 'mcp/http' ) );
	exit;
}
if ( 'POST' !== $method_http ) {
	http_response_code( 405 );
	echo json_encode( array( 'error' => 'Method not allowed' ) );
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

$raw  = file_get_contents( 'php://input' );
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
if ( ! is_string( $config['master_token'] ) || '' === $config['master_token'] || ! hash_equals( (string) $config['master_token'], (string) $token ) ) {
	sbh_error( $id, -32001, 'Unauthorized: invalid master token.', 401 );
}

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

	$ch = curl_init( $url );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_CUSTOMREQUEST  => $http_method,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_TIMEOUT        => isset( $config['timeout'] ) ? (int) $config['timeout'] : 30,
			CURLOPT_HTTPHEADER     => array(
				'Authorization: Bearer ' . $s['key'],
				'Content-Type: application/json',
				'Accept: application/json',
			),
		)
	);
	if ( null !== $body ) {
		curl_setopt( $ch, CURLOPT_POSTFIELDS, json_encode( $body ) );
	}
	$resp = curl_exec( $ch );
	if ( false === $resp ) {
		$err = curl_error( $ch );
		curl_close( $ch );
		return array( 'ok' => false, 'error' => 'Request to site failed: ' . $err );
	}
	$code = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );

	$data = json_decode( $resp, true );
	if ( $code >= 400 ) {
		$m = is_array( $data ) && isset( $data['message'] ) ? $data['message'] : ( 'HTTP ' . $code );
		return array( 'ok' => false, 'error' => $m, 'status' => $code );
	}
	return array( 'ok' => true, 'data' => null === $data ? $resp : $data );
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
	);
}

// ---------------------------------------------------------------------------
// Dispatch a tools/call to the right plugin endpoint.
// ---------------------------------------------------------------------------

function sbh_dispatch_tool( $config, $name, $args ) {
	$site = isset( $args['site'] ) ? preg_replace( '/[^a-zA-Z0-9_\-]/', '', $args['site'] ) : '';

	switch ( $name ) {
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
		$client_ver = isset( $params['protocolVersion'] ) ? $params['protocolVersion'] : '2025-06-18';
		sbh_result(
			$id,
			array(
				'protocolVersion' => $client_ver,
				'capabilities'    => array( 'tools' => new stdClass() ),
				'serverInfo'      => array( 'name' => 'sitebridge-hub', 'version' => '0.1.0' ),
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
		sbh_result( $id, sbh_dispatch_tool( $config, $name, $args ) );
		break;

	default:
		sbh_error( $id, -32601, "Method not found: {$method}" );
}
