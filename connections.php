<?php
/** Browser approvals and OAuth for the standalone PHP hub. */

function sbh_random() { return bin2hex( random_bytes( 32 ) ); }
function sbh_hash( $value ) { return hash( 'sha256', $value ); }
function sbh_json( $data, $status = 200 ) {
    http_response_code( $status );
    header( 'Content-Type: application/json' );
    echo json_encode( $data, JSON_UNESCAPED_SLASHES );
    exit;
}
function sbh_fail( $message, $status = 400 ) { throw new RuntimeException( $message, $status ); }
function sbh_body() {
    $body = file_get_contents( 'php://input', false, null, 0, 1048577 );
    if ( strlen( $body ) > 1048576 ) { sbh_fail( 'Request body exceeds 1 MB.', 413 ); }
    return $body;
}
function sbh_public_url( $url, $allow_path = true ) {
    $p = parse_url( $url );
    if ( preg_match( '/[\x00-\x20\x7f]/', $url ) || ! $p || ( $p['scheme'] ?? '' ) !== 'https' || empty( $p['host'] ) || isset( $p['user'] ) || isset( $p['pass'] ) || isset( $p['fragment'] ) || ( isset( $p['port'] ) && $p['port'] !== 443 ) ) {
        sbh_fail( 'Use a public HTTPS URL without credentials, fragments, or a custom port.' );
    }
    if ( ! $allow_path && isset( $p['query'] ) ) { sbh_fail( 'The site URL must not contain a query.' ); }
    return $p;
}
/** Safe transport diagnostics: never include credentials, response bodies or query strings. */
function sbh_transport_message( $errno, $size, $seconds, $status ) {
    if ( $size > 4 * 1024 * 1024 ) { $message = 'The remote response exceeded the 4 MB limit.'; }
    elseif ( $errno === CURLE_OPERATION_TIMEDOUT ) { $message = 'The remote request timed out after ' . round( $seconds, 1 ) . ' seconds.'; }
    elseif ( $errno === CURLE_COULDNT_CONNECT ) { $message = 'The hub could not establish a connection to the remote server.'; }
    elseif ( $errno === CURLE_COULDNT_RESOLVE_HOST ) { $message = 'The hub could not resolve the remote server hostname.'; }
    elseif ( in_array( $errno, array( CURLE_SSL_CONNECT_ERROR, CURLE_SSL_CACERT ), true ) ) { $message = 'The HTTPS connection or certificate verification failed.'; }
    elseif ( $errno === CURLE_GOT_NOTHING ) { $message = 'The remote server closed the connection without returning a response.'; }
    elseif ( in_array( $errno, array( CURLE_RECV_ERROR, CURLE_SEND_ERROR ), true ) ) { $message = 'The connection to the remote server was interrupted while transferring data.'; }
    else { $message = 'The remote request failed at the transport layer.'; }
    return $message . ' (cURL ' . (int) $errno . ', HTTP ' . (int) $status . ')';
}
/** Resolve and pin a public IPv4 address; never follow redirects or use proxy env vars. */
function sbh_http( $url, $method = 'GET', $body = null, $headers = array(), $timeout = 20 ) {
    $p = sbh_public_url( $url );
    $host = $p['host'];
    $ips = filter_var( $host, FILTER_VALIDATE_IP ) ? array( $host ) : gethostbynamel( $host );
    if ( ! $ips ) { sbh_fail( 'Could not resolve the remote host.', 502 ); }
    foreach ( $ips as $ip ) {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) || strpos( $ip, '169.254.' ) === 0 || ( ip2long( $ip ) >= ip2long( '100.64.0.0' ) && ip2long( $ip ) <= ip2long( '100.127.255.255' ) ) ) {
            sbh_fail( 'Private and reserved network destinations are not allowed.' );
        }
    }
    $ch = curl_init( $url );
    $size = 0;
    $response = '';
    curl_setopt_array( $ch, array(
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_USERAGENT => 'SiteBridge/0.6.0 (+https://github.com/cblabs1/sitebridge)',
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_PROXY => '',
        CURLOPT_RESOLVE => array( $host . ':443:' . $ips[0] ),
        CURLOPT_WRITEFUNCTION => function ( $ch, $chunk ) use ( &$response, &$size ) {
            $size += strlen( $chunk );
            if ( $size > 4 * 1024 * 1024 ) { return 0; }
            $response .= $chunk;
            return strlen( $chunk );
        },
    ) );
    if ( $body !== null ) { curl_setopt( $ch, CURLOPT_POSTFIELDS, $body ); }
    $ok = curl_exec( $ch );
    $status = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
    $errno = curl_errno( $ch );
    $elapsed = curl_getinfo( $ch, CURLINFO_TOTAL_TIME );
    $connect_time = curl_getinfo( $ch, CURLINFO_CONNECT_TIME );
    curl_close( $ch );
    if ( $ok === false ) {
        $reference = bin2hex( random_bytes( 6 ) );
        error_log( 'SiteBridge transport ' . json_encode( array( 'reference' => $reference, 'host' => $host, 'path' => $p['path'] ?? '/', 'method' => $method, 'curl_errno' => $errno, 'http_status' => $status, 'elapsed_seconds' => round( $elapsed, 3 ), 'connect_seconds' => round( $connect_time, 3 ), 'response_bytes' => $size ) ) );
        sbh_fail( sbh_transport_message( $errno, $size, $elapsed, $status ) . ' Reference: ' . $reference . '.', 502 );
    }
    if ( $status === 401 ) { sbh_fail( 'WordPress did not accept SiteBridge authentication (HTTP 401). Update the installed SiteBridge plugin to 0.5.4 or newer for hosting header compatibility, then start a fresh connection. If it persists, check Application Password availability and hosting authentication logs.', 502 ); }
    if ( $status >= 300 && $status < 400 ) { sbh_fail( 'Remote endpoint redirected (HTTP ' . $status . '). Use its final HTTPS URL.', 502 ); }
    if ( $status >= 400 && $status < 500 ) {
        // Surface only a WordPress REST error's code and short plain-text message, never
        // the raw body. A non-JSON refusal usually comes from a firewall/WAF.
        $remote = json_decode( $response, true );
        $code = is_array( $remote ) && is_string( $remote['code'] ?? null ) && preg_match( '/^[a-z0-9_\-]{1,64}$/i', $remote['code'] ) ? $remote['code'] : null;
        if ( ! $code && ( $status === 403 || $status === 406 ) ) {
            sbh_fail( 'The remote site refused the request (HTTP ' . $status . '). The response was not a WordPress REST error, which usually means a hosting firewall or security plugin blocked it. Check its hosting firewall logs.', 502 );
        }
        if ( $code ) {
            $message = is_string( $remote['message'] ?? null ) ? mb_substr( trim( preg_replace( '/\s+/', ' ', strip_tags( $remote['message'] ) ) ), 0, 300 ) : '';
            sbh_fail( 'WordPress returned HTTP ' . $status . ' (' . $code . ')' . ( $message !== '' ? ': ' . $message : '.' ), 502 );
        }
    }
    if ( $status < 200 || $status >= 300 ) { sbh_fail( 'Remote endpoint returned HTTP ' . $status . '. Check the installed plugin version and hosting logs.', 502 ); }
    $data = json_decode( $response, true );
    if ( ! is_array( $data ) ) { sbh_fail( 'The remote endpoint did not return JSON.', 502 ); }
    return $data;
}
function sbh_db( $config ) {
    static $db;
    if ( $db ) { return $db; }
    if ( ! preg_match( '/^[a-f0-9]{64}$/i', $config['encryption_key'] ?? '' ) ) { sbh_fail( 'Set encryption_key to a new 64-character hex secret.', 503 ); }
    $path = $config['storage_path'] ?? '';
    $parent = realpath( dirname( $path ) );
    $root = realpath( $_SERVER['DOCUMENT_ROOT'] ?? __DIR__ );
    if ( ! $parent || ! is_writable( $parent ) || ! $root || $parent === $root || strpos( $parent . '/', $root . '/' ) === 0 ) {
        sbh_fail( 'storage_path must be in an existing writable directory outside the public document root.', 503 );
    }
    if ( ! is_file( $path ) ) { $f = fopen( $path, 'x' ); if ( $f ) { fclose( $f ); chmod( $path, 0600 ); } }
    $db = new PDO( 'sqlite:' . $path, null, null, array( PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION ) );
    $db->exec( 'PRAGMA busy_timeout=5000' );
    $db->exec( 'CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(kind,id))' );
    $db->exec( 'CREATE INDEX IF NOT EXISTS expiry ON records(expires)' );
    $db->exec( 'DELETE FROM records WHERE expires > 0 AND expires < ' . time() );
    return $db;
}
function sbh_get( $db, $kind, $id ) {
    $q = $db->prepare( 'SELECT data FROM records WHERE kind=? AND id=? AND (expires=0 OR expires>=?)' );
    $q->execute( array( $kind, $id, time() ) );
    $data = $q->fetchColumn();
    return $data === false ? null : json_decode( $data, true );
}
function sbh_put( $db, $kind, $id, $data, $expires = 0 ) {
    $q = $db->prepare( 'INSERT OR REPLACE INTO records(kind,id,data,expires) VALUES(?,?,?,?)' );
    $q->execute( array( $kind, $id, json_encode( $data ), $expires ) );
}
function sbh_delete( $db, $kind, $id ) {
    $q = $db->prepare( 'DELETE FROM records WHERE kind=? AND id=?' );
    $q->execute( array( $kind, $id ) );
}
function sbh_encrypt( $config, $plain ) {
    $iv = random_bytes( 12 );
    $tag = '';
    $cipher = openssl_encrypt( $plain, 'aes-256-gcm', hex2bin( $config['encryption_key'] ), OPENSSL_RAW_DATA, $iv, $tag );
    if ( $cipher === false ) { sbh_fail( 'Credential encryption failed.', 500 ); }
    return base64_encode( $iv . $tag . $cipher );
}
function sbh_decrypt( $config, $value ) {
    $raw = base64_decode( $value, true );
    if ( $raw === false || strlen( $raw ) < 29 ) { sbh_fail( 'Invalid encrypted credential.', 500 ); }
    $plain = openssl_decrypt( substr( $raw, 28 ), 'aes-256-gcm', hex2bin( $config['encryption_key'] ), OPENSSL_RAW_DATA, substr( $raw, 0, 12 ), substr( $raw, 12, 16 ) );
    if ( $plain === false ) { sbh_fail( 'Credential decryption failed.', 500 ); }
    return $plain;
}
function sbh_base( $config ) {
    $base = rtrim( $config['public_url'] ?? '', '/' );
    $p = sbh_public_url( $base );
    if ( isset( $p['query'] ) || ! empty( $p['path'] ) ) { sbh_fail( 'public_url must be an HTTPS domain root; install the hub at the domain root.', 503 ); }
    return $base;
}
function sbh_rate( $db, $bucket, $limit ) {
    $id = sbh_hash( $bucket . '|' . ( $_SERVER['REMOTE_ADDR'] ?? '' ) . '|' . floor( time() / 600 ) );
    $db->exec( 'BEGIN IMMEDIATE' );
    try {
        $row = sbh_get( $db, 'rate', $id ) ?? array( 'count' => 0 );
        if ( $row['count'] >= $limit ) { sbh_fail( 'Too many requests. Try again in ten minutes.', 429 ); }
        $row['count']++;
        sbh_put( $db, 'rate', $id, $row, time() + 600 );
        $db->exec( 'COMMIT' );
    } catch ( Throwable $e ) { $db->exec( 'ROLLBACK' ); throw $e; }
}
function sbh_redirect_valid( $url ) {
    $p = parse_url( $url );
    if ( preg_match( '/[\x00-\x20\x7f]/', $url ) || ! $p || empty( $p['host'] ) || isset( $p['user'] ) || isset( $p['pass'] ) || isset( $p['fragment'] ) || strlen( $url ) > 2048 ) { return false; }
    return ( $p['scheme'] ?? '' ) === 'https' || ( ( $p['scheme'] ?? '' ) === 'http' && in_array( $p['host'], array( '127.0.0.1', '[::1]', 'localhost' ), true ) );
}
function sbh_client( $db, $id ) {
    if ( ! is_string( $id ) || strlen( $id ) > 2048 ) { sbh_fail( 'Invalid client identifier.' ); }
    $client = sbh_get( $db, 'client', $id );
    if ( ! $client && strpos( $id, 'https://' ) === 0 ) {
        $p = sbh_public_url( $id );
        if ( empty( $p['path'] ) || $p['path'] === '/' ) { sbh_fail( 'Client metadata URL must have a path.' ); }
        $client = sbh_http( $id );
        if ( ( $client['client_id'] ?? '' ) !== $id ) { sbh_fail( 'Client metadata identifier mismatch.' ); }
        sbh_validate_client( $client );
        sbh_put( $db, 'client', $id, $client, time() + 3600 );
    }
    if ( ! $client ) { sbh_fail( 'Unknown OAuth client.' ); }
    return $client;
}
function sbh_validate_client( $client ) {
    if ( empty( $client['client_name'] ) || ! is_string( $client['client_name'] ) || strlen( $client['client_name'] ) > 120 || empty( $client['redirect_uris'] ) || ! is_array( $client['redirect_uris'] ) || count( $client['redirect_uris'] ) > 10 ) { sbh_fail( 'Provide a client_name and 1–10 redirect_uris.' ); }
    foreach ( $client['redirect_uris'] as $uri ) { if ( ! is_string( $uri ) || ! sbh_redirect_valid( $uri ) ) { sbh_fail( 'Invalid redirect URI.' ); } }
    if ( ( $client['token_endpoint_auth_method'] ?? 'none' ) !== 'none' ) { sbh_fail( 'This server supports public PKCE clients only.' ); }
}
function sbh_pending( $config, $owner, $site_url, $client_name, $oauth = null ) {
    $db = sbh_db( $config );
    sbh_public_url( $site_url, false );
    $site_url = rtrim( $site_url, '/' );
    $id = sbh_random(); $secret = sbh_random();
    $row = array( 'owner' => $owner, 'site_url' => $site_url, 'client_name' => $client_name, 'secret_hash' => sbh_hash( $secret ), 'status' => 'pending', 'expires' => time() + 600, 'oauth' => $oauth );
    sbh_put( $db, 'pending', $id, $row, $row['expires'] );
    $url = sbh_base( $config ) . '/?' . http_build_query( array( 'route' => 'connect', 'request' => $id, 'secret' => $secret ), '', '&', PHP_QUERY_RFC3986 );
    return array( 'request_id' => $id, 'approval_url' => $url, 'expires_in' => 600, 'status' => 'pending', 'message' => 'Open approval_url, sign in as a WordPress administrator, and approve the native WordPress Application Password request. Only the user should approve; do not approve on their behalf. Then call connection_status with request_id.' );
}
function sbh_site_authorization( $site ) {
    if ( ( $site['auth_type'] ?? '' ) === 'application_password' ) {
        $credential = json_decode( $site['key'], true );
        if ( ! is_array( $credential ) || ! isset( $credential['username'], $credential['password'] ) ) { sbh_fail( 'Invalid stored WordPress credential.', 500 ); }
        return 'Authorization: Basic ' . base64_encode( $credential['username'] . ':' . $credential['password'] );
    }
    return 'Authorization: Bearer ' . $site['key'];
}
function sbh_site_headers( $site ) {
    $authorization = sbh_site_authorization( $site );
    $headers = array( $authorization, 'Content-Type: application/json', 'Accept: application/json' );
    if ( ( $site['auth_type'] ?? '' ) === 'application_password' ) {
        $headers[] = 'X-SiteBridge-Authorization: ' . substr( $authorization, strlen( 'Authorization: ' ) );
    }
    return $headers;
}
function sbh_connections( $config, $owner ) {
    $db = sbh_db( $config );
    $q = $db->query( "SELECT id,data FROM records WHERE kind='connection'" );
    $out = array();
    foreach ( $q as $row ) {
        $data = json_decode( $row['data'], true );
        if ( hash_equals( $data['owner'], $owner ) ) { $out[ $row['id'] ] = array( 'url' => $data['url'], 'key' => sbh_decrypt( $config, $data['key'] ), 'auth_type' => $data['auth_type'] ?? 'bearer' ); }
    }
    return $out;
}
function sbh_html( $title, $body, $step = 1, $navigate = null ) {
    header( 'Content-Type: text/html; charset=UTF-8' );
    header( "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" );
    header( 'Referrer-Policy: no-referrer' );
    header( 'X-Content-Type-Options: nosniff' );
    $refresh = $navigate === null ? '' : '<meta http-equiv="refresh" content="0;url=' . htmlspecialchars( $navigate, ENT_QUOTES, 'UTF-8' ) . '">';
    $css = file_get_contents( __DIR__ . '/connection-ui.css' );
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' . htmlspecialchars( $title ) . ' · SiteBridge</title>' . $refresh . '<style>' . $css . '</style></head><body class="sb-journey"><main class="sb-shell"><div class="sb-brand"><span class="sb-mark" aria-hidden="true">sb</span>SiteBridge</div>';
    if ( $step ) {
        echo '<ol class="sb-steps" aria-label="Connection progress">';
        foreach ( array( 1 => 'Connect', 2 => 'Approve', 3 => 'Ready' ) as $number => $label ) {
            echo '<li class="' . ( $number === $step ? 'is-current' : ( $number < $step ? 'is-complete' : '' ) ) . '"' . ( $number === $step ? ' aria-current="step"' : '' ) . '><span class="sb-step-number">' . $number . '</span>' . $label . '</li>';
        }
        echo '</ol>';
    }
    echo '<section class="sb-card" aria-labelledby="sb-title">' . $body . '</section><footer class="sb-footer">Your website. Your AI. Connected with SiteBridge.</footer></main></body></html>';
    exit;
}
function sbh_landing( $config ) {
    $url = sbh_base( $config ) . '/';
    sbh_html( 'Connect WordPress to your AI', '<p class="sb-eyebrow">WordPress, meet your AI</p><h1 id="sb-title">A little bridge.<br>A lot of possibilities.</h1><p class="sb-lead">Connect your WordPress website to an AI app you use. Manage content, work with products, and get things done through conversation.</p><label class="sb-label" for="sb-endpoint">Your MCP server URL</label><input class="sb-input" id="sb-endpoint" value="' . htmlspecialchars( $url, ENT_QUOTES, 'UTF-8' ) . '" readonly><p class="sb-hint">Paste this URL into your AI app’s remote MCP or connector settings and choose OAuth sign-in.</p><ul class="sb-features"><li>Connect from an AI app that supports remote MCP</li><li>Approve once in your own WordPress dashboard</li><li>Manage access from your SiteBridge settings</li></ul><a class="sb-button" href="https://github.com/cblabs1/sitebridge/blob/main/downloads/sitebridge-plugin_0.6.0.zip">Get the WordPress plugin <span aria-hidden="true">↗</span></a><p class="sb-help"><a href="https://github.com/cblabs1/sitebridge#connect-an-ai-client">Read the connection guide</a></p>', 0 );
}
function sbh_restart_action( $config ) {
    $id = $_POST['restart'] ?? $_GET['restart'] ?? '';
    if ( ! is_string( $id ) || ! preg_match( '/^[a-f0-9]{64}$/', $id ) ) { return ''; }
    try {
        if ( ! sbh_get( sbh_db( $config ), 'restart', $id ) ) { return ''; }
        $url = '/?route=authorize&restart=' . $id;
        return '<a class="sb-button" href="' . htmlspecialchars( $url, ENT_QUOTES, 'UTF-8' ) . '">Restart connection <span aria-hidden="true">→</span></a><p class="sb-note">The fresh form opens in this browser. Your website has not been connected by this step.</p>';
    } catch ( Throwable $e ) { return ''; }
}
function sbh_access_token( $db, $owner, $client_id, $resource, $family = null ) {
    $access = sbh_random(); $refresh = sbh_random(); $family = $family ?? sbh_random();
    $row = array( 'owner' => $owner, 'client_id' => $client_id, 'resource' => $resource, 'family' => $family );
    sbh_put( $db, 'access', sbh_hash( $access ), $row, time() + 3600 );
    sbh_put( $db, 'refresh', sbh_hash( $refresh ), $row, time() + 30 * 86400 );
    return array( 'access_token' => $access, 'refresh_token' => $refresh, 'token_type' => 'Bearer', 'expires_in' => 3600, 'scope' => 'sitebridge' );
}
/** WordPress's native approval callback is bound to the browser that opened the link. */
function sbh_native_claim( $db, $state, $cookie ) {
    if ( ! is_string( $state ) || ! preg_match( '/^[a-f0-9]{64}$/', $state ) ) { sbh_fail( 'Invalid approval session.', 403 ); }
    $db->exec( 'BEGIN IMMEDIATE' );
    try {
        $session = sbh_get( $db, 'native', sbh_hash( $state ) );
        if ( ! $session || ! hash_equals( $session['cookie_hash'], sbh_hash( $cookie ) ) ) { sbh_fail( 'Approval session expired or belongs to another browser. Start again in the same browser.', 403 ); }
        $row = sbh_get( $db, 'pending', $session['request'] );
        if ( ! $row || $row['status'] !== 'pending' || ! hash_equals( $row['native_hash'] ?? '', sbh_hash( $state ) ) ) { sbh_fail( 'This approval request expired or was already completed.', 409 ); }
        $row['status'] = 'processing';
        sbh_put( $db, 'pending', $session['request'], $row, $row['expires'] );
        sbh_delete( $db, 'native', sbh_hash( $state ) );
        $db->exec( 'COMMIT' );
        return array( $session, $row );
    } catch ( Throwable $error ) { $db->exec( 'ROLLBACK' ); throw $error; }
}
function sbh_oauth_return( $db, $config, $row ) {
    if ( empty( $row['oauth'] ) ) { return null; }
    $oauth = $row['oauth']; $base = sbh_base( $config );
    $params = array( 'state' => $oauth['state'], 'iss' => $base );
    if ( $row['status'] === 'connected' ) {
        $code = sbh_random();
        sbh_put( $db, 'code', sbh_hash( $code ), array( 'owner' => $row['owner'], 'client_id' => $oauth['client_id'], 'redirect_uri' => $oauth['redirect_uri'], 'challenge' => $oauth['challenge'], 'resource' => $base . '/' ), time() + 120 );
        $params['code'] = $code;
    } else { $params['error'] = 'access_denied'; }
    return $oauth['redirect_uri'] . ( strpos( $oauth['redirect_uri'], '?' ) === false ? '?' : '&' ) . http_build_query( $params, '', '&', PHP_QUERY_RFC3986 );
}
function sbh_native_routes( $config, $route, $db ) {
    $base = sbh_base( $config );
    if ( $route === 'connect' ) {
        $id = $_GET['request'] ?? '';
        $row = sbh_get( $db, 'pending', $id );
        if ( ! $row || $row['status'] !== 'pending' || ! hash_equals( $row['secret_hash'], sbh_hash( $_GET['secret'] ?? '' ) ) ) { sbh_fail( 'Connection link expired or was already completed. Ask your AI app for a fresh link.', 403 ); }
        try { $info = sbh_http( $row['site_url'] . '/wp-json/sitebridge/v1/connect/info' ); }
        catch ( RuntimeException $error ) {
            if ( strpos( $error->getMessage(), 'HTTP 404' ) !== false ) { sbh_fail( 'Update the WordPress SiteBridge plugin to 0.5.0 or newer, then request a fresh connection link.', 409 ); }
            throw $error;
        }
        $app_id = '6c78a910-07e3-4a44-a3fa-299b20b471c5';
        if ( ( $info['app_id'] ?? '' ) !== $app_id || empty( $info['available'] ) || rtrim( $info['site_url'] ?? '', '/' ) !== $row['site_url'] ) { sbh_fail( 'Install SiteBridge 0.5.0 or newer and enable WordPress Application Passwords on this website.', 409 ); }
        $authorization = $info['authorization_url'] ?? '';
        sbh_public_url( $authorization );
        if ( $authorization !== $row['site_url'] . '/wp-admin/authorize-application.php' ) { sbh_fail( 'WordPress returned an unexpected authorization address.', 502 ); }
        $state = sbh_random(); $csrf = sbh_random(); $cookie_name = 'sbh_native_' . substr( $id, 0, 16 );
        $db->exec( 'BEGIN IMMEDIATE' );
        try {
            $row = sbh_get( $db, 'pending', $id );
            if ( ! $row || $row['status'] !== 'pending' ) { sbh_fail( 'Connection already processed.', 409 ); }
            if ( isset( $row['native_hash'] ) ) { sbh_delete( $db, 'native', $row['native_hash'] ); }
            $row['native_hash'] = sbh_hash( $state );
            sbh_put( $db, 'pending', $id, $row, $row['expires'] );
            sbh_put( $db, 'native', sbh_hash( $state ), array( 'request' => $id, 'cookie_name' => $cookie_name, 'cookie_hash' => sbh_hash( $csrf ) ), $row['expires'] );
            $db->exec( 'COMMIT' );
        } catch ( Throwable $error ) { $db->exec( 'ROLLBACK' ); throw $error; }
        setcookie( $cookie_name, $csrf, array( 'expires' => $row['expires'], 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax' ) );
        $callback = $base . '/?route=native-return&state=' . $state;
        $url = $authorization . '?' . http_build_query( array( 'app_name' => 'SiteBridge — ' . $row['client_name'] . ' — ' . substr( $id, 0, 8 ), 'app_id' => $app_id, 'success_url' => $callback, 'reject_url' => $callback . '&denied=1' ), '', '&', PHP_QUERY_RFC3986 );
        header( 'Referrer-Policy: no-referrer' ); header( 'Location: ' . $url, true, 303 ); exit;
    }
    if ( $route === 'native-return' ) {
        // Always leave the credential-bearing callback URL before rendering a document.
        $ticket = sbh_random(); $result = array( 'status' => 'failed', 'message' => 'This approval session expired. Start a new connection from your AI app.' );
        $session = null; $row = null; $connection_data = null;
        try {
            $state = $_GET['state'] ?? '';
            $saved = is_string( $state ) ? sbh_get( $db, 'native', sbh_hash( $state ) ) : null;
            $cookie = $saved ? ( $_COOKIE[ $saved['cookie_name'] ] ?? '' ) : '';
            list( $session, $row ) = sbh_native_claim( $db, $state, $cookie );
            if ( isset( $_GET['denied'] ) || ( $_GET['success'] ?? '' ) === 'false' ) { $row['status'] = 'denied'; }
            else {
                $username = $_GET['user_login'] ?? ''; $password = $_GET['password'] ?? '';
                if ( ! is_string( $username ) || $username === '' || strlen( $username ) > 240 || preg_match( '/[:\x00-\x1f\x7f]/', $username ) || ! is_string( $password ) || ! preg_match( '/^[a-zA-Z0-9]{24}$/', str_replace( ' ', '', $password ) ) || rtrim( $_GET['site_url'] ?? '', '/' ) !== $row['site_url'] ) { sbh_fail( 'WordPress returned an invalid credential or a different website.', 403 ); }
                $credential = json_encode( array( 'username' => $username, 'password' => $password ) );
                $verified = sbh_http( $row['site_url'] . '/wp-json/sitebridge/v1/connect/verify', 'GET', null, sbh_site_headers( array( 'auth_type' => 'application_password', 'key' => $credential ) ) );
                if ( ( $verified['app_id'] ?? '' ) !== '6c78a910-07e3-4a44-a3fa-299b20b471c5' || empty( $verified['uuid'] ) || rtrim( $verified['site_url'] ?? '', '/' ) !== $row['site_url'] || ! in_array( 'site_read', $verified['capabilities'] ?? array(), true ) ) { sbh_fail( 'WordPress could not verify SiteBridge access. Check the plugin settings and approve with an administrator account.', 403 ); }
                $connection = 'site_' . substr( sbh_hash( $row['owner'] . '|' . $row['site_url'] ), 0, 24 );
                $connection_data = array( 'owner' => $row['owner'], 'url' => $row['site_url'], 'auth_type' => 'application_password', 'key' => sbh_encrypt( $config, $credential ), 'uuid' => $verified['uuid'] );
                $row['status'] = 'connected'; $row['site'] = $connection;
            }
            $db->exec( 'BEGIN IMMEDIATE' );
            try {
                if ( $connection_data ) { sbh_put( $db, 'connection', $connection, $connection_data ); }
                $result = array( 'status' => $row['status'], 'return_url' => sbh_oauth_return( $db, $config, $row ), 'cookie_name' => $session['cookie_name'], 'cookie_hash' => $session['cookie_hash'] );
                unset( $row['oauth'] );
                sbh_put( $db, 'pending', $session['request'], $row, $row['expires'] );
                sbh_put( $db, 'native-result', sbh_hash( $ticket ), $result, time() + 120 );
                $db->exec( 'COMMIT' );
            } catch ( Throwable $error ) { $db->exec( 'ROLLBACK' ); throw $error; }

        } catch ( Throwable $error ) {
            $result = array( 'status' => 'failed' );
            $result['message'] = $error instanceof RuntimeException ? $error->getMessage() : 'Connection verification failed. Start again from your AI app.';
            if ( $session ) { $result['cookie_name'] = $session['cookie_name']; $result['cookie_hash'] = $session['cookie_hash']; }
            if ( $row ) { $row['status'] = 'failed'; }
        }
        if ( $row && $session ) { unset( $row['oauth'] ); sbh_put( $db, 'pending', $session['request'], $row, $row['expires'] ); }
        sbh_put( $db, 'native-result', sbh_hash( $ticket ), $result, time() + 120 );
        header( 'Referrer-Policy: no-referrer' ); header( 'Location: ' . $base . '/?route=connected&ticket=' . $ticket, true, 303 ); exit;
    }
    if ( $route === 'connected' ) {
        $result = sbh_get( $db, 'native-result', sbh_hash( $_GET['ticket'] ?? '' ) );
        if ( ! $result || ( isset( $result['cookie_hash'] ) && ! hash_equals( $result['cookie_hash'], sbh_hash( $_COOKIE[ $result['cookie_name'] ] ?? '' ) ) ) ) { sbh_fail( 'Connection result expired or belongs to another browser.', 403 ); }
        $connected = $result['status'] === 'connected';
        $title = $connected ? 'You’re connected' : ( $result['status'] === 'denied' ? 'Connection canceled' : 'Connection needs attention' );
        $body = '<div class="sb-outcome"><p class="sb-eyebrow">' . ( $connected ? 'Ready when you are' : 'Let’s try again' ) . '</p><h1 id="sb-title">' . $title . '</h1><p class="sb-lead">' . htmlspecialchars( $result['message'] ?? ( $connected ? 'Your WordPress website is connected. Return to your AI app to start working.' : 'No connection was approved. Start again from your AI app when you’re ready.' ), ENT_QUOTES, 'UTF-8' ) . '</p>';
        $return = $result['return_url'] ?? null;
        if ( $return ) { $body .= '<a class="sb-button" href="' . htmlspecialchars( $return, ENT_QUOTES, 'UTF-8' ) . '">Return to your AI app →</a>'; }
        sbh_html( $title, $body . '</div>', $connected ? 3 : 2, $return );
    }
}

/** Handle public OAuth/browser endpoints before the MCP bearer gate. */
function sbh_browser_routes( $config ) {
    $path = parse_url( $_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH );
    $route = $_GET['route'] ?? '';
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $base = ! empty( $config['public_url'] ) ? sbh_base( $config ) : null;
    if ( strpos( $path, '/.well-known/oauth-protected-resource' ) === 0 ) {
        if ( ! $base ) { sbh_fail( 'Configure public_url first.', 503 ); }
        sbh_json( array( 'resource' => $base . '/', 'authorization_servers' => array( $base ), 'scopes_supported' => array( 'sitebridge' ), 'bearer_methods_supported' => array( 'header' ) ) );
    }
    if ( $path === '/.well-known/oauth-authorization-server' ) {
        if ( ! $base ) { sbh_fail( 'Configure public_url first.', 503 ); }
        sbh_json( array( 'issuer' => $base, 'authorization_endpoint' => $base . '/?route=authorize', 'token_endpoint' => $base . '/?route=token', 'registration_endpoint' => $base . '/?route=register', 'revocation_endpoint' => $base . '/?route=revoke', 'response_types_supported' => array( 'code' ), 'grant_types_supported' => array( 'authorization_code', 'refresh_token' ), 'code_challenge_methods_supported' => array( 'S256' ), 'token_endpoint_auth_methods_supported' => array( 'none' ), 'scopes_supported' => array( 'sitebridge' ), 'client_id_metadata_document_supported' => true, 'authorization_response_iss_parameter_supported' => true ) );
    }
    if ( ! in_array( $route, array( 'authorize', 'register', 'token', 'request', 'callback', 'revoke', 'connect', 'native-return', 'connected' ), true ) ) { return; }
    if ( ! $base ) { sbh_fail( 'Configure public_url first.', 503 ); }
    $db = sbh_db( $config );
    if ( in_array( $route, array( 'register', 'token', 'callback', 'revoke' ), true ) && $method !== 'POST' ) { sbh_fail( 'POST required.', 405 ); }
    if ( ! in_array( $method, array( 'GET', 'POST' ), true ) ) { sbh_fail( 'Method not allowed.', 405 ); }
    sbh_rate( $db, $route, $route === 'register' ? 30 : 120 );
    if ( in_array( $route, array( 'connect', 'native-return', 'connected' ), true ) ) {
        if ( $method !== 'GET' ) { sbh_fail( 'GET required.', 405 ); }
        sbh_native_routes( $config, $route, $db );
    }
    if ( $route === 'register' ) {
        $input = json_decode( sbh_body(), true );
        if ( ! is_array( $input ) ) { sbh_fail( 'Expected JSON client metadata.' ); }
        sbh_validate_client( $input );
        $client = array( 'client_id' => sbh_random(), 'client_name' => $input['client_name'], 'redirect_uris' => $input['redirect_uris'], 'token_endpoint_auth_method' => 'none', 'grant_types' => array( 'authorization_code', 'refresh_token' ), 'response_types' => array( 'code' ) );
        sbh_put( $db, 'client', $client['client_id'], $client, time() + 365 * 86400 );
        sbh_json( $client, 201 );
    }
    if ( $route === 'authorize' ) {
        if ( $method === 'GET' ) {
            // Restart only from server-validated OAuth context; never trust a return URL in a POST.
            if ( isset( $_GET['restart'] ) ) {
                $restart = is_string( $_GET['restart'] ) ? $_GET['restart'] : '';
                $saved = preg_match( '/^[a-f0-9]{64}$/', $restart ) ? sbh_get( $db, 'restart', $restart ) : null;
                if ( ! $saved ) { sbh_fail( 'This connection session expired. Start a fresh connection from your AI app.', 403 ); }
                $_GET = array_merge( $_GET, $saved );
            }
            $client_id = $_GET['client_id'] ?? '';
            $client = sbh_client( $db, $client_id );
            $redirect = $_GET['redirect_uri'] ?? '';
            if ( ! in_array( $redirect, $client['redirect_uris'], true ) ) { sbh_fail( 'Redirect URI was not registered.' ); }
            if ( ( $_GET['response_type'] ?? '' ) !== 'code' || ( $_GET['code_challenge_method'] ?? '' ) !== 'S256' || ! preg_match( '/^[a-zA-Z0-9_-]{43}$/', $_GET['code_challenge'] ?? '' ) ) { sbh_fail( 'Authorization code flow with S256 PKCE is required.' ); }
            if ( ! in_array( $_GET['resource'] ?? $base . '/', array( $base, $base . '/' ), true ) ) { sbh_fail( 'Invalid resource audience.' ); }
            if ( ! in_array( $_GET['scope'] ?? 'sitebridge', array( '', 'sitebridge' ), true ) ) { sbh_fail( 'Unsupported scope.' ); }
            $flow = sbh_random(); $csrf = sbh_random();
            $oauth = array( 'client_id' => $client_id, 'client_name' => $client['client_name'], 'redirect_uri' => $redirect, 'challenge' => $_GET['code_challenge'], 'state' => substr( $_GET['state'] ?? '', 0, 2048 ), 'resource' => $base . '/', 'csrf' => sbh_hash( $csrf ), 'expires' => time() + 600 );
            sbh_put( $db, 'flow', $flow, $oauth, time() + 600 );
            $restart = sbh_random();
            $context = array( 'client_id' => $client_id, 'redirect_uri' => $redirect, 'response_type' => 'code', 'code_challenge_method' => 'S256', 'code_challenge' => $oauth['challenge'], 'state' => $oauth['state'], 'resource' => $base . '/', 'scope' => 'sitebridge' );
            sbh_put( $db, 'restart', $restart, $context, time() + 1800 );
            setcookie( 'sbh_flow_' . substr( $flow, 0, 16 ), $csrf, array( 'expires' => time() + 600, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax' ) );
            sbh_html( 'Connect WordPress', '<p class="sb-eyebrow">Let’s get connected</p><h1 id="sb-title">Your website.<br>Your AI assistant.</h1><p class="sb-lead">Connect your WordPress website to <span class="sb-client">' . htmlspecialchars( $client['client_name'], ENT_QUOTES, 'UTF-8' ) . '</span> through SiteBridge.</p><form method="post" action="/?route=authorize"><input type="hidden" name="flow" value="' . $flow . '"><input type="hidden" name="restart" value="' . $restart . '"><label class="sb-label" for="sb-site-url">WordPress website URL</label><input class="sb-input" id="sb-site-url" name="site_url" type="url" placeholder="https://yourwebsite.com" autocomplete="url" required><p class="sb-hint">Enter the website where you’ve installed the SiteBridge plugin.</p><button class="sb-button">Continue to WordPress <span aria-hidden="true">→</span></button></form><div class="sb-summary"><p>You’ll sign in to WordPress and approve the connection. Access is managed in your SiteBridge settings.</p></div><p class="sb-note">Each AI client authorization keeps its own connections.</p>' );
        }
        $flow = $_POST['flow'] ?? '';
        $oauth = sbh_get( $db, 'flow', $flow );
        $cookie = $_COOKIE[ 'sbh_flow_' . substr( $flow, 0, 16 ) ] ?? '';
        if ( ! $oauth ) { sbh_fail( 'This form expired or was already submitted. Restart below to open a fresh form.', 403 ); }
        if ( ! hash_equals( $oauth['csrf'], sbh_hash( $cookie ) ) ) { sbh_fail( 'Your browser session could not be verified. Restart below in the same browser, with cookies enabled.', 403 ); }
        $site_url = rtrim( trim( $_POST['site_url'] ?? '' ), '/' );
        // Serialize retries so a double click cannot create two approval requests.
        $db->exec( 'BEGIN IMMEDIATE' );
        try {
            $oauth = sbh_get( $db, 'flow', $flow );
            if ( ! $oauth ) { sbh_fail( 'This form expired. Restart to open a fresh form.', 403 ); }
            if ( isset( $oauth['approval'] ) ) {
                if ( $site_url !== $oauth['site_url'] ) { sbh_fail( 'This form already started a connection for another website. Restart to change websites.', 409 ); }
                $request = sbh_get( $db, 'pending', $oauth['request_id'] );
                if ( ! $request || $request['status'] !== 'pending' ) { sbh_fail( 'This approval request has finished or expired. Return to your AI app or restart the connection.', 409 ); }
                $approval_url = sbh_decrypt( $config, $oauth['approval'] );
            } else {
                $pending = sbh_pending( $config, sbh_random(), $site_url, $oauth['client_name'], $oauth );
                $approval_url = $pending['approval_url'];
                $oauth['site_url'] = $site_url;
                $oauth['request_id'] = $pending['request_id'];
                $oauth['approval'] = sbh_encrypt( $config, $approval_url );
                sbh_put( $db, 'flow', $flow, $oauth, $oauth['expires'] ?? time() + 600 );
            }
            $db->exec( 'COMMIT' );
        } catch ( Throwable $error ) {
            $db->exec( 'ROLLBACK' );
            throw $error;
        }
        // A new document navigates independently of Chrome's form-action redirect check.
        // Keep an ordinary link available if automatic navigation is disabled.
        sbh_html( 'Continue to WordPress', '<p class="sb-eyebrow">One more step</p><h1 id="sb-title">Opening WordPress…</h1><p class="sb-lead">Sign in to your website and approve the connection.</p><a class="sb-button" href="' . htmlspecialchars( $approval_url, ENT_QUOTES, 'UTF-8' ) . '">Continue to WordPress <span aria-hidden="true">→</span></a><p class="sb-note">If WordPress doesn’t open automatically, use the button above.</p>', 2, $approval_url );
    }
    if ( $route === 'request' || $route === 'callback' ) {
        $in = $route === 'request' ? $_GET : json_decode( sbh_body(), true );
        $id = $in['request'] ?? '';
        $row = sbh_get( $db, 'pending', $id );
        if ( ! $row || ! hash_equals( $row['secret_hash'], sbh_hash( $in['secret'] ?? '' ) ) || $row['status'] !== 'pending' ) { sbh_fail( 'Connection request expired, completed, or invalid.', 403 ); }
        if ( $route === 'request' ) {
            sbh_json( array( 'request' => $id, 'site_url' => $row['site_url'], 'hub_url' => $base, 'client_name' => $row['client_name'], 'expires' => $row['expires'] ) );
        }
        // Claim before exchanging the one-time code; concurrent callbacks cannot consume it twice.
        $db->exec( 'BEGIN IMMEDIATE' );
        try {
            $fresh = sbh_get( $db, 'pending', $id );
            if ( ! $fresh || $fresh['status'] !== 'pending' ) { sbh_fail( 'Request already processed.', 409 ); }
            $row['status'] = 'processing'; sbh_put( $db, 'pending', $id, $row, $row['expires'] );
            $db->exec( 'COMMIT' );
        } catch ( Throwable $e ) { $db->exec( 'ROLLBACK' ); throw $e; }
        try {
            if ( ( $in['decision'] ?? '' ) === 'deny' ) {
                $row['status'] = 'denied';
            } else {
                if ( ! preg_match( '/^[a-f0-9]{64}$/', $in['code'] ?? '' ) ) { sbh_fail( 'Invalid exchange code.' ); }
                $exchange = sbh_http( $row['site_url'] . '/wp-json/sitebridge/v1/connect/exchange', 'POST', json_encode( array( 'code' => $in['code'], 'request' => $id ) ), array( 'Content-Type: application/json' ) );
                if ( ! preg_match( '/^sbk_[a-f0-9]{48}$/', $exchange['key'] ?? '' ) || rtrim( $exchange['site_url'] ?? '', '/' ) !== $row['site_url'] ) { sbh_fail( 'WordPress credential exchange did not match the approved site.', 502 ); }
                $connection = 'site_' . substr( sbh_hash( $row['owner'] . '|' . $row['site_url'] ), 0, 24 );
                sbh_put( $db, 'connection', $connection, array( 'owner' => $row['owner'], 'url' => $row['site_url'], 'key' => sbh_encrypt( $config, $exchange['key'] ), 'capabilities' => $exchange['capabilities'] ?? array() ) );
                $row['status'] = 'connected'; $row['site'] = $connection;
            }
            $out = array( 'status' => $row['status'] );
            if ( $row['oauth'] ) {
                $oauth = $row['oauth'];
                $params = array( 'state' => $oauth['state'], 'iss' => $base );
                if ( $row['status'] === 'connected' ) {
                    $code = sbh_random();
                    sbh_put( $db, 'code', sbh_hash( $code ), array( 'owner' => $row['owner'], 'client_id' => $oauth['client_id'], 'redirect_uri' => $oauth['redirect_uri'], 'challenge' => $oauth['challenge'], 'resource' => $base . '/' ), time() + 120 );
                    $params['code'] = $code;
                } else { $params['error'] = 'access_denied'; }
                $out['return_url'] = $oauth['redirect_uri'] . ( strpos( $oauth['redirect_uri'], '?' ) === false ? '?' : '&' ) . http_build_query( $params, '', '&', PHP_QUERY_RFC3986 );
            }
            unset( $row['oauth'] );
            sbh_put( $db, 'pending', $id, $row, $row['expires'] );
            sbh_json( $out );
        } catch ( Throwable $e ) {
            $row['status'] = 'failed'; unset( $row['oauth'] ); sbh_put( $db, 'pending', $id, $row, $row['expires'] ); throw $e;
        }
    }
    if ( $route === 'token' ) {
        $client_id = $_POST['client_id'] ?? '';
        sbh_client( $db, $client_id );
        $grant = $_POST['grant_type'] ?? '';
        $kind = $grant === 'authorization_code' ? 'code' : ( $grant === 'refresh_token' ? 'refresh' : '' );
        if ( ! $kind ) { sbh_json( array( 'error' => 'unsupported_grant_type' ), 400 ); }
        $secret = $kind === 'code' ? ( $_POST['code'] ?? '' ) : ( $_POST['refresh_token'] ?? '' );
        $db->exec( 'BEGIN IMMEDIATE' );
        try {
            $row = sbh_get( $db, $kind, sbh_hash( $secret ) );
            $valid = $row && hash_equals( $row['client_id'], $client_id ) && ! sbh_get( $db, 'revoked', $row['family'] ?? '-' );
            if ( $valid && isset( $_POST['resource'] ) ) { $valid = in_array( $_POST['resource'], array( $base, $base . '/' ), true ); }
            if ( $valid && $kind === 'code' ) {
                $verifier = $_POST['code_verifier'] ?? '';
                $challenge = rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );
                $valid = preg_match( '/^[a-zA-Z0-9._~-]{43,128}$/', $verifier ) && hash_equals( $row['challenge'], $challenge ) && ( $_POST['redirect_uri'] ?? '' ) === $row['redirect_uri'];
            }
            if ( ! $valid ) {
                if ( $kind === 'refresh' ) {
                    $used = sbh_get( $db, 'used_refresh', sbh_hash( $secret ) );
                    if ( $used && hash_equals( $used['client_id'], $client_id ) ) { sbh_put( $db, 'revoked', $used['family'], array( 'revoked' => true ), time() + 31 * 86400 ); }
                }
                $db->exec( 'COMMIT' ); sbh_json( array( 'error' => 'invalid_grant' ), 400 );
            }
            sbh_delete( $db, $kind, sbh_hash( $secret ) );
            if ( $kind === 'refresh' ) { sbh_put( $db, 'used_refresh', sbh_hash( $secret ), $row, time() + 31 * 86400 ); }
            $tokens = sbh_access_token( $db, $row['owner'], $client_id, $base . '/', $kind === 'refresh' ? $row['family'] : null );
            $db->exec( 'COMMIT' ); sbh_json( $tokens );
        } catch ( Throwable $e ) { $db->exec( 'ROLLBACK' ); throw $e; }
    }
    if ( $route === 'revoke' ) {
        $client_id = $_POST['client_id'] ?? '';
        foreach ( array( 'access', 'refresh' ) as $kind ) {
            $row = sbh_get( $db, $kind, sbh_hash( $_POST['token'] ?? '' ) );
            if ( $row && hash_equals( $row['client_id'], $client_id ) ) {
                sbh_put( $db, 'revoked', $row['family'], array( 'revoked' => true ), time() + 31 * 86400 );
                sbh_delete( $db, $kind, sbh_hash( $_POST['token'] ) );
            }
        }
        sbh_json( new stdClass() );
    }
}
function sbh_identity( $config, $token ) {
    // Keep manual configurations working without exposing dynamic users' sites to this token.
    $master = $config['master_token'] ?? '';
    if ( is_string( $master ) && $master !== '' && strpos( $master, 'CHANGE-ME' ) !== 0 && hash_equals( $master, $token ) ) { return array( 'owner' => 'legacy-admin', 'client_name' => 'SiteBridge administrator' ); }
    if ( empty( $config['public_url'] ) ) { return null; }
    $db = sbh_db( $config );
    $row = sbh_get( $db, 'access', sbh_hash( $token ) );
    if ( ! $row || $row['resource'] !== sbh_base( $config ) . '/' || sbh_get( $db, 'revoked', $row['family'] ) ) { return null; }
    $client = sbh_get( $db, 'client', $row['client_id'] );
    return array( 'owner' => $row['owner'], 'client_name' => $client['client_name'] ?? 'MCP client' );
}
