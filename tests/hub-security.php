<?php
$hub = is_dir( __DIR__ . '/../sitebridge-hub' ) ? __DIR__ . '/../sitebridge-hub' : dirname( __DIR__ );
require $hub . '/connections.php';
function check( $condition, $message ) { if ( ! $condition ) { throw new Exception( $message ); } echo "PASS $message\n"; }
function rejects( $fn, $message ) { try { $fn(); } catch ( RuntimeException $e ) { check( true, $message ); return; } throw new Exception( $message ); }
$dir = sys_get_temp_dir() . '/sbh-test-' . bin2hex( random_bytes( 8 ) );
mkdir( $dir, 0700 );
$_SERVER['DOCUMENT_ROOT'] = $hub;
$config = array( 'public_url' => 'https://hub.example.com', 'encryption_key' => sbh_random(), 'storage_path' => $dir . '/connections.sqlite', 'master_token' => 'private-admin' );
try {
    rejects( function () use ( $config ) { $bad = $config; $bad['storage_path'] = $_SERVER['DOCUMENT_ROOT'] . '/test.sqlite'; sbh_db( $bad ); }, 'storage inside document root refused' );
    $db = sbh_db( $config );
    $plain = 'sbk_' . str_repeat( 'a', 48 );
    $cipher = sbh_encrypt( $config, $plain );
    check( $cipher !== $plain && sbh_decrypt( $config, $cipher ) === $plain, 'credential encrypted and decrypted' );
    $tampered = base64_decode( $cipher ); $tampered[28] = chr( ord( $tampered[28] ) ^ 1 );
    rejects( function () use ( $config, $tampered ) { sbh_decrypt( $config, base64_encode( $tampered ) ); }, 'tampered credential refused' );
    sbh_put( $db, 'connection', 'site_a', array( 'owner' => 'alice', 'url' => 'https://alice.example.com', 'key' => $cipher ) );
    sbh_put( $db, 'connection', 'site_b', array( 'owner' => 'bob', 'url' => 'https://bob.example.com', 'key' => $cipher ) );
    check( array_keys( sbh_connections( $config, 'alice' ) ) === array( 'site_a' ), 'Alice cannot list Bob connections' );
    check( array_keys( sbh_connections( $config, 'bob' ) ) === array( 'site_b' ), 'Bob cannot list Alice connections' );
    check( sbh_connections( $config, 'legacy-admin' ) === array(), 'master token cannot list OAuth users connections' );
    check( strpos( file_get_contents( $config['storage_path'] ), $plain ) === false, 'raw WordPress key absent from SQLite file' );
    $tokens = sbh_access_token( $db, 'alice', 'test-client', 'https://hub.example.com/' );
    check( sbh_identity( $config, $tokens['access_token'] )['owner'] === 'alice', 'access token resolves its own principal' );
    check( sbh_identity( $config, 'not-a-token' ) === null, 'invalid bearer refused' );
    $row = sbh_get( $db, 'access', sbh_hash( $tokens['access_token'] ) );
    sbh_put( $db, 'revoked', $row['family'], array( 'revoked' => true ), time() + 100 );
    check( sbh_identity( $config, $tokens['access_token'] ) === null, 'revoked token family refused' );
    sbh_put( $db, 'access', sbh_hash( 'expired' ), $row, time() - 1 );
    check( sbh_identity( $config, 'expired' ) === null, 'expired access token refused' );
    $pending = sbh_pending( $config, 'alice', 'https://alice.example.com', 'My AI' );
    parse_str( parse_url( $pending['approval_url'], PHP_URL_QUERY ), $query );
    $stored = sbh_get( $db, 'pending', $pending['request_id'] );
    check( $stored['secret_hash'] === sbh_hash( $query['secret'] ) && ! isset( $stored['secret'] ), 'approval secret stored only as hash' );
    check( strpos( $pending['approval_url'], 'sbk_' ) === false, 'approval URL contains no API key' );
    $native_state = sbh_random(); $native_cookie = sbh_random(); $request_id = $pending['request_id'];
    $stored['native_hash'] = sbh_hash( $native_state );
    sbh_put( $db, 'pending', $request_id, $stored, time() + 600 );
    sbh_put( $db, 'native', sbh_hash( $native_state ), array( 'request' => $request_id, 'cookie_hash' => sbh_hash( $native_cookie ) ), time() + 600 );
    rejects( function () use ( $db, $native_state ) { sbh_native_claim( $db, $native_state, 'wrong-cookie' ); }, 'native callback cannot be claimed from another browser' );
    list( $session, $claimed ) = sbh_native_claim( $db, $native_state, $native_cookie );
    check( $claimed['status'] === 'processing' && sbh_get( $db, 'native', sbh_hash( $native_state ) ) === null, 'native callback claims and consumes its state atomically' );
    rejects( function () use ( $db, $native_state, $native_cookie ) { sbh_native_claim( $db, $native_state, $native_cookie ); }, 'native callback state cannot be replayed' );
    sbh_put( $db, 'native', sbh_hash( $native_state ), array( 'request' => $request_id, 'cookie_hash' => sbh_hash( $native_cookie ) ), time() - 1 );
    rejects( function () use ( $db, $native_state, $native_cookie ) { sbh_native_claim( $db, $native_state, $native_cookie ); }, 'expired native callback refused' );
    check( strpos( sbh_transport_message( CURLE_OPERATION_TIMEDOUT, 0, 20, 0 ), 'timed out after 20 seconds' ) !== false, 'transport timeout is distinguished from response limits' );
    check( strpos( sbh_transport_message( CURLE_WRITE_ERROR, 4194305, 1, 200 ), '4 MB limit' ) !== false, 'oversized response is reported separately' );
    check( strpos( sbh_transport_message( CURLE_COULDNT_CONNECT, 0, 8, 0 ), 'establish a connection' ) !== false, 'connection failure has a specific diagnostic' );
    check( strpos( sbh_transport_message( CURLE_SSL_CACERT, 0, 1, 0 ), 'certificate' ) !== false, 'TLS failures keep verification enabled and identify the failure' );
    check( strpos( sbh_transport_message( CURLE_RECV_ERROR, 200, 3, 200 ), 'interrupted' ) !== false, 'interrupted transfers retain curl and HTTP diagnostics' );
    rejects( function () { sbh_public_url( 'http://example.com' ); }, 'HTTP WordPress URLs refused' );
    rejects( function () { sbh_http( 'https://127.0.0.1' ); }, 'loopback SSRF refused before connection' );
    rejects( function () { sbh_http( 'https://169.254.169.254/latest/meta-data' ); }, 'metadata SSRF refused before connection' );
    rejects( function () { sbh_http( 'https://10.0.0.1' ); }, 'private network SSRF refused before connection' );
    check( sbh_redirect_valid( 'http://127.0.0.1:3000/callback' ), 'desktop loopback redirect accepted' );
    check( ! sbh_redirect_valid( 'http://evil.example.com/callback' ) && ! sbh_redirect_valid( 'https://evil.example.com/#fragment' ), 'unsafe redirect URIs refused' );
    rejects( function () { sbh_validate_client( array( 'client_name' => 'AI', 'redirect_uris' => array( 'javascript:alert(1)' ) ) ); }, 'malicious client registration refused' );
    $chatgpt = array( 'client_id' => 'https://chatgpt.com/oauth/client.json', 'client_name' => 'ChatGPT', 'redirect_uris' => array( 'https://chatgpt.com/connector_platform_oauth_redirect' ), 'token_endpoint_auth_method' => 'private_key_jwt', 'token_endpoint_auth_methods_supported' => array( 'none', 'private_key_jwt' ) );
    check( sbh_validate_client( $chatgpt, true )['token_endpoint_auth_method'] === 'none', 'ChatGPT metadata document accepted as a public PKCE client' );
    rejects( function () use ( $chatgpt ) { $c = $chatgpt; $c['token_endpoint_auth_methods_supported'] = array( 'private_key_jwt' ); sbh_validate_client( $c, true ); }, 'metadata document without none refused' );
    rejects( function () use ( $chatgpt ) { $c = $chatgpt; unset( $c['token_endpoint_auth_methods_supported'] ); sbh_validate_client( $c, true ); }, 'legacy metadata document requiring private_key_jwt refused' );
    rejects( function () use ( $chatgpt ) { sbh_validate_client( $chatgpt ); }, 'dynamic registration requesting private_key_jwt refused' );
} finally {
    unset( $db );
    foreach ( glob( $dir . '/*' ) as $file ) { unlink( $file ); }
    rmdir( $dir );
}
