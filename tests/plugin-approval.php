<?php
/** WordPress boundary tests with a minimal WP API fixture; no real site is changed. */
define( 'ABSPATH', __DIR__ ); define( 'SITEBRIDGE_NS', 'sitebridge/v1' );
$GLOBALS['transients'] = array(); $GLOBALS['options'] = array(); $GLOBALS['admin'] = true; $GLOBALS['nonce'] = true;
function add_action() {}
function add_filter() {}
function register_rest_route() {}
function wp_schedule_single_event() {}
function current_user_can() { return $GLOBALS['admin']; }
function wp_unslash( $s ) { return $s; }
function sanitize_text_field( $s ) { return $s; }
function sanitize_key( $s ) { return $s; }
function get_current_user_id() { return 7; }
function check_admin_referer() { if ( ! $GLOBALS['nonce'] ) { throw new RuntimeException( 'Invalid nonce' ); } }
function wp_die( $message ) { throw new RuntimeException( $message ); }
function get_transient( $key ) { return $GLOBALS['transients'][ $key ] ?? false; }
function set_transient( $key, $value, $ttl ) { $GLOBALS['transients'][ $key ] = $value; }
function delete_transient( $key ) { unset( $GLOBALS['transients'][ $key ] ); }
function add_option( $key, $value ) { if ( isset( $GLOBALS['options'][ $key ] ) ) { return false; } $GLOBALS['options'][ $key ] = $value; return true; }
function delete_option( $key ) { unset( $GLOBALS['options'][ $key ] ); }
function sitebridge_get_settings() { return $GLOBALS['settings'] ?? array( 'enabled' => true, 'site_read' => true, 'content_write' => false ); }
function wp_safe_remote_get() { return array( 'status' => 200, 'body' => json_encode( array( 'request' => str_repeat( 'a', 64 ), 'site_url' => 'https://site.example.com', 'hub_url' => 'https://hub.example.com', 'expires' => time() + 100, 'client_name' => 'Test AI' ) ) ); }
function wp_remote_retrieve_response_code( $res ) { return $res['status']; }
function wp_remote_retrieve_body( $res ) { return $res['body']; }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function home_url() { return 'https://site.example.com'; }
class WP_Error { public $code; public function __construct( $code ) { $this->code = $code; } }
class WP_REST_Response { public $data; public function __construct( $data ) { $this->data = $data; } public function header() {} }
class Request { private $params; public function __construct( $params ) { $this->params = $params; } public function get_param( $key ) { return $this->params[ $key ] ?? null; } }
class SiteBridge_Auth { public static function generate_key( $label, $caps ) { $GLOBALS['granted_caps'] = $caps; throw new RuntimeException( 'TEST_KEY_CAPTURE' ); } }
$plugin = is_dir( __DIR__ . '/../sitebridge' ) ? __DIR__ . '/../sitebridge' : __DIR__ . '/../wordpress-plugin/sitebridge';
require $plugin . '/includes/class-sitebridge-connect.php';
function check( $condition, $message ) { if ( ! $condition ) { throw new Exception( $message ); } echo "PASS $message\n"; }
function rejects( $fn, $expected, $name ) { try { $fn(); } catch ( RuntimeException $e ) { check( strpos( $e->getMessage(), $expected ) !== false, $name ); return; } throw new Exception( $name ); }
$connect = new SiteBridge_Connect();
$GLOBALS['admin'] = false;
rejects( function () use ( $connect ) { $connect->decide(); }, 'Not allowed', 'non-administrator cannot approve' );
$GLOBALS['admin'] = true;
$_POST = array( 'local' => str_repeat( 'b', 48 ) );
$GLOBALS['nonce'] = false;
rejects( function () use ( $connect ) { $connect->decide(); }, 'Invalid nonce', 'CSRF nonce required' );
$GLOBALS['nonce'] = true;
rejects( function () use ( $connect ) { $connect->decide(); }, 'expired', 'missing local approval state refused' );
$slot = 'sb_connect_7_' . $_POST['local'];
$GLOBALS['transients'][ $slot ] = array( 'hub' => 'https://hub.example.com', 'request' => str_repeat( 'a', 64 ), 'secret' => str_repeat( 'c', 64 ) );
$_POST['decision'] = 'approve'; $_POST['caps'] = array( 'content_write' );
rejects( function () use ( $connect ) { $connect->decide(); }, 'Read access', 'approval without server-side scope snapshot cannot create unrestricted key' );
function approval_fixture( $snapshot ) {
    $local = bin2hex( random_bytes( 24 ) );
    $_POST = array( 'local' => $local, 'decision' => 'approve', 'caps' => array( 'db_write', 'code_edit' ) );
    $GLOBALS['transients']['sb_connect_7_' . $local] = array( 'hub' => 'https://hub.example.com', 'request' => str_repeat( 'a', 64 ), 'secret' => str_repeat( 'c', 64 ), 'approved_caps' => $snapshot );
}
approval_fixture( array( 'site_read', 'content_write' ) );
rejects( function () use ( $connect ) { $connect->decide(); }, 'TEST_KEY_CAPTURE', 'approval reaches scoped key creation without posted permission fields' );
check( $GLOBALS['granted_caps'] === array( 'site_read' ), 'disabled capabilities and forged browser scopes are excluded' );
$GLOBALS['settings'] = array( 'enabled' => true, 'site_read' => true, 'content_write' => true );
approval_fixture( array( 'site_read' ) );
rejects( function () use ( $connect ) { $connect->decide(); }, 'TEST_KEY_CAPTURE', 'settings enabled after the screen opened do not broaden consent' );
check( $GLOBALS['granted_caps'] === array( 'site_read' ), 'approval uses the original server-side snapshot' );
$GLOBALS['settings'] = array( 'enabled' => true, 'site_read' => false, 'content_write' => true );
approval_fixture( array( 'site_read', 'content_write' ) );
rejects( function () use ( $connect ) { $connect->decide(); }, 'Read access', 'read access revoked after opening screen stops approval' );
$code = str_repeat( 'd', 64 ); $id = str_repeat( 'a', 64 );
$exchange_slot = 'sb_exchange_' . hash( 'sha256', $code );
$GLOBALS['transients'][ $exchange_slot ] = array( 'request' => $id, 'key' => 'sbk_test', 'site_url' => 'https://site.example.com', 'capabilities' => array( 'site_read' ) );
$r = $connect->exchange( new Request( array( 'code' => $code, 'request' => str_repeat( 'f', 64 ) ) ) );
check( $r instanceof WP_Error, 'exchange code bound to exact request' );
$r = $connect->exchange( new Request( array( 'code' => $code, 'request' => $id ) ) );
check( $r instanceof WP_REST_Response && $r->data['key'] === 'sbk_test' && ! isset( $r->data['request'] ), 'approved code exchanged once' );
$r = $connect->exchange( new Request( array( 'code' => $code, 'request' => $id ) ) );
check( $r instanceof WP_Error, 'WordPress exchange replay rejected' );
$GLOBALS['transients'][ $exchange_slot ] = array( 'request' => $id, 'key' => 'sbk_test' );
$r = $connect->exchange( new Request( array( 'code' => $code, 'request' => $id ) ) );
check( $r instanceof WP_Error, 'concurrent exchange lock rejects duplicated code' );
