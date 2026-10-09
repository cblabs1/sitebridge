<?php
/** Offline fixtures for connection UI checks; never changes a real website. */
$root = dirname( __DIR__ );
$hub = is_dir( $root . '/sitebridge-hub' ) ? $root . '/sitebridge-hub' : $root;
$plugin = is_dir( $root . '/sitebridge' ) ? $root . '/sitebridge' : $root . '/wordpress-plugin/sitebridge';
$mode = $argv[1] ?? 'approve';
if ( $mode === 'landing' ) {
    require $hub . '/connections.php';
    sbh_landing( array( 'public_url' => 'https://hub.example.com' ) );
}
define( 'ABSPATH', __DIR__ ); define( 'SITEBRIDGE_NS', 'sitebridge/v1' );
function add_action() {} function add_filter() {} function nocache_headers() {} function status_header() {}
function current_user_can() { return true; } function get_current_user_id() { return 7; }
function wp_unslash( $v ) { return $v; } function sanitize_text_field( $v ) { return $v; }
function esc_url_raw( $v ) { return $v; } function esc_url( $v ) { return htmlspecialchars( $v, ENT_QUOTES, 'UTF-8' ); }
function esc_html( $v ) { return htmlspecialchars( $v, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $v ) { return htmlspecialchars( $v, ENT_QUOTES, 'UTF-8' ); }
function wp_parse_url( $v ) { return parse_url( $v ); }
function wp_die( $message ) { throw new RuntimeException( $message ); }
function home_url() { return 'https://your-site.example'; } function admin_url( $v ) { return 'https://your-site.example/wp-admin/' . $v; }
function get_bloginfo() { return 'Your WordPress website'; }
function sitebridge_get_settings() { return array( 'enabled' => true, 'site_read' => true, 'content_write' => true, 'woo_write' => true, 'db_write' => false, 'code_edit' => false ); }
function wp_nonce_field() { echo '<input type="hidden" name="_wpnonce" value="preview-only">'; }
function set_transient() {} function delete_transient() {} function add_option() { return true; } function wp_schedule_single_event() {} function check_admin_referer() {}
function get_transient() { return array( 'hub' => 'https://hub.example.com', 'request' => str_repeat( 'a', 64 ), 'secret' => str_repeat( 'c', 64 ), 'approved_caps' => array( 'site_read', 'content_write' ) ); }
function wp_safe_remote_get() { return array( 'status' => 200, 'body' => json_encode( array( 'request' => str_repeat( 'a', 64 ), 'site_url' => home_url(), 'hub_url' => 'https://hub.example.com', 'expires' => time() + 100, 'client_name' => ( $GLOBALS['mode'] === 'escape' ? '<script>alert(1)</script>' : 'Your AI assistant' ) ) ) ); }
function wp_safe_remote_post() { return array( 'status' => 200, 'body' => json_encode( array( 'status' => $GLOBALS['mode'] === 'denied' ? 'denied' : 'connected', 'return_url' => 'https://ai.example.com/callback' ) ) ); }
function wp_remote_retrieve_body( $r ) { return $r['body']; } function wp_remote_retrieve_response_code( $r ) { return $r['status']; }
function is_wp_error() { return false; } function wp_json_encode( $v ) { return json_encode( $v ); }
class SiteBridge_Auth { public static function generate_key() { return array( 'raw' => 'fixture-not-a-real-key', 'id' => 'fixture' ); } }
class SiteBridge_Logger { public static function log() {} }
require $plugin . '/includes/class-sitebridge-connect.php';
$connect = new SiteBridge_Connect();
$_GET = array( 'hub' => 'https://hub.example.com', 'request' => str_repeat( 'a', 64 ), 'secret' => str_repeat( 'c', 64 ) );
$_POST = array( 'local' => str_repeat( 'b', 48 ), 'decision' => $mode === 'denied' ? 'deny' : 'approve' );
if ( $mode === 'success' || $mode === 'denied' ) { $connect->decide(); }
elseif ( $mode === 'error' ) { $method = new ReflectionMethod( $connect, 'error' ); $method->invoke( $connect, 'This approval link has expired. Please request a new connection.' ); }
else { $connect->screen(); }
