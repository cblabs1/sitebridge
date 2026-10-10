<?php
/** Native authentication boundary tests. */
define( 'ABSPATH', __DIR__ );
define( 'SITEBRIDGE_NS', 'sitebridge/v1' );
define( 'SITEBRIDGE_APP_ID', '6c78a910-07e3-4a44-a3fa-299b20b471c5' );
define( 'SITEBRIDGE_VERSION', '0.5.0' );
define( 'SITEBRIDGE_OPT_KEYS', 'sitebridge_keys' );
$mode = $argv[1] ?? '';
// early: a plugin initialized the user before WordPress defined REST_REQUEST.
define( 'REST_REQUEST', ! in_array( $mode, array( 'xmlrpc', 'early', 'other' ), true ) );
if ( $mode === 'xmlrpc' ) { define( 'XMLRPC_REQUEST', true ); }
$_SERVER['REQUEST_URI'] = $mode === 'other' ? '/wp-admin/admin-ajax.php?x=/wp-json/sitebridge/v1/' : '/blog/wp-json/sitebridge/v1/connect/verify';
$GLOBALS['settings'] = array( 'enabled' => true, 'site_read' => true, 'content_write' => false );
$GLOBALS['user_id'] = 7;
$GLOBALS['is_admin'] = true;
function add_action() {}
function add_filter() {}
function user_can( $user, $cap ) { return $user->admin; }
function current_user_can() { return $GLOBALS['is_admin']; }
function get_current_user_id() { return $GLOBALS['user_id']; }
function sitebridge_get_settings() { return $GLOBALS['settings']; }
function get_option( $key, $default ) { return $default; }
function home_url() { return 'https://site.example.com'; }
function rest_get_url_prefix() { return 'wp-json'; }
if ( ! function_exists( 'wp_unslash' ) ) { function wp_unslash( $s ) { return $s; } }
function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
class WP_Error { public $errors = array(); public $error_data = array(); public function __construct( $code = '', $message = '', $data = null ) { if ( $code ) { $this->add( $code, $message, $data ); } } public function add( $code, $message, $data = null ) { $this->errors[$code] = $message; $this->error_data[$code] = $data; } public function has_errors() { return (bool) $this->errors; } public function get_error_code() { return key( $this->errors ); } }
class WP_REST_Response { public $data; public function __construct( $data ) { $this->data = $data; } public function header() {} }
class SiteBridge_Logger { public static function log() {} }
class Request { private $route; public function __construct( $route ) { $this->route=$route; } public function get_route() { return $this->route; } public function get_header() { return ''; } }
function check( $value, $name ) { if ( ! $value ) { throw new Exception( $name ); } echo "PASS $name\n"; }
$plugin = is_dir( __DIR__ . '/../sitebridge' ) ? __DIR__ . '/../sitebridge' : __DIR__ . '/../wordpress-plugin/sitebridge';
require $plugin . '/includes/class-sitebridge-auth.php';
require $plugin . '/includes/class-sitebridge-connect.php';
if ( defined( 'SITEBRIDGE_NATIVE_FIXTURE_ONLY' ) && SITEBRIDGE_NATIVE_FIXTURE_ONLY ) { return; }
$user = (object) array( 'ID' => 7, 'admin' => true );
$item = array( 'uuid' => 'native-uuid', 'name' => 'SiteBridge Test', 'app_id' => SITEBRIDGE_APP_ID );
$error = new WP_Error(); SiteBridge_Auth::check_application( $error, $user, $item, 'not-logged' );
if ( $mode === 'xmlrpc' ) { check( $error->has_errors(), 'SiteBridge application password cannot authenticate XML-RPC' ); exit; }
if ( $mode === 'other' ) { check( $error->has_errors(), 'SiteBridge application password refused outside SiteBridge REST routes' ); exit; }
if ( $mode === 'early' ) { check( ! $error->has_errors(), 'SiteBridge REST route accepted when user initialized before REST_REQUEST' ); exit; }
check( ! $error->has_errors(), 'administrator native credential accepted for REST authentication' );
$nonadmin = (object) array( 'ID' => 8, 'admin' => false );
$error = new WP_Error(); SiteBridge_Auth::check_application( $error, $nonadmin, $item, '' );
SiteBridge_Auth::capture_application( $nonadmin, $item );
$GLOBALS['user_id'] = 8; $GLOBALS['is_admin'] = false;
check( ! $error->has_errors() && SiteBridge_Auth::restrict_application_routes( null, null, new Request( '/sitebridge/v1/site' ) ) instanceof WP_Error, 'non-administrator native credential refused at REST dispatch' );
$GLOBALS['user_id'] = 7; $GLOBALS['is_admin'] = true;
SiteBridge_Auth::capture_application( $user, $item );
$GLOBALS['settings']['enabled'] = false;
$error = new WP_Error(); SiteBridge_Auth::check_application( $error, $user, $item, '' );
check( ! $error->has_errors() && SiteBridge_Auth::restrict_application_routes( null, null, new Request( '/sitebridge/v1/site' ) ) instanceof WP_Error, 'disabled plugin blocks native access at REST dispatch' );
$error = new WP_Error(); SiteBridge_Auth::check_application( $error, $user, array( 'app_id' => 'other-app' ), '' );
check( ! $error->has_errors(), 'other applications are unaffected' );
$GLOBALS['settings']['enabled'] = true;
SiteBridge_Auth::capture_application( $user, $item );
check( SiteBridge_Auth::require_cap( 'site_read' )( new Request( '/sitebridge/v1/site' ) ) === true, 'native password can use enabled SiteBridge capability' );
check( SiteBridge_Auth::require_cap( 'content_write' )( new Request( '/sitebridge/v1/content' ) ) instanceof WP_Error, 'native password cannot bypass disabled write permission' );
$GLOBALS['settings']['content_write'] = true;
check( SiteBridge_Auth::require_cap( 'content_write' )( new Request( '/sitebridge/v1/content' ) ) === true, 'native connection follows updated plugin permissions' );
foreach ( array( '/wp/v2/users', '/wp/v2/posts', '/batch/v1', '/sitebridge/v10/site', '/sitebridge/v1evil/site' ) as $route ) {
    check( SiteBridge_Auth::restrict_application_routes( null, null, new Request( $route ) ) instanceof WP_Error, 'native password cannot call ' . $route );
}
check( SiteBridge_Auth::restrict_application_routes( null, null, new Request( '/sitebridge/v1/site' ) ) === null, 'native password stays within SiteBridge namespace' );
$connect = new SiteBridge_Connect();
check( $connect->native_verify()->data['uuid'] === $item['uuid'], 'native verification identifies the authenticated application without returning a password' );
$GLOBALS['user_id'] = 8;
check( SiteBridge_Auth::current_application() === null, 'native authentication is bound to the current WordPress user' );
$GLOBALS['user_id'] = 7;
SiteBridge_Auth::capture_application( $user, array( 'app_id' => 'other-app' ) );
check( $connect->native_verify() instanceof WP_Error, 'unrelated application password cannot complete a SiteBridge connection' );
check( SiteBridge_Auth::require_cap( 'site_read' )( new Request( '/sitebridge/v1/site' ) ) instanceof WP_Error, 'missing or unrelated credentials cannot use SiteBridge API' );
