<?php
/** REST proxy, option write and internal-dispatch boundaries for the WPVibe-style tools. */
define( 'SITEBRIDGE_NATIVE_FIXTURE_ONLY', true );
require __DIR__ . '/plugin-native.php';
function register_rest_route() {}
function sanitize_key( $key ) { return strtolower( preg_replace( '/[^a-z0-9_\-]/i', '', $key ) ); }
$GLOBALS['options'] = array( 'blogname' => 'Old' );
function update_option( $name, $value ) { $GLOBALS['options'][ $name ] = $value; return true; }
function rest_ensure_response( $data ) { return new WP_REST_Response( $data ); }
$GLOBALS['wpdb'] = (object) array( 'prefix' => 'wp_' );
class OptionRequest implements ArrayAccess {
    private $name; private $body;
    public function __construct( $name, $body ) { $this->name = $name; $this->body = $body; }
    public function offsetExists( $k ): bool { return $k === 'name'; }
    public function offsetGet( $k ): mixed { return $this->name; }
    public function offsetSet( $k, $v ): void {}
    public function offsetUnset( $k ): void {}
    public function get_json_params() { return $this->body; }
}
require $plugin . '/includes/class-sitebridge-tools.php';
class Tools extends SiteBridge_Tools { public function guard( $m, $r ) { return $this->guard_route( $m, $r ); } }
$tools = new Tools();
$GLOBALS['settings'] = array( 'enabled' => true, 'site_read' => true, 'rest_proxy' => true, 'content_write' => true, 'code_edit' => false, 'options_write' => false );
$code = function ( $result ) { return $result instanceof WP_Error ? array_key_first( $result->errors ) : null; };

check( $tools->guard( 'GET', '/wp/v2/posts' ) === null, 'proxy allows reads of core routes' );
check( $tools->guard( 'POST', '/yoast/v1/configuration' ) === null, 'proxy allows plugin writes with content_write' );
check( $code( $tools->guard( 'GET', '/sitebridge/v1/site' ) ) === 'sitebridge_proxy_loop', 'proxy refuses SiteBridge routes' );
check( $code( $tools->guard( 'GET', '/wp/v2/users/me/application-passwords' ) ) === 'sitebridge_proxy_forbidden', 'proxy refuses application password routes, even reads' );
check( $code( $tools->guard( 'POST', '/wp/v2/users/7' ) ) === 'sitebridge_proxy_forbidden', 'proxy refuses user and role changes' );
check( $tools->guard( 'GET', '/wp/v2/users' ) === null, 'proxy allows listing users' );
check( $code( $tools->guard( 'POST', '/wp/v2/plugins' ) ) === 'sitebridge_forbidden', 'plugin installs need code_edit' );
check( $code( $tools->guard( 'POST', '/wp/v2/settings' ) ) === 'sitebridge_forbidden', 'settings writes need options_write' );
$GLOBALS['settings']['content_write'] = false;
check( $code( $tools->guard( 'DELETE', '/wp/v2/posts/5' ) ) === 'sitebridge_forbidden', 'proxy writes need content_write' );
check( $tools->guard( 'GET', '/wp/v2/posts/5' ) === null, 'proxy reads work without content_write' );

// A SiteBridge application password stays confined to its namespace except inside the proxy.
$user = (object) array( 'ID' => 7, 'admin' => true );
SiteBridge_Auth::capture_application( $user, array( 'uuid' => 'native-uuid', 'name' => 'SiteBridge', 'app_id' => SITEBRIDGE_APP_ID ) );
check( SiteBridge_Auth::restrict_application_routes( null, null, new Request( '/wp/v2/posts' ) ) instanceof WP_Error, 'application password refused on core routes outside the proxy' );
$inner = SiteBridge_Auth::internal_dispatch( function () { return SiteBridge_Auth::restrict_application_routes( null, null, new Request( '/wp/v2/posts' ) ); } );
check( $inner === null, 'proxy dispatch reaches core routes' );
check( SiteBridge_Auth::restrict_application_routes( null, null, new Request( '/wp/v2/posts' ) ) instanceof WP_Error, 'namespace restriction restored after proxy dispatch' );
try { SiteBridge_Auth::internal_dispatch( function () { throw new RuntimeException( 'inner failure' ); } ); } catch ( RuntimeException $e ) {}
check( SiteBridge_Auth::restrict_application_routes( null, null, new Request( '/wp/v2/posts' ) ) instanceof WP_Error, 'namespace restriction restored after a failing proxy dispatch' );

foreach ( array( 'siteurl', 'active_plugins', 'wp_user_roles', 'sitebridge_settings', 'smtp_password', 'stripe_api_key', 'default_role' ) as $name ) {
    check( $code( $tools->update_option_value( new OptionRequest( $name, array( 'value' => 'x' ) ) ) ) === 'forbidden_option', "option $name cannot be written" );
}
$result = $tools->update_option_value( new OptionRequest( 'blogname', array( 'value' => 'New' ) ) );
check( $result->data['name'] === 'blogname' && $GLOBALS['options']['blogname'] === 'New', 'ordinary option written' );
