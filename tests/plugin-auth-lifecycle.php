<?php
/** Model WordPress's lazy current-user initialization and a third-party capability filter. */
define( 'ABSPATH', __DIR__ ); define( 'SITEBRIDGE_NS', 'sitebridge/v1' );
define( 'SITEBRIDGE_APP_ID', '6c78a910-07e3-4a44-a3fa-299b20b471c5' );
define( 'REST_REQUEST', true );
$GLOBALS['current_wp_user']=null; $GLOBALS['auth_depth']=0; $GLOBALS['auth_calls']=0;
$GLOBALS['admin']=true; $GLOBALS['enabled']=true; $GLOBALS['core_uuid']=null;
function add_action() {} function add_filter() {}
class SiteBridge_Logger { public static function log() {} }
function sitebridge_get_settings() {
    // Option filters can also inspect the current user, so settings must wait.
    get_current_user_id();
    return array('enabled'=>$GLOBALS['enabled'],'site_read'=>true);
}
function rest_get_authenticated_app_password() { return $GLOBALS['core_uuid']; }
class WP_User { public $ID=7; public $admin; public function __construct() { $this->admin=$GLOBALS['admin']; } }
class WP_Error { public $errors=array(); public function __construct($code='',$message='',$data=null) { if($code) { $this->add($code,$message,$data); } } public function add($code,$message,$data=null) { $this->errors[$code]=$message; } public function has_errors() { return (bool)$this->errors; } }
class WP_Application_Passwords { public static function get_user_application_password($id,$uuid) { return $id===7 && $uuid==='native-uuid' ? native_item() : null; } }
class Request { private $route; public function __construct($route) { $this->route=$route; } public function get_route() { return $this->route; } }
function native_item() { return array('uuid'=>'native-uuid','name'=>'SiteBridge','app_id'=>SITEBRIDGE_APP_ID); }
function wp_authenticate_application_password($unused,$username,$password) {
    $GLOBALS['auth_calls']++;
    if (++$GLOBALS['auth_depth']>5) { throw new RuntimeException('Recursive current-user initialization during application authentication'); }
    try {
        $user=new WP_User(); $error=new WP_Error();
        SiteBridge_Auth::check_application($error,$user,native_item(),$password);
        if ($error->has_errors()) { return $error; }
        SiteBridge_Auth::capture_application($user,native_item()); $GLOBALS['core_uuid']='native-uuid';
        return $user;
    } finally { $GLOBALS['auth_depth']--; }
}
function wp_get_current_user() {
    if ($GLOBALS['current_wp_user']===null) {
        $user=wp_authenticate_application_password(null,'admin','fixture');
        if (!$user instanceof WP_User) { throw new RuntimeException('Unexpected authentication error'); }
        $GLOBALS['current_wp_user']=$user;
    }
    return $GLOBALS['current_wp_user'];
}
function get_current_user_id() { return wp_get_current_user()->ID; }
function user_can($user,$cap) {
    // A capability filter from another plugin reads the current user. During
    // determine_current_user this re-enters authentication unless checks are deferred.
    get_current_user_id();
    return $user->admin;
}
function current_user_can($cap) { return user_can(wp_get_current_user(),$cap); }
function check($value,$message) { if (!$value) { throw new RuntimeException($message); } echo "PASS $message\n"; }
$plugin=is_dir(__DIR__.'/../sitebridge') ? __DIR__.'/../sitebridge' : __DIR__.'/../wordpress-plugin/sitebridge';
require $plugin.'/includes/class-sitebridge-auth.php';
$user=wp_get_current_user();
check($user->ID===7 && $GLOBALS['auth_calls']===1,'capability hooks cannot recurse during Application Password authentication');
check(SiteBridge_Auth::restrict_application_routes(null,null,new Request('/sitebridge/v1/connect/verify'))===null,'administrator checks succeed after current-user initialization');
check(SiteBridge_Auth::restrict_application_routes(null,null,new Request('/wp/v2/users')) instanceof WP_Error,'deferred checks retain namespace restrictions');
$GLOBALS['enabled']=false;
check(SiteBridge_Auth::restrict_application_routes(null,null,new Request('/sitebridge/v1/site')) instanceof WP_Error,'disabled plugin is rejected after authentication');
$GLOBALS['enabled']=true; $GLOBALS['current_wp_user']->admin=false;
check(SiteBridge_Auth::restrict_application_routes(null,null,new Request('/sitebridge/v1/site')) instanceof WP_Error,'non-administrator is rejected after authentication');
